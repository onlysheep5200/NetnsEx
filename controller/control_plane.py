# -*- coding: utf-8 -*-
import sys
sys.path.append('..')
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet,ipv4,icmp,arp,tcp,udp
from ryu.lib.packet import ether_types
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.utils import hex_array
from ryu.lib import dpid as dpid_lib
from ryu.lib.ovs.bridge import OVSBridge,CONF
from webob import Response
import json
from persistent import TestPersistent
import requests
import uuid
import cgi
import ipgen
from atomic import TunnelFlagGenerator

instance_name = 'netns_api_app'
url = '/netnsex'
conf = json.load(open('config.json','r'))

MAGIC_MAC_ADDR = 'ac:87:a3:1f:36:e7'
GATEWAY_ADDR = '10.109.243.212'
TO_GATE_TUNNEL_NAME = 'to_gate'


#TODO：链接重置时不可用



class NetnsExtension(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    _CONTEXTS = { 'wsgi': WSGIApplication ,'persistent' : TestPersistent}

    def __init__(self, *args, **kwargs):
        super(NetnsExtension, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.persistent = kwargs['persistent']
        self.allocated_ipaddrs = []
        self.datapaths = {}
        wsgi = kwargs['wsgi']
        wsgi.register(NetnsExController, {instance_name : self,'persistent':self.persistent})
        self.bridges = {}
        self.containerFlows = {}
        self.gateToHostConnections = {}


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        print 'new datapath : %s'%datapath.id
        self.datapaths[datapath.id] = {'datapath':datapath}
        self.mapping_datapath_with_host(datapath=datapath)
        addr = 'tcp:%s:6632'%datapath.address[0]
        bridge = OVSBridge(CONF,datapath.id,addr)
        bridge.init()
        if datapath.address[0] != GATEWAY_ADDR :
            self.bridges[addr] = bridge
        else :
            print 'gateway bridge init !'
            self.gateBridge = bridge

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPErrorMsg,MAIN_DISPATCHER)
    def _error_handler(self,ev):
        msg = ev.msg
        print 'type=0x%02x code=0x%02x msg : %s'%(msg.type,msg.code,hex_array(msg.data))

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg

        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']



        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        icmp_pkt = pkt.get_protocols(icmp.icmp)
        ip = pkt.get_protocols(ipv4.ipv4)
        arp_pkt = pkt.get_protocols(arp.arp)
        tcp_pkt = pkt.get_protocols(tcp.tcp)
        udp_pkt = pkt.get_protocols(udp.udp)


        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            self.logger.info('LLDP PACKET')
            return
        dst = eth.dst
        src = eth.src

        #流量来自系统外部的情况
        if datapath.address[0] == GATEWAY_ADDR :
            print 'from port %d'%in_port
            if arp_pkt :
                self.reply_arp(datapath,in_port,arp_pkt[0],eth,MAGIC_MAC_ADDR)
                return
            else :
                self._operate_flow_from_outside(msg,datapath,eth,ip[0] if ip else None,tcp_pkt[0] if tcp_pkt else None)
                return

        #取得发包容器所属的netns
        sendContainer = self._update_container_info(datapath,in_port,src)
        if not sendContainer :
            self.logger.info('no sendcontainer recognize')
            self._operate_flow_from_gateway(msg,datapath,eth,ip[0] if ip else None,tcp_pkt[0] if tcp_pkt else None)
            return

        netns = self.persistent.findOne('netns',{'_id':sendContainer['netnsId']})
        if not netns :
            self.logger.info('No Networknamespace exists !')
            return
        sendHost = self.persistent.findOne('host',{'_id':sendContainer['hostId']})

        #解决隧道包
        #if in_port in sendHost['targetPorts'].values() or ( in_port <= len(sendHost['portNameList']) and sendHost['portNameList'][in_port-1] in sendHost['targetPorts'].values() ):
        if in_port in sendHost['targetPorts'].values() :
            self._operate_with_tunnel(msg,datapath,eth,ip[0] if ip else None,tcp_pkt[0] if tcp_pkt else None,sendContainer,netns)
            return

        #arp协议
        if arp_pkt :
            arp_pkt = arp_pkt[0]
            self._operate_with_arp(msg,datapath,arp_pkt,sendContainer,netns,eth)
        #IP协议-
        if icmp_pkt :
            print 'icmp packet coming'
            icmp_pkt = icmp_pkt[0]
            self._operate_with_icmp(msg,datapath,ip[0],icmp_pkt,sendContainer,netns,eth)

        elif tcp_pkt or udp_pkt :
            if tcp_pkt :
                protocol = 'tcp'
            else :
                protocol = 'udp'
            self._operate_with_transport_layer(msg,datapath,tcp_pkt[0] if tcp_pkt else udp_pkt[0],ip[0],sendContainer,netns,eth,protocol)

        elif ip :
            print 'ip packet comming'
            ip = ip[0]
            self._operate_with_ip(in_port,datapath,ip,sendContainer,netns,eth)


    #TODO:待优化，调整代码结构，减少代码行数
    def _operate_with_tunnel(self,msg,datapath,eth_pkt,ip_pkt,tsl_pkt,sender_container,netns):
        #系统内部流量
        parser = datapath.ofproto_parser
        if netns :
            if ip_pkt :
                sip = ip_pkt.src
                dip = ip_pkt.dst
                #在namespace内传送
                if dip == '127.0.0.1' :
                    if tsl_pkt and isinstance(tsl_pkt,tcp.tcp) :
                        dst_port = tsl_pkt.dst_port
                        target_container = self.persistent.findOne('container',{'_id':netns['containerPortMapping'].get(str(dst_port))})
                        if not target_container :
                            print 'no such port opened !!!'
                            return
                        actions = [
                            parser.OFPActionSetField(ipv4_dst=target_container['private_ip']),
                            parser.OFPActionSetField(eth_dst=target_container['mac']),
                            parser.OFPActionOutput(target_container['portId'])
                        ]
                        match = parser.OFPMatch(eth_type=0x800,ip_proto=6,in_port=msg.match['in_port'],tunnel_id=msg.match['tunnel_id'],tcp_dst=dst_port,ipv4_dst=('127.0.0.1',netns['ip']))
                        self.add_flow(datapath,1,match,actions)

                        match = parser.OFPMatch(eth_type=0x800,ip_proto=6,tcp_src=dst_port,ipv4_dst=sip,tcp_dst=tsl_pkt.src_port)
                        bActions = [
                            parser.OFPActionSetField(ipv4_src=dip),
                            parser.OFPActionSetField(eth_src=eth_pkt.dst),
                            parser.OFPActionSetField(tunnel_id=msg.match['tunnel_id']),
                            parser.OFPActionOutput(msg.match['in_port'])
                        ]
                        self.add_flow(datapath,1,match,bActions)
                        out = parser.OFPPacketOut(datapath=datapath,buffer_id = datapath.ofproto.OFP_NO_BUFFER,in_port=msg.match['in_port'],actions=actions,data = msg.data)
                        datapath.send_msg(out)
                #跨netns传送
                elif netns['ip'] != dip :
                    targetNetns = self.persistent.findOne('netns',{'ip':dip})
                    if not targetNetns :
                        self.logger.info('cannot find target container !!!')
                        return
                    if tsl_pkt and isinstance(tsl_pkt,tcp.tcp) :
                        dst_port = tsl_pkt.dst_port
                        containerId = targetNetns['containerPortMapping'].get(str(dst_port))
                        if not containerId :
                            self.logger.info("Invalid port number !")
                            return

                        target_container = self.persistent.findOne('container',{'_id':containerId})
                        match = parser.OFPMatch(eth_type=0x800,ip_proto=6,in_port=msg.match['in_port'],tunnel_id=msg.match['tunnel_id'],tcp_dst=dst_port,ipv4_dst=dip)
                        actions = [
                            parser.OFPActionSetField(ipv4_dst = target_container['private_ip']),
                            parser.OFPActionSetField(eth_dst=target_container['mac']),
                            parser.OFPActionOutput(target_container['portId'])
                        ]
                        self.add_flow(datapath,1,match,actions)

                        match = parser.OFPMatch(eth_type=0x800,ip_proto=6,tcp_src=dst_port,ipv4_dst=sip,tcp_dst=tsl_pkt.src_port)
                        bActions = [
                            parser.OFPActionSetField(ipv4_src=dip),
                            parser.OFPActionSetField(eth_src=eth_pkt.dst),
                            parser.OFPActionSetField(tunnel_id=msg.match['tunnel_id']),
                            parser.OFPActionOutput(msg.match['in_port'])
                        ]
                        self.add_flow(datapath,1,match,bActions)
                        out = parser.OFPPacketOut(datapath=datapath,buffer_id = datapath.ofproto.OFP_NO_BUFFER,in_port=msg.match['in_port'],actions=actions,data = msg.data)
                        datapath.send_msg(out)
        #外部流量
        else :
            pass

    def _operate_flow_from_outside(self,msg,datapath,eth_pkt,ip_pkt,tsl_pkt):
        parser = datapath.ofproto_parser
        if ip_pkt :
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst
            target_netns = self.persistent.findOne('netns',{'ip':dst_ip})
            if not target_netns :
                self.logger.info("No ngroup with ip : %s"%dst_ip)
                return
            if tsl_pkt :
                src_port = tsl_pkt.src_port
                dst_port = tsl_pkt.dst_port
                target_container = target_netns['containerPortMapping'].get(str(dst_port))
                if not target_container :
                    self.logger.info('No container open port %d'%dst_port)
                    return
                target_container = self.persistent.findOne('container',{'_id':target_container})
                transportPort = self.gateToHostConnections.get(target_container['hostId'])

                match = parser.OFPMatch(eth_type = 0x800,ip_proto=6,ipv4_dst = dst_ip,tcp_dst=dst_port)
                #TODO:似有问题
                #将源IP改成相对应的网关IP以区别其他流
                actions = [
                    parser.OFPActionSetField(ipv4_dst=target_container['private_ip']),
                    parser.OFPActionSetField(eth_dst=target_container['mac']),
                    parser.OFPActionSetField(tunnel_id=target_netns['flag']),
                    parser.OFPActionSetField(ipv4_src=GATEWAY_ADDR),
                    parser.OFPActionSetField(tunnel_id=target_netns['flag']),
                    parser.OFPActionOutput(transportPort)
                ]
                self.add_flow(datapath,1,match,actions)

                match = parser.OFPMatch(eth_type = 0x800,ip_proto=6,ipv4_src = target_container['private_ip'],tcp_src=dst_port,tcp_dst=src_port,ipv4_dst=GATEWAY_ADDR)
                backActions = [
                    parser.OFPActionSetField(ipv4_src=dst_ip),
                    parser.OFPActionSetField(eth_src = eth_pkt.dst),
                    parser.OFPActionSetField(ipv4_dst = src_ip),
                    parser.OFPActionSetField(eth_dst = eth_pkt.src),
                    parser.OFPActionOutput(msg.match['in_port'])
                ]
                self.add_flow(datapath,1,match,backActions)

                out = parser.OFPPacketOut(datapath=datapath,buffer_id = datapath.ofproto.OFP_NO_BUFFER,in_port=datapath.ofproto.OFPP_CONTROLLER,actions=actions,data = msg.data)
                datapath.send_msg(out)

            else :
                self.logger.info('INVALID PROTOCOL !!! ONLY SUPPORT TCP NOW !!!')
        else :
            self.logger.info('INVALID PROTOCOL !!! ONLY SUPPORT IPV4 NOW !!!')

    def _operate_flow_from_gateway(self,msg,datapath,eth_pkt,ip_pkt,tsl_pkt):
        if not ip_pkt :
            return
        parser = datapath.ofproto_parser
        src_ip = ip_pkt.src
        dst_ip = ip_pkt.dst
        target_container = self.persistent.findOne('container',{'private_ip':dst_ip})
        if not target_container :
            self.logger.info('Target IP : %s'%dst_ip)
            self.logger.info("CANNOT FIND CORRECT CONTAINER !!!!")
            return
        src_port = tsl_pkt.src_port
        dst_port = tsl_pkt.dst_port
        match = parser.OFPMatch(eth_type = 0x800,ip_proto=6,ipv4_src = src_ip,ipv4_dst = target_container['private_ip'],tcp_dst=dst_port,tunnel_id=msg.match['tunnel_id'])
        actions = [
            parser.OFPActionOutput(target_container['portId'])
        ]
        self.add_flow(datapath,1,match,actions)

        match = parser.OFPMatch(eth_type = 0x800,ip_proto=6,ipv4_dst = src_ip)
        self.add_flow(datapath,1,match,[
            parser.OFPActionOutput(msg.match['in_port'])
        ])
        out = parser.OFPPacketOut(datapath=datapath,buffer_id = datapath.ofproto.OFP_NO_BUFFER,in_port=datapath.ofproto.OFPP_CONTROLLER,actions=actions,data = msg.data)
        datapath.send_msg(out)






    def _operate_with_icmp(self,msg,datapath,ip_pkt,icmp_pkt,send_container,netns,eth):
        src = ip_pkt.src
        dst = ip_pkt.dst
        if 'backPortId' not in send_container :
            return
        parser = datapath.ofproto_parser
        if dst == '127.0.0.1' :
            actions = []
            actions.append(parser.OFPActionSetField(ipv4_dst=send_container['private_ip']))
            actions.append(parser.OFPActionSetField(eth_dst=send_container['backMac']))
            actions.append(parser.OFPActionOutput(send_container['backPortId']))
            match = parser.OFPMatch(eth_type=0x800,in_port=msg.match['in_port'],ipv4_dst=dst,ipv4_src = src)
            self.add_flow(datapath,1,match,actions)

            actions = [
                parser.OFPActionSetField(ipv4_src='127.0.0.1'),
                parser.OFPActionSetField(ipv4_dst=src),
                parser.OFPActionSetField(eth_src = eth.dst),
                parser.OFPActionOutput(send_container['portId'])
            ]
            match = parser.OFPMatch(eth_type=0x800,in_port=send_container['backPortId'],ipv4_dst=src)
            self.add_flow(datapath,1,match,actions)
        elif dst == send_container['private_ip'] and src == netns['ip']:
            print 'to self private IP addr '
            self.add_flow(datapath,1,parser.OFPMatch(eth_type=0x800,in_port=send_container['backPortId'],ipv4_dst=src,ipv4_src=dst),
                [
                    parser.OFPActionOutput(send_container['portId'])
                ]
            )
            out = parser.OFPPacketOut(datapath=datapath,buffer_id=msg.buffer_id,in_port=msg.match['in_port'],actions = [
                    parser.OFPActionOutput(send_container['backPortId'])
                ], data = msg.data if msg.buffer_id==datapath.ofproto.OFP_NO_BUFFER else None)
            datapath.send_msg(out)

    def _operate_with_ip(self,msg,datapath,ip_pkt,send_container,netns,eth):
        pass

    def _operate_with_transport_layer(self,msg,datapath,pkt,ip_pkt,send_container,netns,eth,protocol='tcp'):
        print 'protocol is %s , src mac is %s , dst mac is %s'%(protocol,eth.src,eth.dst)
        print 'protocol is %s , src ip is %s , dst ip is %s'%(protocol,ip_pkt.src,ip_pkt.dst)
        print 'INPORT is %s'%msg.match['in_port']
        dst_port = pkt.dst_port
        dst_ip = ip_pkt.dst
        #print 'from %s:%s to %s:%s '%(ip_pkt.src,pkt.src_port,ip_pkt.dst,pkt.dst_port)
        # dst_netns = self.persistent.findOne('netns',{'ip':dst_ip}) if dst_ip != '127.0.0.1' and dst_ip != netns['ip'] else netns
        target_container = None
        if dst_ip == '127.0.0.1' or dst_ip == netns['ip'] or dst_ip == send_container['private_ip']:
            dst_netns = netns
        else :
            dst_netns = self.persistent.findOne('netns',{'ip':dst_ip})
            if not dst_netns :
                target_container = self.persistent.findOne('container',{'private_ip':dst_ip})
                if target_container :
                    dst_netns = self.persistent.findOne('netns',{'_id':target_container['netnsId']})
                else :
                    dst_netns = None
        if not dst_netns :
            self.logger.info('No Netns exists !')
            return

        target_container = self.persistent.findOne('container',{'_id':dst_netns['containerPortMapping'].get(str(dst_port))})

        #此时，目的IP为系统外的IP地址
        if not target_container :
            self.logger.info('cannot find target coantainer for port %s!'%dst_port)
            #TODO:修改IP包的目标地址，并将起发往in_port
            return

        #同一个netns下
        if target_container['netnsId'] == send_container['netnsId'] :
            self._transport_in_netns(msg,datapath,pkt,ip_pkt.src,dst_ip,dst_port,send_container,target_container,dst_netns)
        else :
            self._transport_between_netns(msg,datapath,pkt,ip_pkt.src,dst_ip,dst_port,send_container,target_container,dst_netns)

    def _transport_in_netns(self,msg,datapath,pkt,src_ip,dst_ip,dst_port,send_container,target_container,dst_netns):
         #target_port = target_container['portId']
         print 'from %s:%s to %s:%s '%(src_ip,pkt.src_port,dst_ip,pkt.dst_port)
         in_port = msg.match['in_port']
         print 'in port is %d'%in_port
         parser = datapath.ofproto_parser
         src_port = pkt.src_port
         #当源与目标在同一个主机上时
         #同一个namespace之间的各个容器间只能通过localhost通信
         if target_container['hostId'] == send_container['hostId'] :
             actions = []
             if dst_ip == '127.0.0.1' :
                 #发出包
                 actions.append(parser.OFPActionSetField(ipv4_dst=target_container['private_ip']))
                 actions.append(parser.OFPActionSetField(eth_dst=target_container['mac']))
                 actions.append(parser.OFPActionOutput(target_container['portId']))
                 match = parser.OFPMatch(eth_type=0x800,ip_proto=6,in_port=in_port,tcp_dst=dst_port,ipv4_dst=dst_ip,ipv4_src = src_ip)
                 self.add_flow(datapath,1,match,actions)
                 #TODO : 清除tcp src_port为当前src_port的流表项
                 match = parser.OFPMatch(eth_type = 0x800,ip_proto=6,in_port=target_container['portId'],tcp_src=dst_port,ipv4_src = target_container['private_ip'],ipv4_dst=send_container['private_ip'])
                 backActions = []
                 backActions.append(parser.OFPActionSetField(eth_src=MAGIC_MAC_ADDR))
                 backActions.append(parser.OFPActionSetField(ipv4_src='127.0.0.1'))
                 backActions.append(parser.OFPActionOutput(send_container['portId']))
                 self.add_flow(datapath,1,match,backActions)
                 out = parser.OFPPacketOut(datapath=datapath,buffer_id = datapath.ofproto.OFP_NO_BUFFER,in_port=msg.match['in_port'],actions=actions,data = msg.data)
                 datapath.send_msg(out)

             else :
                 pass

         else :
             #跨主机间
             #发包
             match = parser.OFPMatch(eth_type=0x800,ip_proto=6,tcp_dst=dst_port,ipv4_dst=dst_ip,ipv4_src = src_ip)
             senderHost = self.persistent.findOne('host',{'_id':send_container['hostId']})
             portId = senderHost['targetPorts'].get(target_container['hostId'])
             if not portId :
                 self.logger.info('no tunnel between two host !!!!!!')
                 return
             if not isinstance(portId,int) :
                 #portId = senderHost['portNameList'].index(portId)+1
                 senderHost['targetPorts'][target_container['hostId']] = portId
             actions = [
                parser.OFPActionSetField(tunnel_id=dst_netns['flag']),
                parser.OFPActionOutput(portId)
             ]
             self.add_flow(datapath,1,match,actions)

             #回包
             #对端将包的原地址改成127.0.0.1后再发
             match = parser.OFPMatch(eth_type=0x800,ip_proto=6,in_port=portId,tcp_dst=src_port,ipv4_dst=src_ip,ipv4_src = dst_ip,tunnel_id=dst_netns['flag'])
             backActions = [
                 parser.OFPActionOutput(in_port)
             ]
             self.add_flow(datapath,1,match,backActions)

             out = parser.OFPPacketOut(datapath=datapath,buffer_id = datapath.ofproto.OFP_NO_BUFFER,in_port=msg.match['in_port'],actions=actions,data = msg.data)
             datapath.send_msg(out)


    def _transport_between_netns(self,msg,datapath,pkt,src_ip,dst_ip,dst_port,send_container,target_container,dst_netns):
         #target_port = target_container['portId']
         print 'from %s:%s to %s:%s '%(src_ip,pkt.src_port,dst_ip,pkt.dst_port)
         in_port = msg.match['in_port']
         print 'in port is %d'%in_port
         parser = datapath.ofproto_parser
         src_port = pkt.src_port
         #当源与目标在同一个主机上时
         #同一个namespace之间的各个容器间只能通过localhost通信
         if target_container['hostId'] == send_container['hostId'] :
             actions = []

             #发出包
             actions.append(parser.OFPActionSetField(ipv4_dst=target_container['private_ip']))
             actions.append(parser.OFPActionSetField(eth_dst=target_container['mac']))
             actions.append(parser.OFPActionOutput(target_container['portId']))
             match = parser.OFPMatch(eth_type=0x800,ip_proto=6,in_port=in_port,tcp_dst=dst_port,ipv4_dst=dst_ip,ipv4_src = src_ip)
             self.add_flow(datapath,1,match,actions)
             #TODO : 清除tcp src_port为当前src_port的流表项
             match = parser.OFPMatch(eth_type = 0x800,ip_proto=6,in_port=target_container['portId'],tcp_src=dst_port,ipv4_src = target_container['private_ip'],ipv4_dst=send_container['private_ip'])
             backActions = []
             backActions.append(parser.OFPActionSetField(eth_src=MAGIC_MAC_ADDR))
             backActions.append(parser.OFPActionSetField(ipv4_src=dst_ip))
             backActions.append(parser.OFPActionOutput(send_container['portId']))
             self.add_flow(datapath,1,match,backActions)
             out = parser.OFPPacketOut(datapath=datapath,buffer_id = datapath.ofproto.OFP_NO_BUFFER,in_port=msg.match['in_port'],actions=actions,data = msg.data)
             datapath.send_msg(out)

         else :
             #跨主机间
             #发包
             match = parser.OFPMatch(eth_type=0x800,ip_proto=6,tcp_dst=dst_port,ipv4_dst=dst_ip,ipv4_src = src_ip)
             senderHost = self.persistent.findOne('host',{'_id':send_container['hostId']})
             portId = senderHost['targetPorts'].get(target_container['hostId'])
             if not portId :
                 self.logger.info('no tunnel between two host !!!!!!')
                 return
             if not isinstance(portId,int) :
                 #portId = senderHost['portNameList'].index(portId)+1
                 senderHost['targetPorts'][target_container['hostId']] = portId
             actions = [
                parser.OFPActionSetField(tunnel_id=dst_netns['flag']),
                parser.OFPActionOutput(portId)
             ]
             self.add_flow(datapath,1,match,actions)

             #回包
             #对端将包的原地址改成127.0.0.1后再发
             match = parser.OFPMatch(eth_type=0x800,ip_proto=6,in_port=portId,tcp_dst=src_port,ipv4_dst=src_ip,ipv4_src = dst_ip,tunnel_id=dst_netns['flag'])
             backActions = [
                 parser.OFPActionOutput(in_port)
             ]
             self.add_flow(datapath,1,match,backActions)

             out = parser.OFPPacketOut(datapath=datapath,buffer_id = datapath.ofproto.OFP_NO_BUFFER,in_port=msg.match['in_port'],actions=actions,data = msg.data)
             datapath.send_msg(out)



    def _operate_with_arp(self,msg,datapath,arp_pkt,send_container,netns,eth):
        #由控制器代理回复arp请求
        opcode =arp_pkt.opcode
        actions = []
        in_port = msg.match['in_port']
        if opcode == arp.ARP_REQUEST :
            self.logger.info('arp request from port %d'%in_port)
            actions.append(datapath.ofproto_parser.OFPActionOutput(in_port))
            dst_ip = arp_pkt.dst_ip
            self.logger.info('dst ip is : %s'%dst_ip)
            #判断是否是本地IP
            if dst_ip == '127.0.0.1' or dst_ip == send_container['private_ip']:
                dst_netns = self.persistent.findOne('netns',{'_id':send_container['netnsId']})
            else :
                dst_netns = self.persistent.findOne('netns',{'ip':dst_ip})

            if True :
                #容器内部互相通信
                if dst_ip == '127.0.0.1' :
                    macaddr = MAGIC_MAC_ADDR
                #容器之间通信
                elif self.persistent.findOne('netns',{'ip':dst_ip}) :
                    macaddr = MAGIC_MAC_ADDR
                else :
                    targetContainer = self.persistent.findOne('container',{'private_ip':dst_ip})
                    if targetContainer :
                        macaddr = targetContainer['mac']
                    else :
                        macaddr = 'ff:ff:ff:ff:ff:ff'
                reply = packet.Packet()
                reply.add_protocol(ethernet.ethernet(ethertype=eth.ethertype,dst=eth.src,src=macaddr))
                reply.add_protocol(arp.arp(
                    opcode=arp.ARP_REPLY,
                    #src_mac=containerWithNetns['mac'],
                    src_mac=macaddr,
                    src_ip=arp_pkt.dst_ip,
                    dst_mac=eth.src,
                    dst_ip = arp_pkt.src_ip
                ))
                reply.serialize()

                out = datapath.ofproto_parser.OFPPacketOut(
                    datapath=datapath,
                    buffer_id = datapath.ofproto.OFP_NO_BUFFER,
                    in_port=datapath.ofproto.OFPP_CONTROLLER,
                    actions = actions,
                    data = reply.data
                )
                datapath.send_msg(out)

        #如果是arp reply ，将其导向相应的port，或直接泛洪
        elif opcode == arp.ARP_REPLY :
            dst_mac = arp_pkt.dst_mac
            container = self.persistent.findOne('container',{'mac':dst_mac})
            out_port = None
            if container :
                out_port = container['portId']
            if not out_port :
                out_port = datapath.ofproto.OFPP_FLOOD
            actions.append(datapath.ofproto_parser.OFPActionOutput(out_port))
            out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                   in_port=in_port, actions=actions, data=msg.data)
            datapath.send_msg(out)

    def reply_arp(self,datapath,in_port,arp_pkt,eth,macaddr):
        actions = []
        actions.append(datapath.ofproto_parser.OFPActionOutput(in_port))
        reply = packet.Packet()
        reply.add_protocol(ethernet.ethernet(ethertype=eth.ethertype,dst=eth.src,src=macaddr))
        reply.add_protocol(arp.arp(
            opcode=arp.ARP_REPLY,
            src_mac=macaddr,
            src_ip=arp_pkt.dst_ip,
            dst_mac=eth.src,
            dst_ip = arp_pkt.src_ip
        ))
        reply.serialize()

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id = datapath.ofproto.OFP_NO_BUFFER,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions = actions,
            data = reply.data
        )
        datapath.send_msg(out)

    def _update_container_info(self,datapath,in_port,mac):
        container = self.persistent.findOne('container',{'mac':mac})
        if container :
            #self.logger.info('container with mac %s connect to port %s'%(container['mac'],in_port))
            container['portId'] = in_port
            container['dpId'] = datapath.id
            #保存最新的容器信息
            self.persistent.update('container',{'_id':container['_id']},container)
        else :
            container = self.persistent.findOne('container',{'backMac':mac})
            if container :
                container['backPortId'] = in_port

        return container

    def mapping_datapath_with_host(self,datapath=None,host=None):
        if datapath :
            addr = datapath.address[0]
            host = self.persistent.findOne('host',{'switchIp':addr})
            if host :
                host['dpid'] = datapath.id
                self.persistent.update('host',{'_id':host['_id']},host)
                self.datapaths[datapath.id]['host'] = host
            return host
        elif host :
            switchIp = host['switchIp']
            for item in self.datapaths.values() :
                dp = item['datapath']
                addr = dp.address[0]
                if addr == switchIp :
                    host['dpid'] = dp.id
                    self.persistent.update('host',{'_id':host['_id']},host)
                    item['host'] = host
                    return host
        return None




class NetnsExController(ControllerBase):

    def __init__(self, req, link, data, **config):
        super(NetnsExController, self).__init__(req, link, data, **config)
        self.app = data[instance_name]
        self.persistent = self.app.persistent


    @route('get_host_id', url+'/getHostId/{hostMac}/{transIp}/{switchIp}', methods=['GET'],requirements={'hostMac':r'[a-z0-9:]+','transIp':r'[0-9\\.]+'})
    def get_host_id(self, req, **kwargs):
        print self.persistent.persistent
        reply = {}
        hostMac = kwargs['hostMac']
        transIp = kwargs['transIp']
        switchIp = kwargs['switchIp']
        host = self.persistent.findOne('host',{'mac':hostMac,'transIp':transIp,'switchIp':switchIp})
        if host :
            reply['id'] = host['_id']
        else :
            host = self.persistent.save('host',{'mac':hostMac,'transIp':transIp,'switchIp':switchIp,'containers':[],'flag':TunnelFlagGenerator.nextFlag()})
            reply['id'] = host['_id']

        #TODO:增加可扩展性（该部分目前只适合存在内存中）
        #TODO:并发时或有bug
        if 'bridge' not in host :
            bridge = self.app.bridges.get('tcp:%s:6632'%switchIp)
            if bridge :
                host['bridge'] = bridge
                print 'new created : '
                print host
                self.persistent.update('host',{'_id':host['_id']},host)
            self.build_tunnel_for_new_host(host)

        self.app.mapping_datapath_with_host(host=host)
        return self.successReturn(reply)

    @route('create_container', url+'/createContainer', methods=['POST'])
    def create_container(self, req, **kwargs):
        # print req.body
        # print req.environ
        data = cgi.parse_multipart(req.body_file,{'boundary':self._getBoundary(req)})
        ip = data.get('ip')[0]
        host = self.persistent.findOne('host',{'_id':data.get('host')[0]}) if 'host' in data else None
        image = data.get('image')[0] if 'image' in data else None
        servicePort = data.get('servicePort')[0] if 'servicePort' in data else -1
        privateIp = ipgen.generateIp()
        if ip and host :
            result = self.request_host_to_create_container(host,ip,servicePort=servicePort,image=image,privateIp=ipgen.generateIp())
            print result
            if 'container' in result :
                newContainer = self.persistent.save('container',self.parse_container(result['container']))
            else :
                return self.failReturn("Fail to create container")

            netns = self.persistent.findOne('netns',{'_id':newContainer['netnsId']})
            if not netns :
                if 'netns' in result :
                    print 'parse netns now!'
                    netns = self.persistent.save('netns',self.parse_netns(result['netns'],ip))
                    netns['creatorId'] = newContainer['id']
                    self.persistent.update('netns',{'_id':netns['_id']},netns)
            if newContainer['hostId'] not in netns['hostContainerMapping'] :
                netns['hostContainerMapping'][newContainer['hostId']] = [newContainer['_id']]
                self.persistent.update('netns',{'_id':netns['_id']},netns)
            else :
                #如果相应主机已经存在该netns，则将初始netns的privateIp赋予新的container实例，以作为返回接口的IP
                # initContainer = self.persistent.findOne('container',{'_id':netns['hostContainerMapping'][newContainer['hostId']]})
                # newContainer['privateIp'] = initContainer['privateIp']
                # self.persistent.update('container',{'_id':newContainer['_id']},newContainer)
                netns['hostContainerMapping'][newContainer['hostId']].append(newContainer['_id'])
                self.persistent.update('netns',{'_id':netns['_id']},netns)

            if 'servicePort' in newContainer :
                port = newContainer['servicePort']
                if int(port) > 0 :
                    if port in netns['containerPortMapping'] :
                        return self.failReturn("Duplicate port : %d"%port)
                    netns['containerPortMapping'][port] = newContainer['_id']

            netns.setdefault('containers',[])
            netns['containers'].append(newContainer['_id'])

            if newContainer['hostId'] not in netns['hosts'] :
                netns['hosts'].append(newContainer['hostId'])

            self.persistent.update('netns',{'_id':netns['_id']},netns)
            print self.persistent.persistent

            self.request_container_to_boot_self(host,newContainer)
            return self.successReturn({
                'container':newContainer,
                'netns' : netns
            })
        else :
            return self.failReturn("Miss Arguments !")




    def successReturn(self,data):
        reply = {'state':'success','data':data}
        return Response(content_type='application/json', body=json.dumps(reply))

    def failReturn(self,reason):
        return Response(content_type='application/json', body=json.dumps({'state':'failed','reason':reason}))

    #TODO:并发场景不适合，改之
    #TODO:port id 获取方式不对!!!
    def build_tunnel_for_new_host(self,newHost):
        hosts = self.persistent.findAll('host')
        newHost.setdefault('targetPorts',{})
        nBridge = newHost['bridge']
        for h in hosts :
            if h['_id'] == newHost['_id'] :
                continue
            h.setdefault('targetPorts',{})
            oBridge = h['bridge']
            nNum = self._get_tunnel_port_num(newHost)
            oNum = self._get_tunnel_port_num(h)

            nBridgeName = 'vxlan%d'%nNum
            nBridge.add_tunnel_port(nBridgeName,'vxlan',newHost['switchIp'],h['switchIp'],key='flow')
            newHost['targetPorts'][h['_id']] = nBridge.get_ofport(nBridgeName)

            oBridgeName = 'vxlan%d'%oNum
            oBridge.add_tunnel_port(oBridgeName,'vxlan',h['switchIp'],newHost['switchIp'],key='flow')
            h['targetPorts'][newHost['_id']] = oBridge.get_ofport(oBridgeName)

            h['portNameList'] = oBridge.get_port_name_list()
            self.persistent.update('host',{'_id':h['_id']},h)

        nBridge.add_tunnel_port(TO_GATE_TUNNEL_NAME,'vxlan',newHost['switchIp'],GATEWAY_ADDR,key='flow')
        gate_tunnel_name = 'to_host_%d'%newHost['flag']
        if gate_tunnel_name not in self.app.gateBridge.get_port_name_list() :
            self.app.gateBridge.add_tunnel_port(gate_tunnel_name,'vxlan',GATEWAY_ADDR,newHost['switchIp'],key='flow')
        self.app.gateToHostConnections[newHost['_id']] = self.app.gateBridge.get_ofport(gate_tunnel_name)

        newHost['toGatePort'] = nBridge.get_ofport(TO_GATE_TUNNEL_NAME)
        self.persistent.update('host',{'_id':newHost['_id']},newHost)





    def _get_tunnel_port_num(self,host):
        return len(host['targetPorts'].values())

    def request_host_to_create_container(self,host,ip,servicePort=-1,image=None,privateIp=None):
        # host = self.persistent.findOne('host',{'_id':host})
        if 'transIp' in host :
            url = "http://%s:%d/createContainer"%(host['transIp'],conf['client_port'])
            netns = self.persistent.findOne('netns',{'ip':ip.split('/')[0]})
            if not privateIp :
                privateIp = ip
            #是否应在此时建立network namespace ???
            data = {
                'ip' : ip,
                'serialId' : str(uuid.uuid4()),
                'image' : image,
                'servicePort' : servicePort,
                'netns' : json.dumps(netns),
                'privateIp' : privateIp+'/24'
            }
            r = requests.post(url,data=data)
            return r.json()
        else :
            return {}

    def request_container_to_boot_self(self,host,container):
        if 'pid' not in container :
            print 'No Pid Field In Container !!!'
            return
        requests.get("http://%s:%d/bootSelf"%(host['transIp'],conf['client_port']),params = {'pid':container['pid']})

    def parse_container(self,container_raw):
        return {
            'portId' : '',
            'mac' : container_raw['mac'],
            'backMac' : container_raw.get('backMac'),
            'hostId' : container_raw['hostId'],
            'dpId' : '',
            'netnsId' : container_raw['netnsId'],
            'id' : container_raw['id'],
            'create_time' : container_raw['createTime'],
            'servicePort' : container_raw.get('servicePort'),
            'pid' : container_raw['pid'],
            'private_ip' : container_raw.get('privateIp').split('/')[0]
        }

    def parse_netns(self,netns_raw,ip):
        return {
            '_id' : netns_raw['uuid'],
            'ip' : ip.split('/')[0],
            'cidrMask' : ip.split('/')[1] if len(ip.split('/'))>=2 else '',
            'containerPortMapping' : {},
            'hosts' : [],
            'containers' : [],
            'hostContainerMapping' : {},
            'initHostId' : netns_raw['initHostId'],
            'flag' : TunnelFlagGenerator.nextFlag()
        }

    def _getBoundary(self,req):
        contentType = req.environ['CONTENT_TYPE']
        for item in contentType.split(';') :
            if 'boundary' in item  :
                return item.split('=')[1]
        return None

