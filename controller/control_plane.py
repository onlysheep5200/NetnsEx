# -*- coding: utf-8 -*-
import  sys
sys.path.append('..')
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet,ipv4,icmp,arp
from ryu.lib.packet import ether_types
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.lib import dpid as dpid_lib
from webob import Response
import json
from persistent import TestPersistent
import requests
import uuid

instance_name = 'netns_api_app'
url = '/netnsex'
conf = json.load(open('config.json','r'))

class NetnsExtension(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    _CONTEXTS = { 'wsgi': WSGIApplication ,'persistent' : TestPersistent}

    def __init__(self, *args, **kwargs):
        super(NetnsExtension, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.persistent = kwargs['persistent']
        self.allocated_ipaddrs = []
        wsgi = kwargs['wsgi']
        wsgi.register(NetnsExController, {instance_name : self,'persistent':self.persistent})

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
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
        icmp_pkt = pkt.get_protocols(icmp.icmp) if icmp in pkt.protocols else None
        ip = pkt.get_protocols(ipv4.ipv4) if ipv4.ipv4 in pkt.protocols else None


        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src



        #取得发包容器所属的netns
        sendContainer = self._update_container_info(datapath,in_port,src)
        if not sendContainer :
            return
        netns = self.persistent.findOne('netns',{'_id':sendContainer['netnsId']})

        if icmp_pkt :
            self._operate_with_icmp(in_port,datapath,icmp_pkt,sendContainer,netns,eth)

        if ip :
            self._operate_with_ip(in_port,datapath,ip,sendContainer,netns,eth)

        # dpid = datapath.id
        # self.mac_to_port.setdefault(dpid, {})
        #
        # self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
        #
        # # learn a mac address to avoid FLOOD next time.
        # self.mac_to_port[dpid][src] = in_port
        #
        # if dst in self.mac_to_port[dpid]:
        #     out_port = self.mac_to_port[dpid][dst]
        # else:
        #     out_port = ofproto.OFPP_FLOOD
        #
        # actions = [parser.OFPActionOutput(out_port)]
        #
        # # install a flow to avoid packet_in next time
        # if out_port != ofproto.OFPP_FLOOD:
        #     match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
        #     # verify if we have a valid buffer_id, if yes avoid to send both
        #     # flow_mod & packet_out
        #     if msg.buffer_id != ofproto.OFP_NO_BUFFER:
        #         self.add_flow(datapath, 1, match, actions, msg.buffer_id)
        #         return
        #     else:
        #         self.add_flow(datapath, 1, match, actions)
        # data = None
        # if msg.buffer_id == ofproto.OFP_NO_BUFFER:
        #     data = msg.data
        #
        # out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
        #                           in_port=in_port, actions=actions, data=data)
        # datapath.send_msg(out)

    def _operate_with_icmp(self,msg,datapath,icmp_pkt,send_container,netns,eth):
        pass

    def _operate_with_ip(self,msg,datapath,ip_pkt,send_container,netns,eth):

        pass

    def _operate_with_arp(self,msg,datapath,arp_pkt,send_container,netns,eth):
        #由控制器代理回复arp请求
        opcode =arp_pkt.opcode
        actions = []
        in_port = msg.match['in_port']
        if opcode == arp.ARP_REQUEST :
            actions.append(datapath.ofproto_parser.OFPActionOutput(in_port))
            dst_ip = arp_pkt.dst_ip
            dst_netns = self.persistent.findOne('netns',{'ip':dst_ip})
            if dst_netns :
                containerWithNetns = self.persistent.findOne('container',{'netnsId':dst_netns['_id']})
                reply = packet.Packet()
                reply.add_protocol(ethernet.ethernet(ethertype=eth.ethertype,dst=eth.src,src=containerWithNetns['mac']))
                reply.add_protocol(arp.arp(
                    opcode=arp.ARP_REPLY,
                    src_mac=containerWithNetns['mac'],
                    src_ip=arp_pkt.dst_ip,
                    dst_mac=eth.src,
                    dst_ip = arp_pkt.src_ip
                ))
                reply.serialize()

                out = datapath.ofproto_parser.OFPPacketOut(
                    datapath=datapath,
                    buffer_id = msg.buffer_id,
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

    def _update_container_info(self,datapath,in_port,mac):
        container = self.persistent.findOne('container',{'mac':mac})
        if container :
            container['portId'] = in_port
            container['dpId'] = datapath.id

        return container






    def _transport_flow_to_container(self,pkt,netns):
        pass

    def _flow_back_to_inport(self,inport,pkt):
        pass




class NetnsExController(ControllerBase):

    def __init__(self, req, link, data, **config):
        super(NetnsExController, self).__init__(req, link, data, **config)
        self.simpl_switch_spp = data[instance_name]
        self.persistent = data['persistent']


    @route('get_host_id', url+'/getHostName/{hostMac}/{transIp}', methods=['GET'],requirements={'hostMac':r'[a-z0-9:]+','transIp':r'[1-9\\.]+'})
    def list_mac_table(self, req, **kwargs):
        reply = {}
        hostMac = kwargs['hostMac']
        transIp = kwargs['transIp']
        host = self.persistent.findOne('host',{'mac':hostMac,'transIp':transIp})
        if host :
            reply['id'] = host['_id']
        else :
            host = self.persistent.save('host',{'mac':hostMac,'containers':[]})
            reply['id'] = host['_id']
        return self.successReturn(reply)

    @route('create_container', url+'/createContainer', methods=['POST'])
    def create_container(self, req, **kwargs):
        data = json.loads(req.body)
        ip = data.get('ip')
        host = self.persistent.findOne('host',{'id':data.get('host')})
        image = data.get('image')
        if ip and host :
            result = self.request_host_to_create_container(host,ip,image)
            if 'container' in result :
                newContainer = self.persistent.save(self.parse_container(result['container']))
            else :
                return self.failReturn("Fail to create container")

            if 'netns' in result :
                netns = self.persistent.save(self.parse_netns(result['netns']))
            else :
                netns = self.persistent.findOne(newContainer['netnsId'])
            netns.setdefault('containers',[])
            netns['containers'].append(newContainer['_id'])

            if newContainer['hostId'] not in netns['hosts'] :
                netns['hosts'].append(newContainer['hostId'])

            if 'servicePort' in newContainer :
                port = newContainer['servicePort']
                if port > 0 :
                    if port in netns['containerPortMapping'] :
                        return self.failReturn("Duplicate port : %d"%port)
                    netns['containerPortMapping'][port] = newContainer['_id']

            self.persistent.update('netns',{'_id':netns['_id']},netns)

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

    def request_host_to_create_container(self,host,ip,servicePort=-1,image=None):
        host = self.persistent.findOne('host',{'_id':host})
        if 'transIp' in host :
            url = "http://%s:%d/createContainer"%(host['transIp'],conf['client_port'])
            netns = self.persistent.findOne('netns',{'ip':ip.split('/')[0]})
            #是否应在此时建立network namespace ???
            data = {
                'ip' : ip,
                'serialId' : str(uuid.uuid4()),
                'image' : 'image',
                'servicePort' : servicePort,
                'netns' : netns
            }
            r = requests.post(url,json=data)
            return r.json()
        else :
            return {}

    def parse_container(self,container_raw):
        return {
            'portId' : '',
            'mac' : container_raw['mac'],
            'hostId' : container_raw['hostId'],
            'dpId' : '',
            'netnsId' : container_raw['netns_id'],
            'id' : container_raw['id'],
            'create_time' : container_raw['create_time'],
            'servicePort' : container_raw.get('servicePort')
        }

    def parse_netns(self,netns_raw):
        return {
            '_id' : netns_raw['uuid'],
            'ip' : netns_raw['ip'].split('/')[0],
            'cidrMask' : netns_raw['ip'].split('/')[1] if len(netns_raw['ip'].split('/'))>=2 else '',
            'containerPortMapping' : {},
            'hosts' : [],
            'containers' : [],
        }

