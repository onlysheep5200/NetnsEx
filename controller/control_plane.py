# -*- coding: utf-8 -*-
import  sys
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
from ryu.services.protocols.ovsdb import api as ovsdb
from ryu.services.protocols.ovsdb import event as ovsdb_event
from ryu.lib import dpid as dpid_lib
from ryu.lib.ovs.bridge import OVSBridge,CONF
from webob import Response
import json
from persistent import TestPersistent
import requests
import uuid
import cgi
import ipgen

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
        self.datapaths = {}
        wsgi = kwargs['wsgi']
        wsgi.register(NetnsExController, {instance_name : self,'persistent':self.persistent})
        self.tunnels = {}
        self.containerFlows = {}


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
        print bridge.db_get_val('Interface','vxlan1','type')



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



        #取得发包容器所属的netns
        sendContainer = self._update_container_info(datapath,in_port,src)
        if not sendContainer :
            self.logger.info('no sendcontainer recognize')
            return
        netns = self.persistent.findOne('netns',{'_id':sendContainer['netnsId']})

        if arp_pkt :
            arp_pkt = arp_pkt[0]
            self._operate_with_arp(msg,datapath,arp_pkt,sendContainer,netns,eth)

        elif icmp_pkt :
            print 'icmp packet coming'
            icmp_pkt = icmp_pkt[0]
            self._operate_with_icmp(msg,datapath,icmp_pkt,sendContainer,netns,eth)

        elif tcp_pkt or udp_pkt :
            self._operate_with_transport_layer(msg,datapath,tcp_pkt[0] if tcp_pkt else udp_pkt[0],ip[0],sendContainer,netns,eth)

        elif ip :
            print 'ip packet comming'
            ip = ip[0]
            self._operate_with_ip(in_port,datapath,ip,sendContainer,netns,eth)


    def _operate_with_icmp(self,msg,datapath,icmp_pkt,send_container,netns,eth):
        pass

    def _operate_with_ip(self,msg,datapath,ip_pkt,send_container,netns,eth):
        pass

    def _operate_with_transport_layer(self,msg,datapath,pkt,ip_pkt,send_container,netns,eth):
        dst_port = pkt.dst_port
        dst_ip = ip_pkt.dst
        dst_netns = self.persistent.findOne('netns',{'ip':dst_ip}) if dst_ip != 'localhost' and dst_ip != netns['ip'] else netns
        target_container = None
        #此时，目的IP为netns对应的IP地址
        if dst_netns :
            target_container = dst_netns['containerPortMapping'].get(dst_port)
        #此时，目的IP为privateIP，是返回包
        else:
            target_container = self.persistent.findOne('container',{'privateIp':dst_ip})

        #此时，目的IP为系统外的IP地址
        if not target_container :
            self.logger.log('cannot find target coantainer for port %s!'%dst_port)
            #TODO:修改IP包的目标地址，并将起发往in_port
            return

        #同一个netns下
        if target_container['netnsId'] == send_container['netnsId'] :
            self._transport_in_netns(msg,datapath,pkt,ip_pkt.src,dst_ip,dst_port,send_container,target_container,dst_netns)
        else :
            pass
            # target_port = target_container['portId']
            # match = parser.OFPMatch(tcp_dst=dst_port,ipv4_dst=('127.0.0.1',dst_netns['ip']))
            # actions = []
            # if dst_ip == '127.0.0.1' :
            #     actions.append(parser.OFPActionSetField(ipv4_dst=dst_netns['ip']))
            # actions.append(parser.OFPActionOutput(target_port))
            # data = None
            # if msg.buffer_id == datapath.ofproto.OFP_NO_BUFFER :
            #     data = msg.data
            # out = parser.OFPPacketOut(datapath=datapath,buffer_id = msg.buffer_id,in_port = msg.match['in_port'],actions=actions,data = data)
            # datapath.send_msg(out)
            # self.add_flow(datapath,12345,match,actions)



    def _transport_in_netns(self,msg,datapath,pkt,src_ip,dst_ip,dst_port,send_container,target_container,dst_netns):
         target_port = target_container['portId']
         parser = datapath.ofproto_parser
         #此时，目的IP为netns对应的IP地址或localhost
         if dst_ip == '127.0.0.1' or dst_ip == dst_netns['ip'] :
            match = parser.OFPMatch(tcp_dst=dst_port,ipv4_dst=('127.0.0.1',dst_netns['ip']))
         #此时，目的IP为privateIP，是返回包
         else :
            match = parser.OFPMatch(ipv4_dst=dst_ip)
         actions = []
         if dst_ip == '127.0.0.1' or dst_ip == dst_netns['ip'] :
             actions.append(parser.OFPActionSetField(ipv4_dst=target_container['privateIp']))
         else :
             actions.append(parser.OFPActionSetField(ipv4_src='127.0.0.1'))
         actions.append(parser.OFPActionOutput(target_port))
         data = None
         if msg.buffer_id == datapath.ofproto.OFP_NO_BUFFER :
             data = msg.data
         out = parser.OFPPacketOut(datapath=datapath,buffer_id = msg.buffer_id,in_port = msg.match['in_port'],actions=actions,data = data)
         datapath.send_msg(out)
         self.add_flow(datapath,12345,match,actions)



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
            if dst_ip == '127.0.0.1' :
                dst_netns = self.persistent.findOne('netns',{'_id':send_container['netnsId']})
            else :
                dst_netns = self.persistent.findOne('netns',{'ip':dst_ip})
            print dst_netns
            print self.persistent.persistent

            if dst_netns :
                print 'netns id is %s'%dst_netns['_id']
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

    def _update_container_info(self,datapath,in_port,mac):
        container = self.persistent.findOne('container',{'mac':mac})
        if container :
            #self.logger.info('container with mac %s connect to port %s'%(container['mac'],in_port))
            container['portId'] = in_port
            container['dpId'] = datapath.id
            #保存最新的容器信息
            self.persistent.update('container',{'_id':container['_id']},container)

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

    def _transport_flow_to_container(self,pkt,netns):
        pass

    def _flow_back_to_inport(self,inport,pkt):
        pass




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
            host = self.persistent.save('host',{'mac':hostMac,'transIp':transIp,'switchIp':switchIp,'containers':[]})
            reply['id'] = host['_id']
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

            if 'servicePort' in newContainer :
                port = newContainer['servicePort']
                if port > 0 :
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
                'netns' : netns,
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
        }

    def _getBoundary(self,req):
        contentType = req.environ['CONTENT_TYPE']
        for item in contentType.split(';') :
            if 'boundary' in item  :
                return item.split('=')[1]
        return None

