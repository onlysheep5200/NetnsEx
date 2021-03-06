#-*- coding:utf-8 -*-
import sys
sys.path.append('..')
from hostend.proxy import *
from lib.utils import Host
from hostend.controller import *
from lib.container import Container
import os

class NormalProxy(Proxy) :

    host = None
    controller = None

    def __init__(self,dockerClient,host,controller):
        if not isinstance(dockerClient,Client) :
            raise ContainerCreatorTypeInvalidError(dockerClient)
        self.client = dockerClient
        self.host = host
        self.controller = controller

    def create_container(self,ip,bindNetns=None,privateIp=None,*args,**kwargs):
        container = {}
        print bindNetns
        if not privateIp :
            privateIp = ip.split('/')[0]
        try :
            hostConfig = kwargs.get('host_config') if isinstance(kwargs.get('host_config'),dict) else self.client.create_host_config()
            #if bindNetns and isinstance(bindNetns,NetworkNamespace) and bindNetns.initHostId == self.host.uuid:
            if False :
                tid = bindNetns.hostContainerMapping[self.host.uuid]
                hostConfig['NetworkMode'] = 'container:%s'%tid
            else :
                hostConfig['NetworkMode'] = 'none'
            #hostConfig['privileged'] = True
            kwargs['host_config'] = hostConfig
            container = self.client.create_container(*args,**kwargs)
            self.client.start(container=container.get('Id'))
            containerInfo = self.client.inspect_container(container.get('Id'))
            pid = containerInfo['State']['Pid']
            self._link_netns_to_directory(pid)
            if hostConfig['NetworkMode'] == 'none' :
                 bridge = 'docker0'
                 if self.host.switchInterface :
                     bridge = self.host.getSwitchName()
                 #self._add_veth_to_netns(pid,bridge)
                 if not bindNetns :
                     bindNetns = self._create_netns(container,ip)
                 self._add_veth_to_netns(pid,privateIp,bridge,privateIp)


#            container = self._create_container_instance(containerInfo,self.host.switchInterface,bindNetns,privateIp=privateIp)
 #           self._after_create_container(container,bindNs=bindNetns)
            return container,bindNetns

        except Exception,e :
            containerId = None
            if container and isinstance(container,dict) and 'Id' in container :
                containerId = container['Id']
            elif container and isinstance(container,Container) :
                containerId = container.id

            if containerId :
                self.client.stop(container['Id'])
                self.client.remove_container(container['Id'])
            raise e

    def _link_netns_to_directory(self,pid):
        dir = '/proc/%d/ns/net'%pid
        target = '/var/run/netns/%d'%pid
        if os.path.exists(dir) :
            command = 'ln -s %s %s'%(dir,target)
            command_exec(command)

    def _add_veth_to_netns(self,pid,ip,bridge='docker0',privateIp=None):
        if not ip :
            raise MissArgumentException('ip')
        #添加正向接口
        veth = 'veth_%d'%pid
        peer = 'veth_%dc'%pid
        commonds = self._get_network_cmds(pid,ip,bridge,veth,peer)
        #添加反向接口
        # if privateIp :
        #     back_veth = 'b'+veth
        #     back_peer = 'b'+peer
        #     bcmds = self._get_back_network_cmds(pid,privateIp,bridge,back_veth,back_peer)
        #     commonds.extend(bcmds)

	exeCmd = ' && '.join(commonds)
        #command_exec(exeCmd)
        os.system(exeCmd)
        #for cmd in commonds :
        #    command_exec(cmd)

    def _get_network_cmds(self,pid,ip,bridge,veth,peer):
        commands = [ 'ip link add %s type veth peer name %s'%(veth,peer),
                    'ovs-vsctl add-port %s %s'%(bridge,veth),
                    'ip link set %s netns %d'%(peer,pid),
                    'ip netns exec %d ip link set dev %s name eth0'%(pid,peer),
                    'ip netns exec %d ip addr add %s dev eth0'%(pid,ip),
                    'ip netns exec %d ip link set eth0 up'%(pid),
                    'ip netns exec %d ifconfig eth0 promisc'%(pid),
                    'ip netns exec %d ip addr del 127.0.0.1/8 dev lo'%(pid),
                    'ip netns exec %d ip route add default dev eth0'%(pid),
                    'ip netns exec %d sysctl -w net.ipv4.conf.eth0.route_localnet=1'%(pid),
                    'ip link set %s up'%veth]
        return commands

    def _get_back_network_cmds(self,pid,ip,bridge,veth,peer):
        commands = [ 'ip link add %s type veth peer name %s'%(veth,peer),
                    'ovs-vsctl add-port %s %s'%(bridge,veth),
                    'ip link set %s netns %d'%(peer,pid),
                    'ip netns exec %d ip link set dev %s name back'%(pid,peer),
                    'ip netns exec %d ip addr add %s dev back'%(pid,ip),
                    'ip netns exec %d ip link set back up'%(pid),
                    'ip link set %s up'%veth]
        return commands

    def _create_netns(self,container,ip):
        netns = NetworkNamespace(str(self.host.uuid),ip)
        return netns


    def _create_container_instance(self,containerInfo,switch,netns,belongTo=None,privateIp=None):
        container = Container()
        container.belongsTo = belongTo
        container.createTime = now()
        container.hostId = str(self.host.uuid)
        container.id = containerInfo['Id']
        container.netnsId = netns.uuid
        container.pid = containerInfo['State']['Pid']
        container.state = CONTAINER_STATE_ACTIVE
        container.switch = switch
        container.privateIp = privateIp
        # p = subprocess.Popen(shlex.split('ip netns exec %d ifconfig eth0'%containerInfo['State']['Pid']),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        # if p.wait() == 0 :
        #     s = p.stdout.read()
        #     m = re.match(r'.* HWaddr (?P<mac>\S*).*',s)
        #     container.mac = m.groupdict().get('mac') if m else None
        # else :
        #     print p.stdout.read()
        #     print p.stderr.read()
        container.mac = self.get_mac_address(containerInfo['State']['Pid'],'eth0')
        #container.backMac = self.get_mac_address(containerInfo['State']['Pid'],'back')
        return container


    def _after_create_container(self,container,bindNs = None):
        if bindNs :
            bindNs = bindNs.__dict__
        else :
            bindNs = {}
        self.controller.report(Events.container_created_event(container.__dict__,bindNs))

    def get_mac_address(self,pid,interface):
        p = subprocess.Popen(shlex.split('ip netns exec %d ifconfig %s'%(pid,interface)),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        if p.wait() == 0 :
            s = p.stdout.read()
            m = re.match(r'.* HWaddr (?P<mac>\S*).*',s)
            mac = m.groupdict().get('mac') if m else None
            return mac
        else :
            print p.stdout.read()
            print p.stderr.read()
            return  None



    def remove(self,container):
        pass


if __name__ == '__main__' :
    num = int(sys.argv[1]) if len(sys.argv)>1 else 1
    proxy = NormalProxy(Client('unix://var/run/docker.sock'),Host.currentHost('1212',switchInterface='ovsbr1'),Controller())
    start = time.time()
    for i in xrange(num) :
        container = proxy.create_container('10.232.0.3/24',None,image='ubuntu',stdin_open=True,tty=True,detach=True)
    end = time.time()
    print 'time spend : %s'%(end-start)
