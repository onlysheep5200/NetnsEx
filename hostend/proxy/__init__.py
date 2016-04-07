# -*- coding: utf-8 -*-
from abc import ABCMeta,abstractmethod
from docker import Client
from lib.exceptions import *
from lib.utils import  Host,Switch
import shlex
import subprocess
from lib.net import NetworkNamespace
from lib.tools import *
import os.path
from lib.container import *
import re
from hostend.controller import *
import traceback
class Proxy(object):
    """容器创建代理"""
    __metaclass__ = ABCMeta

    @abstractmethod
    def create_container(self,bindingSwitch,bindNetns) :
        pass

    @abstractmethod
    def remove(self,container) :
        pass

class DockerProxy(Proxy) :

    host = None
    controller = None
	
    def __init__(self,dockerClient,host,controller):
        if not isinstance(dockerClient,Client) :
            raise ContainerCreatorTypeInvalidError(dockerClient)
        self.client = dockerClient
        self.host = host
        self.controller = controller

    def create_container(self,ip,bindNetns=None,privateIp=None,*args,**kwargs):
        '''
        创建容器
        :param ip : 分配的IP地址
        :param bindingSwitch: 绑定的本机ovs网桥
        :param bindNetns: 待绑定的网络命名空间信息
        :param args:
        :param kwargs:
        :return:
        '''
        container = {}
        print bindNetns
        if not privateIp :
            privateIp = ip.split('/')[0]
        try :
            hostConfig = kwargs.get('host_config') if isinstance(kwargs.get('host_config'),dict) else self.client.create_host_config()
            if bindNetns and isinstance(bindNetns,NetworkNamespace) and bindNetns.initHostId == self.host.uuid:
                tid = bindNetns.hostContainerMapping[self.host.uuid]
                hostConfig['NetworkMode'] = 'container:%s'%tid
            else :
                hostConfig['NetworkMode'] = 'none'
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

                self._add_veth_to_netns(pid,bridge)
                if not bindNetns :
                    bindNetns = self._create_netns(container,ip)
                self._add_veth_to_netns(pid,ip,bridge)


            container = self._create_container_instance(containerInfo,self.host.switchInterface,bindNetns,privateIp=privateIp)
            self._after_create_container(container,bindNs=bindNetns)
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
        veth = 'veth_%d'%pid
        peer = 'veth_%dc'%pid
        commonds = [ 'ip link add %s type veth peer name %s'%(veth,peer),
                    'ovs-vsctl add-port %s %s'%(bridge,veth),
                    'ip link set %s netns %d'%(peer,pid),
                    'ip netns exec %d ip link set dev %s name eth0'%(pid,peer),
                    'ip netns exec %d ip addr add %s dev eth0'%(pid,ip if not privateIp else privateIp),
                    'ip netns exec %d ip link set eth0 up'%(pid),
                    'ip netns exec %d ip addr del 127.0.0.1/8 dev lo'%(pid),
                    'ip netns exec %d ip route add default dev eth0'%(pid),
                    'ip link set %s up'%veth]
        for cmd in commonds :
            command_exec(cmd)






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
        p = subprocess.Popen(shlex.split('ip netns exec %d ifconfig eth0'%containerInfo['State']['Pid']),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        if p.wait() == 0 :
            s = p.stdout.read()
            print s
            m = re.match(r'.* HWaddr (?P<mac>\S*).*',s)
            container.mac = m.groupdict().get('mac') if m else None
        else : 
            print p.stdout.read()
            print p.stderr.read()
        return container


    def _after_create_container(self,container,bindNs = None):
        if bindNs :
            bindNs = bindNs.__dict__
        else :
            bindNs = {}
        self.controller.report(Events.container_created_event(container.__dict__,bindNs))




    def remove(self,container):
        pass



if __name__ == '__main__' :
    proxy = DockerProxy(Client('unix://var/run/docker.sock'),Host.currentHost('1212',switchInterface='ovsbr1'))
    container = proxy.create_container('10.232.0.3',None,image='ubuntu',command='/bin/sh',stdin_open=True,tty=True,detach=True)
    print container.__dict__


	
