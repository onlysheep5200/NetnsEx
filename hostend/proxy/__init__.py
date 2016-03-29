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
class Proxy(object):
    """容器创建代理"""
    __metaclass__ = ABCMeta

    @abstractmethod
    def create(self,bindingSwitch,bindNetns) :
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

    def create_container(self,bindingSwitch=None,bindNetns=None,*args,**kwargs):
        '''
        创建容器
        :param bindingSwitch: 绑定的本机ovs网桥
        :param bindNetns: 待绑定的网络命名空间信息
        :param args:
        :param kwargs:
        :return:
        '''
        container = {}
        try :
            hostConfig = kwargs.get('host_config') if isinstance(kwargs.get('host_config')) else self.client.create_host_config()
            if bindNetns and isinstance(bindNetns,NetworkNamespace) and bindNetns.initHostId == self.host.uuid:
                hostConfig['network_mode'] = 'container:%s'%bindNetns.creatorId
            else :
                hostConfig['network_mode'] = None

            container = self.client.create_container(*args,**kwargs)
            self.client.start(container=container.get('Id'))
            containerInfo = self.client.inspect_container(container.get('Id'))
            pid = containerInfo['State']['Pid']
            self._link_netns_to_directory(pid)
            bridge = 'docker0'
            if bindingSwitch and isinstance(bindingSwitch,Switch):
                bridge = bindingSwitch.bridgeName
            self._add_veth_to_netns(pid,bridge)
            if not bindNetns :
                bindNetns = self._create_netns(container)

            container = self._create_container_instance(containerInfo,bindingSwitch,bindNetns)
            self._after_create_container(container)
            return container

        except Exception,e :
            if container and 'Id' in container :
                self.client.stop(container['Id'])
                self.client.remove_container(container['Id'])
            raise e

    def _link_netns_to_directory(self,pid):
        dir = '/proc/%d/ns/net'%pid
        target = '/var/run/netns/%d'%pid
        if os.path.exists(dir) :
            command = 'ln -s %s %s'%(dir,target)
            command_exec(command)

    def _add_veth_to_netns(self,pid,ip,bridge='docker0'):
        veth = 'veth_%d'%pid
        peer = 'veth_%dc'%pid
        commonds = [ 'ip link add %s type veth peer name %s'%(veth,peer),
                     'ovs-vsctl add-port %s %s'%(bridge,veth),
                    'ip link set %s netns %d'%(peer,pid),
                    'ip netns exec %d ip link set dev %s name veth0 && ip addr add %s dev eth0 && ip link set eth0 up'%(pid,peer,ip),
                    'ip netns exec %d ip addr del 127.0.0.1/8 dev lo && ip route add 127.0.0.1/8 dev eth0',
                    'ip link set %s up'%veth]






    def _create_netns(self,container,ip):
        pass

    def _create_container_instance(self,containerInfo,switch,netns):
        pass

    def _after_create_container(self,container):
        pass



    def remove(self,container):
        pass




	
