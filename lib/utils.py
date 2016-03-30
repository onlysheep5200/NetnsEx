# -*- coding: utf-8 -*-
import netifaces
from uuid import uuid4
class Host(object):
    '''
    描述物理宿主机的数据结构
    '''
    mac = None
    transportIP = None
    uuid = None
    switchInterface = None


    def getConcreteProxy(self,ProxyClass):
        for item in self.proxys :
            if isinstance(item,ProxyClass) :
                return item
        return None

    def getSwitchName(self):
        if self.switchInterface :
            return self.switchInterface.get('name')

    @classmethod
    def currentHost(cls,uuid,switchInterface = None,transportInterface=None):
        if not hasattr(cls,'host') :
            switchInterfaceInfo = Host._getInterfaceInfo(switchInterface)
            transportInterfaceInfo = Host._getInterfaceInfo(transportInterface)
            cls.host = Host()
            cls.host.mac = switchInterfaceInfo[netifaces.AF_LINK][0]['addr']
            cls.host.transportIP = transportInterfaceInfo[netifaces.AF_INET][0]['addr']
            cls.host.uuid = uuid
            cls.host.switchInterface = {
                'name' : switchInterface,
                'info' : switchInterfaceInfo
            }

        return cls.host



    @classmethod
    def _firstOfValidInterface(cls,interfaces):
        '''
        获取第一个非loopback网卡相应信息
        :param interfaces:
        :return:
        '''
        for interface in interfaces :
            if_info = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in if_info and  if_info[netifaces.AF_INET][0]['addr'] != '127.0.0.1' :
                return if_info
        return None

    @classmethod
    def _getInterfaceInfo(cls,interface=None):
        '''
        获取相应名称的网络接口的接口信息
        :param interface: 接口名称
        :return:
        '''
        validInterfaces = netifaces.interfaces()
        if interface and interface in validInterfaces :
            interface_info = netifaces.ifaddresses(interface)
        elif interface :
            raise NameError
        else :
            interface_info = Host._firstOfValidInterface(validInterfaces)
        return interface_info


class Switch(object) :
    host = None
    portsToContainers = {}
    portsInfo = {}
    bridgeName = ''
    def __init__(self,host,bridge):
        self.host = host
        self.bridgeName = bridge
