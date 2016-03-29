# -*- coding: utf-8 -*-
import netifaces
class Host(object):
    '''
    描述物理宿主机的数据结构
    '''
    mac = None
    transportIP = None
    containers = []
    proxys = []
    existNetworkNamespaces = []
    uuid = None

    def getConcreteProxy(self,ProxyClass):
        for item in self.proxys :
            if isinstance(item,ProxyClass) :
                return item
        return None

    @classmethod
    def currentHost(cls,switchInterface = None,transportInterface=None):
        if not getattr(cls,'currentHost') :
            switchInterface = Host._getInterfaceInfo(switchInterface)
            transportInterface = Host._getInterfaceInfo(transportInterface)
            cls.host = Host()
            cls.host.mac = switchInterface[netifaces.AF_LINK][0]['address']
            cls.host.transportIP = transportInterface[netifaces.AF_INET][0]['address']
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
            if netifaces.AF_INET in if_info and  if_info[netifaces.AF_INET][0]['address'] != '127.0.0.1' :
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
