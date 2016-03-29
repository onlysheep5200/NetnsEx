# -*- coding: utf-8 -*-
'''
部分通用的数据结构
container.py :
	NetInterface : 描述容器的一个虚拟网卡
		-name : 虚拟网卡名称
		-hostVeth : 虚拟网卡对应的主机veth名称
		-ip : IP地址
		-mac : mac地址
		-vethMac : 主机veth的mac地址

		+ NetInterface::create : 创建一个虚拟网卡,返回NetInterface对象
			container : 目标容器
			vName : 容器端peer名字
			h_vName : 主机端peer的名字


	Container : 描述一个容器的数据结构，可持久化存储	
		-host : 容器所属的主机
		-pid : 主机中容器的pid
		-id : docker daemon 赋予容器的ID
		-ifaces [list] : 容器的虚拟网卡列表 ，为Interface对象集合
		-netns : 容器的网络命名空间,为NetworkNamespace对象实例
		-image : 创建容器所用的镜像名称
		-dataDirectory : 容器数据存储路径
		-createTime : 创建时间
		-state : 当前运行状态
		-belongsTo : 所属用户

		+attachToNetworkNamespace : 加入一个命名空间
			netns : 要加入的命名空间对象

		+detachNetworkNamespace : 离开命名空间
		    netns : 要离开的命名空间对象


net.py : 
	NetworkNamespace : 描述网络命名空间的数据结构 
		-uid : 唯一ID，初始化时通过uuid函数生成
		-addrs [list] : 网络命名空间所属IP，可谓多个，为cidr地址
		-containers : 加入网络的容器
		-initHost : 初始化该命名空间时，该命名空间所属的主机
		-createTime : 创建时间
		-belongsTo : 所属用户

	

utils.py:
	Host : 描述主机的数据结构
		-mac : mac地址
		-transportIp : 数据传输所用IP
		-containers : 主机所包行的容器，为Container对象列表
		-proxys : 主机上的容器创建代理代理列表

		+getConcreteProxy ：获取特定的容器创建代理类型
		    ProxyClass ： 代理类型

	Switch : 描述主机上安装着的虚拟交换机
		-host : 所属主机
		-portsToContainers : 交换机端口和容器的对应关系
		-portsInfo : 每个端口的相关信息
		-bridgeName : 网桥名称

exceptions.py :
    ContainerCreatorTypeInvalidError : 容器创建器与容器创建代理类型不匹配

tools.py :




'''