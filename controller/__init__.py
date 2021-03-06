# -*- coding: utf-8 -*-
'''
	本模块主要实现控制器相关功能
	主要包括：容器与命名空间的映射（通过容器所在的主机一级容器所对应的交换机接口进行）
			数据流量的规划（通过数据包的目的地址与目的端口进行，如果是ARP协议，则直接将arp包随机传向同一命名空间的任一可用容器）
			容器的迁移（流程见例图）
			访问控制（可由用户配置）

    部分数据结构 ：
        container :
            id
            dpid
            portId
            mac
            hostid
            netnsId


        netns:
            id
            ip
            containerPortMapping {container_id : port}
            flag
            hostId
            containers

        host :
            id
            containers
            transIp


'''