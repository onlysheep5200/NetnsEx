# -*- coding: utf-8 -*-
from utils import Host
from datetime import datetime
from tools import *
class NetworkNamespace(object) :
    '''
    NetworkNamespace : 描述网络命名空间的数据结构
		-uuid : 唯一ID，初始化时通过uuid函数生成
		-addrs [list] : 网络命名空间所属IP，可谓多个，为cidr地址
		-containers : 加入网络的容器
		-initHostId : 初始化该命名空间时，该命名空间所属的主机
		-createTime : 创建时间
		-creatorId : 创建该命名空间的容器的ID
		-belongsTo : 所属用户
    '''
    uuid = None
    addrs = []
    containers = []
    initHostId = None
    belongsTo = None
    createTime = None
    creatorId = None

    def __init__(self,host,address,belongsTo = None):
        self.initHost = host
        self.addrs.append(address)
        self.belongsTo = belongsTo
        self.createTime = now()



