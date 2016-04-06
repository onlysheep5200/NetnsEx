# -*- coding: utf-8 -*-
__author__ = 'hyd'
from abc import ABCMeta,abstractmethod
from lib.exceptions import ArgumentTypeException
from uuid import uuid4


'''
    schemas :
        container : 标识一个容器
            portId : 对应的交换机端口号
            mac : container的mac地址
            hostId : 容器对应的主机ID
            dpId : 容器所连接到的ovs的dpid
            netnsId : 容器所属的网络命名空间ID
            id : 容器引擎赋予容器的ID
            _id : persistent赋予容器的ID
            servicePort : ''
            create_time : 创建时间

        netns :
            ip : Namespace对应的IP地址
            cidrMask : IP地址对应的CIDR掩码
            containerPortMapping : 每个netns中开放的端口和服务所在容器的对应关系
            flag : 唯一性标识，用来租户隔离，暂时使用vlanId
            hosts ： 存在该netns所属容器的主机
            containers ： 所属容器，存容器的_id字段
            _id :

        Host :
            _id : 容器ID
            containers : 所包含的容器，记录_id
            mac : 主机的mac地址
            transIp : 发送请求的IP地址
            switchIp : vxlan对应IP
            dpid : 主机对应的datapath id


'''

class DataPersistent(object) :
    __meta__ = ABCMeta

    @abstractmethod
    def save(self,schema,data):
        pass

    @abstractmethod
    def remove(self,schema,id):
        pass

    @abstractmethod
    def update(self,schema,old,current):
        pass

    @abstractmethod
    def query(self,schema,conditions):
        pass

    @abstractmethod
    def findOne(self,schema,conditions):
        pass


class TestPersistent(DataPersistent) :

    def __init__(self):
        self.persistent = {}

    def save(self,schema,data):
        self.persistent.setdefault(schema,{})
        if not isinstance(data,dict) :
            raise ArgumentTypeException(data)

        if '_id' not in data :
            data['_id'] = str(uuid4())
            self.persistent[schema][data['_id']] = data
        return data

    def remove(self,schema,id):
        if schema not in self.persistent :
            return 0
        if not isinstance(id,list) :
            id = [id]
        for item in id :
            del self.persistent[schema][item]

        return len(id)

    def update(self,schema,old,current):
        self.persistent.setdefault(schema,{})
        if '_id' in old :
            t = self.persistent[schema].get(old['_id'])
            if t == None :
                return 0
            t.update(current)
            return 1
        else :
            c = 0
            for item in self.persistent[schema].values() :
                if self._dict_partial_equals(old,item) :
                    item.update(current)
                    c += 1
            return c

    def query(self,schema,conditions):
        self.persistent.setdefault(schema,{})
        targets = []

        if '_id' in conditions :
            print 'condition is :',conditions
            key = conditions['_id']
            targets.append(self.persistent[schema].get(key))
            return targets

        for item in self.persistent[schema].values() :
            if self._dict_partial_equals(conditions,item) :
                targets.append(item)
        return targets

    def findOne(self,schema,conditions):
        results = self.query(schema,conditions)
        if results :
            return results[0]
        return None




    def _dict_partial_equals(self,dict1,dict2):
        first,last = (dict2,dict1) if len(dict1.keys()) > len(dict2.keys()) else (dict1,dict2)
        for key in first :
            if first[key] != last.get(key):
                return False

        return True





