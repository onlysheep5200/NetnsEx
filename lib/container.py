# -*- coding: utf-8 -*-
from abc import ABCMeta,abstractmethod
CONTAINER_STATE_ACTIVE = 1
CONTAINER_STATE_INACTIVE = 2
CONTAINER_STATE_MIGRATING = 3
CONTAINER_STATE_PREPARE = 4

class Container(object):
    hostId = None
    pid = None
    id = None
    mac = None
    netnsId = None
    image = None
    dataDirectory = ''
    createTime = None
    switch = None
    state = CONTAINER_STATE_PREPARE
    belongsTo = None
    servicePort = -1
    privateIp=None
    backMac = None

    def toJson(self):
        pass

    @classmethod
    def parseFromJson(cls):
        pass







