# -*- coding: utf-8 -*-
from abc import ABCMeta,abstractmethod
CONTAINER_STATE_ACTIVE = 1
CONTAINER_STATE_INACTIVE = 2
CONTAINER_STATE_MIGRATING = 3
CONTAINER_STATE_PREPARE = 4

class Container(object):
    host = None
    pid = None
    id = None
    ifaces = []
    netns = None
    image = None
    dataDirectory = ''
    createTime = None
    state = CONTAINER_STATE_PREPARE
    belongsTo = None
    createProxy = None

    @abstractmethod
    def attachToNetworkNamespace(self,netns):
        pass

    @abstractmethod
    def detachNetworkNamespace(self,netns):
        pass


class DockerContainer(Container) :
    def attachToNetworkNamespace(self,netns):
        pass

    def detachNetworkNamespace(self,netns):
        pass




