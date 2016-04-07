# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from tornado.web import RequestHandler
from tornado import gen
import uuid
import tornado.escape
import copy
import subprocess
import shlex
from lib.tools import command_exec
from lib.net import NetworkNamespace

class CreateContainerHandler(RequestHandler):
    @gen.coroutine
    def post(self):
        ip = self.get_argument('ip')
        netns = self.get_argument('netns',default=None)
        if netns :
            netns = NetworkNamespace.parseJson(netns)
        image = self.get_argument('image',default='ubuntu')
        serialId = self.get_argument('serialId')
        servicePort = self.get_argument('servicePort')
        privateIp = self.get_argument('privateIp')
        container,netns = self.application.containerProxy.create_container(ip,netns,privateIp=privateIp,image=image,command='/bin/sh',stdin_open=True,tty=True,detach=True)
        ns = copy.deepcopy(netns.__dict__)
        container = copy.deepcopy(container.__dict__)
        container['servicePort'] = servicePort
        # del ns['containers']
        self.write(dict(serialId = serialId,container = container,netns = ns))

class BootSelfHandler(RequestHandler):
    @gen.coroutine
    def get(self):
        pid = self.get_argument('pid')
        cmd = 'ip netns exec %s ping -c 1 localhost'%pid
        self.application.executionPool.submit(command_exec,cmd)
        self.write(dict(state='success'))

