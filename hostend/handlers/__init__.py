# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from tornado.web import RequestHandler
from tornado import gen
import uuid
import tornado.escape
import copy

class CreateContainerHandler(RequestHandler):
    @gen.coroutine
    def post(self):
        ip = self.get_argument('ip')
        netns = self.get_argument('netns',default=None)
        image = self.get_argument('image',default='ubuntu')
        serialId = self.get_argument('serialId')
        servicePort = self.get_argument('servicePort')
        container,netns = self.application.containerProxy.create_container(ip,netns,image=image,command='/bin/sh',stdin_open=True,tty=True,detach=True)
        ns = copy.deepcopy(netns.__dict__)
        del ns['containers']
        self.write(dict(serialId = serialId,container = container.__dict__.update({'servicePort':servicePort}),netns = ns))
