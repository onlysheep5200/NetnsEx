#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import unicode_literals
import sys
sys.path.append('..')

from tornado.web import Application
import tornado.ioloop
import tornado.options
import tornado.httpserver
import tornado.autoreload
from tornado.options import define, options
from hostend.controller import *
from lib.utils import Host
from proxy import *
import docker
import json
from handlers import *

config = json.load(open('config.json','r'))
controller = Controller()
controller.reportUrl = config.get('reportUrl')
controller.requestUrl = config.get('requestUrl')

host = Host.currentHost('',switchInterface=config['switchName'],transportInterface=config['transportInterface'])
data = controller.request('getHostId',[host.mac,host.transportIP])
if 'uuid' in data :
    host.uuid = data['uuid']

print 'my host id is : %s'%host.uuid


define("port", default=8000, help="run on the given port", type=int)

class Application(tornado.web.Application):
    def __init__(self):
        handlers = [
            (r'/createContainer',CreateContainerHandler)
        ]

        settings = {
            'template_path': 'templates',
            'debug': True,
            'cookie_secret' : "dfaew989q2kejczo8u8923e400ialsjdf",
            'static_path': 'static'
        }

        self.host = host
        self.controller = controller
        self.containerProxy =  DockerProxy(docker.Client('unix://var/run/docker.sock'),self.host,self.controller)

        tornado.web.Application.__init__(self, handlers, **settings)

if __name__ == "__main__":
    tornado.options.parse_command_line()
    app = Application()
    http_server = tornado.httpserver.HTTPServer(app)
    http_server.listen(options.port)
    tornado.ioloop.IOLoop.instance().start()
