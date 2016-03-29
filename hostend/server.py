#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from tornado.web import Application
import tornado.ioloop
import tornado.options
import tornado.httpserver
import tornado.autoreload
from tornado.options import define, options
import uuid
define("port", default=8000, help="run on the given port", type=int)

class Application(tornado.web.Application):
    def __init__(self):
        handlers = []

        settings = {
            'template_path': 'templates',
            'debug': True,
            'cookie_secret' : "dfaew989q2kejczo8u8923e400ialsjdf",
            'static_path': 'static'
        }

if __name__ == "__main__":
    tornado.options.parse_command_line()
    app = Application()
    http_server = tornado.httpserver.HTTPServer(app)
    http_server.listen(options.port)
    tornado.ioloop.IOLoop.instance().start()