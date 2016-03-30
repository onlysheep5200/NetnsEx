import sys
sys.path.append('..')
from hostend.proxy import *
from lib.utils import Host
from hostend.controller import Controller
if __name__ == '__main__' :
    proxy = DockerProxy(Client('unix://var/run/docker.sock'),Host.currentHost('1212',switchInterface='ovsbr1'),Controller())
    proxy.create_container('10.232.0.3',None,image='ubuntu',command='/bin/sh',stdin_open=True,tty=True,detach=True)
