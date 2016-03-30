import sys
sys.path.append('..')
from hostend.proxy import *
from lib.utils import Host
from hostend.controller import *
from lib.container import Container 
if __name__ == '__main__' :
    proxy = DockerProxy(Client('unix://var/run/docker.sock'),Host.currentHost('1212',switchInterface='ovsbr1'),Controller())
    container = proxy.create_container('10.232.0.3/24',None,image='ubuntu',command='/bin/sh',stdin_open=True,tty=True,detach=True)
    print(container.__dict__)
