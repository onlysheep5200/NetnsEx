import sys
sys.path.append('..')
from hostend.proxy import *
from lib.utils import Host
from hostend.controller import *
from lib.container import Container
import time
if __name__ == '__main__' :
    num = int(sys.argv[1]) if len(sys.argv)>1 else 1
    proxy = DockerProxy(Client('unix://var/run/docker.sock'),Host.currentHost('1212',switchInterface='ovsbr1'),Controller())
    start = time.time()
    for i in xrange(num) :
        container = proxy.create_container('10.232.0.3/24',None,image='ubuntu',command='/bin/sh',stdin_open=True,tty=True,detach=True)
    end = time.time()
    print 'time spend : %s'%(end-start)
