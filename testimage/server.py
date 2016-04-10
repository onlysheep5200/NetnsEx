#-*- coding:utf-8 -*-

from SocketServer import TCPServer, StreamRequestHandler
import traceback

class MyStreamRequestHandlerr(StreamRequestHandler):
    """
    #继承StreamRequestHandler，并重写handle方法
    #（StreamRequestHandler继承自BaseRequestHandler）
    """
    def handle(self):
        while True:
            #客户端主动断开连接时，self.rfile.readline()会抛出异常
            try:
                #self.rfile类型是socket._fileobject,读写模式是"rb",方法有
                #read,readline,readlines,write(data),writelines(list),close,flush
                data = self.rfile.readline().strip()
                print "receive from (%r):%r" % (self.client_address, data)

                #self.wfile类型是socket._fileobject,读写模式是"wb"
                self.wfile.write(data.upper())
            except:
                traceback.print_exc()
                break

if __name__ == "__main__":
    host = "0.0.0.0"       #主机名，可以是ip,像localhost的主机名,或""
    port = 9999     #端口
    addr = (host, port)

    server = TCPServer(addr, MyStreamRequestHandlerr)
    server.serve_forever()
