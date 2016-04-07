# -*- coding: utf-8 -*-

def ipRange(start_ip, end_ip):
   start = list(map(int, start_ip.split(".")))
   end = list(map(int, end_ip.split(".")))
   temp = start
   ip_range = []

   ip_range.append(start_ip)
   while temp != end:
      start[3] += 1
      for i in (3, 2, 1):
         if temp[i] == 256:
            temp[i] = 0
            temp[i-1] += 1
      ip_range.append(".".join(map(str, temp)))

   return ip_range

generated = ipRange('172.0.0.1','172.0.255.224')

def generateIp():
    return generated.pop(1)

if __name__ == '__main__' :
    print generated
    print generateIp()
