# -*- coding: utf-8 -*-
import requests
import json
from lib.tools import *


class Controller(object):

    reportUrl = None
    requestUrl = None


    def report(self,event):
        #requests.post(self.reportUrl,event)
        pass

    def request(self,resources,data):
        #requests.get(requests,data=dict(resources=resources))
        url = combine_url(self.requestUrl,resources)
        if isinstance(data,dict) :
            r = requests.get(url,params=data)
        elif isinstance(data,list) :
            for x in data :
                url+= '/'+str(x)
            r = requests.get(url)
        else :
            r = None
        print 'the response for %s is %s'%(url,r.text if r else None)
        return r.json() if r else None




class Events(object):

    @classmethod
    def container_created_event(cls,container,netns=None):
        pass
       # return {
       #     'type' : 'container_created',
       #     'container' : json.dumps(container),
       #     'is_netns_created' : netns == None,
       #     'netns' : json.dumps(netns)
       # }





