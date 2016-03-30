# -*- coding: utf-8 -*-
import requests
import json
class Controller(object):

    reportUrl = None
    requestUrl = None

    def report(self,event):
        #requests.post(self.reportUrl,event)
        pass

    def request(self,resources):
        #requests.get(requests,data=dict(resources=resources))
        pass


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




