# -*- coding:utf-8 -*-
import threading
import time



class TunnelFlagGenerator(object) :
    lock = threading.Lock()
    startFlag = 1
    @classmethod
    def nextFlag(cls):
        cls.lock.acquire()
        currentFlag = cls.startFlag
        cls.startFlag+=1
        cls.lock.release()
        return currentFlag






