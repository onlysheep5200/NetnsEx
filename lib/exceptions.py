# -*- coding: utf-8 -*-

class ContainerCreatorTypeInvalidError(Exception) :
    def __init__(self,value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class MissArgumentException(Exception) :
    def __init__(self,value):
        self.value = 'miss argument for : '+value

    def __str__(self):
        return repr(self.value)

class ArgumentTypeException(Exception) :
    def __init__(self,value):
        self.value = value

    def __str__(self):
        self.value = 'Invalid Argument for method : %s'%self.value


