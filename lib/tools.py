# -*- coding: utf-8 -*-
import datetime
import time
import shlex
import subprocess

def now(fmt="%Y-%m-%d %H:%M:%S"):
    return datetime.datetime.now().strftime(fmt)

def timeToStr(datetime,fmt="%Y-%m-%d %H:%M:%S"):
    return datetime.strftime(fmt)

def strToTime(dateStr,fmt="%Y-%m-%d %H:%M:%S") :
    dt = datetime.datetime.fromtimestamp(time.mktime(time.strptime(dateStr,fmt)))
    return dt


def command_exec(command):
    '''
    执行命令行
    :param command: 所需执行的命令
    :return: 执行命令的return code
    '''
    if not isinstance(command,list) :
        command = shlex.split(command)

    process = subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    process.wait()
    return process.returncode


