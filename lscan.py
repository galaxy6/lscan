#!/usr/bin/env python2.7
#_*_coding:utf-8_*_

import os
import re
import datetime
import logging
import functools
import threading
from lib.config import *
from parse import Payload
from verify import Verification
from cmdline import cmdLineParser
from cmdline import option_
from lib.datatype import AttribDict
from lib.datatype import InjectionDict

from lib.common import banner
from lib.common import kill_phantomjs
from lib.common import get_baseurl
from lib.common import get_standard_data
from lib.common import get_standard_cookie
from lib.common import get_standard_param
from lib.common import get_flag_url
from lib.common import get_flag_data
from lib.common import get_flag_header
from lib.common import get_origi_url


def initTargetEnv():
    """
    初始化数据
    """
    option,args = cmdLineParser()
    Injections = InjectionDict()

    if option.url:
        Injections.url = option.url
        Injections.p = option.testParameter if option.testParameter else None
        Injections.level = option.level if option.level else '1'
        Injections.tech = option.tech if option.tech else None
        Injections.headers = option.headers if option.headers else ''
        Injections.cookie = option.cookie if option.cookie else ''

        if option.data:
            Injections.ptype = 'POST'
            Injections.data = option.data if option.data else ''
            return Injections
        else:
            Injections.ptype = 'GET'
            return Injections 
    else:
        logging.info("You must enter the URL link !")

def httpFormat():
    '''
    1.通过p参数指定测试元素
	2.直接通过*好的位置指定测试的元素
	3.默认情况(没有指定测试的参数)下的各个参数测试
    '''
    Injections = initTargetEnv()
 

    if Injections.p:
        if Injections.data:
            if Injections.p in Injections.data:
                data= get_standard_data(Injections.data,Injections.p)
                Injections.data = data
                Injections.place = 'p'
                return Injections
        elif Injections.p in Injections.url:
            url = get_standard_param(Injections.url,Injections.p)
            Injections.url = url
            Injections.place = 'p'
            return Injections

    #在url中，data中，cookie或者header中设置了标记的情况
    if Injections.url.find('*') != -1:
        url = get_flag_url(Injections.url)
        Injections.url = url
        Injections.place = "set"
        return Injections

    if Injections.data and Injections.data.find('*') != -1:
        data = get_flag_data(Injections.data)
        Injections.data = data
        Injections.place = "set"
        return Injections


    #headers设置成词典的形式
    if Injections.headers and Injections.headers.find('*') != -1:
        headers = get_flag_header(Injections.headers)
        Injections.headers = headers
        Injections.place = "set"
        return Injections

         
    #cookie设置成字典的形式
    if Injections.cookie and Injections.cookie.find('*') != -1:
        cookie = get_flag_header(Injections.cookie)
        Injections.cookie = cookie
        Injections.place = "set"
        #print Injections
        return Injections

    #什么都不设置的情况,直接返回原始url数据
    #print Injections
    return Injections


if __name__ == '__main__':
    """
    主函数解析xmlde的payloads，并多线程调用验证类
    """
    option_()
    banner()

    print '[*] Starting at {time_}'.format(time_=datetime.datetime.now().strftime('%H:%M:%S'))
	
    threads = []
    for payload in Payload().parseXmlNode():
        try:
        	threads.append(threading.Thread(target=Verification,args=(payload,httpFormat())))
        except Exception,e:
            pass
    for t in threads:
        t.start()
    for t in threads:
        t.join()
	kill_phantomjs()
    print '[*] shutting down at {time_}'.format(time_=datetime.datetime.now().strftime('%H:%M:%S'))
