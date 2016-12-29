#!/usr/bin/evn python2.7
#_*_coding:utf-8_*_

import time
import random
import string
from injection import SendRequest
from injection import BrowserRequest
from lib.config import *
from lib.common import print_
from lib.common import get_url
from lib.common import findStr
from lib.common import replaceStr
from lib.common import current_time
import threading
import multiprocessing
class StandardOut(object):
   """
   装饰器，线程锁，标准数据输出，多线程下数据不会乱
   """
   def __init__(self):
       self.thread_lock = threading.Lock()

   def __call__(self,func):
       def _call(*args,**kw):
           self.thread_lock.acquire()
           func(*args,**kw)
           self.thread_lock.release()
       return _call

class Verification(object):
    """
    漏洞验证
    """
    def __init__(self,payloads,http_data):
        """
        初始化http请求数据和payloads数据
        """
        self.payloads = payloads
        self.http_data = http_data
        self.run()
    
    @StandardOut()
    def echo(self,flag,url,desc,data="",header="",cookie=""):
        if flag:
            content = "[%s] [INFO] testing '%s' "%(current_time(),desc)
            header = "Header: %s"%header if header else ""
            cookie = "Cookie: %s"%cookie if cookie else ""
            types  = "Type: POST" if data else "Type: GET"
            if len(data)>0:
                if len(header)>0:
                    info = "%sTitle: %s\n%s\nPayload: %s\nData: %s\n%s%s"%(Y,desc,types,url,data,header,W)
                elif len(cookie)>0:
                    info = "%sTitle: %s\n%s\nPayload: %s\nData: %s\n%s%s"%(Y,desc,types,url,data,cookie,W)
                else:
                    info = "%sTitle: %s\n%s\nPayload: %s\nData: %s%s"%(Y,desc,types,url,data,W)
            else:
                if len(header)>0:
                    info = "%sTitle: %s\n%s\nPayload: %s\n%s%s"%(Y,desc,types,url,header,W)
                elif len(cookie)>0:
                    info = "%sTitle: %s\n%s\nPayload: %s\n%s%s"%(Y,desc,types,url,cookie,W)
                else:
                    info = "%sTitle: %s\n%s\nPayload: %s%s"%(Y,desc,types,url,W)
            print_(content,R,W)
            print_(info,G,W)
        else:
            content  = "[%s] [INFO] testing '%s' "%(current_time(),desc)
            print_(content,G,W)
        return
    @StandardOut()
    def echo_status(self,status,url,desc,data="",header="",cookie=""):
        '''
        存储型xss信息输出，结果需要在触发的位置查看
        '''
        if status == 200:
            content = "[%s] [INFO] testing '%s' [RESULT] 'Saved successfully !' "%(current_time(),desc)
            print_(content,B,W)
        else:
            content  = "[%s] [INFO] testing '%s' "%(current_time(),desc)
            print_(content,G,W)


    def run(self):
        """
        #检测payload的具体流程
        #函数，四种不同的检测方式
        思路
        不同的类型进行不同的测试
            tech=1 匹配返回内容的值
            tech=2 直接提交插入xss的payload，结果需要手动在触发位置查看。
            tech=3 利用浏览器模拟进行反射型xss的测试和检测。
            tech=4 利用dnslog的方式进行检测

        Injection.level中的值和payload中的level值对比来取出url
        """
        if self.payloads.tech == "1":
            if self.http_data.place =="p":
                if self.http_data.ptype == "GET":
                    url = self.http_data.url.get(self.payloads.level)
                    url_ = url.replace("*",self.payloads.request.payload if self.payloads.request.payload else "")
                    flag = SendRequest(url_,"",cookie,header,timeout).sendReqRex(self.payloads.response.grep)
                    self.echo(flag,url_,self.payloads.title)
                else:
                    data = self.http_data.data.get(self.payloads.level)
                    data_ = data.replace('*',self.payloads.request.payload if self.payloads.request.payload else "")
                    flag = SendRequest(self.http_data.url,data_,cookie,header,timeout).sendReqRex(self.payloads.response.grep)
                    self.echo(flag,self.http_data.url,self.payloads.title,data=data_)

            if self.http_data.place == "set":
                if isinstance(self.http_data.url,dict):
                    url = self.http_data.url.get(self.payloads.level)
                    url_ = url.replace("*",self.payloads.request.payload if self.payloads.request.payload else "")
                    flag = SendRequest(url_,"",cookie,header,timeout).sendReqRex(self.payloads.response.grep)
                    self.echo(flag,url_,self.payloads.title)

                elif isinstance(self.http_data.data,dict):
                    data = self.http_data.data.get(self.payloads.level)
                    data_ = data.replace('*',self.payloads.request.payload if self.payloads.request.payload else "")
                    flag = SendRequest(self.http_data.url,data_,cookie,header,timeout).sendReqRex(self.payloads.response.grep)
                    self.echo(flag,self.http_data.url,self.payloads.title,data=data_)

                elif isinstance(self.http_data.headers,dict):
                    headers = self.http_data.headers.get(self.payloads.level)
                    header_ = eval(headers.replace('*',self.payloads.request.payload if self.payloads.request.payload else ""))
                    if self.http_data.ptype == "POST":
                        flag = SendRequest(self.http_data.url,self.http_data.data,cookie,header_,timeout).sendReqRex(self.payloads.response.grep)
                        self.echo(flag,self.http_data.url,self.payloads.title,data=self.http_data.data,header=header_)
                    else:
                        flag = SendRequest(self.http_data.url,"",cookie,header_,timeout).sendReqRex(self.payloads.response.grep)
                        self.echo(flag,self.http_data.url,self.payloads.title,data="",header=header_)
                elif isinstance(self.http_data.cookie,dict):
                    cookies = self.http_data.cookie.get(self.payloads.level)
                    cookies_ = eval(cookies.replace('*',self.payloads.request.payload if self.payloads.request.payload else ""))
                    if self.http_data.ptype == "POST":
                        flag = SendRequest(self.http_data.url,self.http_data.data,cookies_,header,timeout).sendReqRex(self.payloads.response.grep)
                        self.echo(flag,self.http_data.url,self.payloads.title,data=self.http_data.data,cookie=cookies_)
                    else:
                        flag = SendRequest(self.http_data.url,"",cookies_,header,timeout).sendReqRex(self.payloads.response.grep)
                        self.echo(flag,self.http_data.url,self.payloads.title,data="",cookie=cookies_)
                else:
                    #url为伪静态或不规则的情况
                    print '暂时还不能设置这个位置的参数'
    
            if self.http_data.place == None:
                #1.对get中url的参数逐次检查
                #2.对data中的参数逐次检查
                if self.http_data.ptype == "GET":
                    #GET参数处理
                    url1 = get_url(self.http_data.url)
                    '''url1=http://demo.aisec.cn/demo/aisec/html_link.php?id=2*&action=123*&mid=test*'''
                    count = url1.count("*")
                   
                    for i in range(count):
                        length = findStr(url1,'*',i)
                        if self.payloads.level == 'level2': 
                            signlength = url1[:length].rfind("=")
                          
                            url1 = "%s%s"%(url1[:signlength+1],url1[length:])
                        url_ = replaceStr(url1,findStr(url1,'*',i),self.payloads.request.payload).replace("*","")
                    
                        flag = SendRequest(url_,"",cookie,header,timeout).sendReqRex(self.payloads.response.grep)
                        self.echo(flag,url_,self.payloads.title)
                        url1 = get_url(self.http_data.url)
                else:
                    data = get_url(self.http_data.data)
                    count = data.count("*")
                    for i in range(count):
                        length = findStr(data,'*',i)
                        if self.payloads.level == 'level1': 
                            signlength = data[:length].rfind("=")
                            data = "%s%s"%(data[:signlength+1],data[length:])
                        data_ = replaceStr(data,findStr(data,'*',i),self.payloads.request.payload).replace("*","")
                        flag = SendRequest(self.http_data.url,data_,cookie,header,timeout).sendReqRex(self.payloads.response.grep)
                       
                        self.echo(flag,self.http_data.url,self.payloads.title,data=data_)
                        data = get_url(self.http_data.data)
                    #POST参数处理
                    pass
        
        if self.payloads.tech == "2":
            if self.http_data.place =="p":
                if self.http_data.ptype == "GET":
                    url = self.http_data.url.get(self.payloads.level)
                    url_ = url.replace("*",self.payloads.request.payload if self.payloads.request.payload else "")
                    status = SendRequest(url_,"",cookie,header,timeout).sendReqStatus()
                    self.echo_status(status,url_,self.payloads.title)
                else:
                    data = self.http_data.data.get(self.payloads.level)
                    data_ = data.replace('*',self.payloads.request.payload if self.payloads.request.payload else "")
                    status = SendRequest(self.http_data.url,data_,cookie,header,timeout).sendReqStatus()
                    self.echo_status(status,self.http_data.url,self.payloads.title,data=data_)

            
            if self.http_data.place == "set":
                if isinstance(self.http_data.url,dict):
                    url = self.http_data.url.get(self.payloads.level)
                    url_ = url.replace("*",self.payloads.request.payload if self.payloads.request.payload else "")
                    status = SendRequest(url_,"",cookie,header,timeout).sendReqStatus()
                    self.echo_status(status,url_,self.payloads.title)
                elif isinstance(self.http_data.data,dict):
                    data = self.http_data.data.get(self.payloads.level)
                    data_ = data.replace("*",self.payloads.request.payload if self.payloads.request.payload else "")
                    status = SendRequest(self.http_data.url,data_,cookie,header,timeout).sendReqStatus()
                    self.echo_status(status,self.http_data.url,self.payloads.title,data=data_)
                elif isinstance(self.http_data.headers,dict):
                    headers = self.http_data.headers.get(self.payloads.level)
                    header_ = eval(headers.replace('*',self.payloads.request.payload.replace("'","\\'") if self.payloads.request.payload else ""))
                    if self.http_data.ptype == "POST":
                        status = SendRequest(self.http_data.url,self.http_data.data,cookie,header_,timeout).sendReqStatus()
                        self.echo_status(status,self.http_data.url,self.payloads.title,data=self.http_data.data,header=header_)
                    else:
                        status = SendRequest(self.http_data.url,"",cookie,header_,timeout).sendReqStatus()
                        self.echo_status(status,self.http_data.url,self.payloads.title,data="",header=header_)
                elif isinstance(self.http_data.cookie,dict):
                    cookies = self.http_data.cookie.get(self.payloads.level)
                    cookies_ = eval(cookies.replace("*",self.payloads.request.payload.replace("'","\\'").replace(";","") if self.payloads.request.payload else ""))
                    if self.http_data.ptype == "POST":
                        status = SendRequest(self.http_data.url,self.http_data.data,cookies_,header,timeout).sendReqStatus()
                        self.echo_status(status,self.http_data.url,self.payloads.title,data=self.http_data.data,cookie=cookies_)
                    else:
                        status = SendRequest(self.http_data.url,"",cookies_,header,timeout).sendReqStatus()
                        self.echo_status(status,self.http_data.url,self.payloads.title,data="",cookie=cookies_)
                else:
                    #url为伪静态或不规则的情况
                    print '暂时还不能设置这个位置的参数'
        
            if self.http_data.place == None:
                if self.http_data.ptype == "GET":
                    url = get_url(self.http_data.url)
                    count = url.count("*")
                    for i in range(count):
                        length = findStr(url,'*',i)
                        if self.payloads.level == 'level2': 
                            signlength = url[:length].rfind("=")
                            url = "%s%s"%(url[:signlength+1],url[length:])
                        url_ = replaceStr(url,findStr(url,'*',i),self.payloads.request.payload).replace("*","")
                        status = SendRequest(url_,"",cookie,header,timeout).sendReqStatus()
                        self.echo_status(status,url_,self.payloads.title)
                        url = get_url(self.http_data.url)
                    
                else:
                    data = get_url(self.http_data.data)
                    count = data.count("*")
                    for i in range(count):
                        length = findStr(data,'*',i)
                        if self.payloads.level == 'level2': 
                            signlength = data[:length].rfind("=")
                            data = "%s%s"%(data[:signlength+1],data[length:])
                        data_ = replaceStr(data,findStr(data,'*',i),self.payloads.request.payload).replace("*","")
                        status = SendRequest(self.http_data.url,data_,cookie,header,timeout).sendReqStatus()
                        self.echo_status(status,self.http_data.url,self.payloads.title,data=data_)
                        data = get_url(self.http_data.data)
                    pass


        if self.payloads.tech =="3":
            if self.http_data.place=="p":
                if self.http_data.ptype == "GET":
                    url = self.http_data.url.get(self.payloads.level)
                    random_ = "".join(random.sample(string.ascii_lowercase,10))
                    payload_ = self.payloads.request.payload.replace("[random]",random_) if self.payloads.request.payload else ""
                    url_ = url.replace("*",payload_)
                    flag = BrowserRequest(url_).sendReqRex("<title>%s</title>"%random_)
                    self.echo(flag,url_,self.payloads.title)
            if self.http_data.place == "set":
                if isinstance(self.http_data.url,dict):
                    url = self.http_data.url.get(self.payloads.level)
                    random_ = "".join(random.sample(string.ascii_lowercase,10))
                    payload_ = self.payloads.request.payload.replace("[random]",random_) if self.payloads.request.payload else ""
                    url_ = url.replace("*",payload_)
                    flag = BrowserRequest(url_).sendReqRex("<title>%s</title>"%random_)
                    self.echo(flag,url_,self.payloads.title)
            if self.http_data.place == None:
                if self.http_data.ptype == "GET":
                    random_ = "".join(random.sample(string.ascii_lowercase,10))
                    url = get_url(self.http_data.url)
                    count = url.count("*")
                    for i in range(count):
                        length = findStr(url,'*',i)
                        if self.payloads.level == 'level2': 
                            signlength = url[:length].rfind("=")
                            url = "%s%s"%(url[:signlength+1],url[length:])
                        url_ = replaceStr(url,findStr(url,'*',i),self.payloads.request.payload.replace("[random]",random_) if self.payloads.request.payload else "").replace("*","")
                        flag = BrowserRequest(url_).sendReqRex("<title>%s</title>"%random_)
                        self.echo(flag,url_,self.payloads.title)
                        url = get_url(self.http_data.url)
 
   


        #使用dnslog/api的方式对漏洞是否触发进行判断
        if self.payloads.tech == "4":
            if self.http_data.place =="p":
                if self.http_data.ptype == "GET":
                    url = self.http_data.url.get(self.payloads.level)
                    random_ = "".join(random.sample(string.ascii_lowercase,10))
                    payload_ = self.payloads.request.payload.replace("[random]",random_) if self.payloads.request.payload else ""
                    url_ = url.replace("*",payload_)
                    status = SendRequest(url_,"",cookie,header,timeout).sendReqStatus_()
                    if status == 200:
                        time.sleep(3)
                        flag = SendRequest(self.payloads.response.url.replace("[random]",random_),"",cookie,header,timeout).sendReqRex("True")
                        self.echo(flag,url_,self.payloads.title)
                    else:
                        self.echo(False,url_,self.payloads.title)
                else:
                    data = self.http_data.data.get(self.payloads.level)
                    random_ = "".join(random.sample(string.ascii_lowercase,10))
                    payload_ = self.payloads.request.payload.replace("[random]",random_) if self.payloads.request.payload else ""
                    data_ = data.replace('*',payload_)
                    status = SendRequest(self.http_data.url,data_,cookie,header,timeout).sendReqStatus_()
                    if status == 200:
                        time.sleep(3)
                        flag = SendRequest(self.payloads.response.url.replace("[random]",random_),"",cookie,header,timeout).sendReqRex("True")
                        self.echo(flag,self.http_data.url,self.payloads.title,data=data_)
                    else:
                       self.echo(False,self.http_data.url,self.payloads.title,data=data_)
            if self.http_data.place == "set":
                if isinstance(self.http_data.url,dict):
                    url = self.http_data.url.get(self.payloads.level)
                    random_ = "".join(random.sample(string.ascii_lowercase,10))
                    payload_ = self.payloads.request.payload.replace("[random]",random_) if self.payloads.request.payload else ""
                    url_ = url.replace("*",payload_)
                    status = SendRequest(url_,"",cookie,header,timeout).sendReqStatus_()
                    if status == 200:
                        time.sleep(3)
                        flag = SendRequest(self.payloads.response.url.replace("[random]",random_),"",cookie,header,timeout).sendReqRex("True")
                        self.echo(flag,url_,self.payloads.title)
                    else:
                        self.echo(False,url_,self.payloads.title)
                elif isinstance(self.http_data.data,dict):
                    data = self.http_data.data.get(self.payloads.level)
                    random_ = "".join(random.sample(string.ascii_lowercase,10))
                    payload_ = self.payloads.request.payload.replace("[random]",random_) if self.payloads.request.payload else ""
                    data_ = data.replace('*',payload_)
                    status = SendRequest(self.http_data.url,data_,cookie,header,timeout).sendReqStatus_()
                    if status == 200:
                        time.sleep(3)
                        flag = SendRequest(self.payloads.response.url.replace("[random]",random_),"",cookie,header,timeout).sendReqRex("True")
                        self.echo(flag,self.http_data.url,self.payloads.title,data=data_)
                    else:
                        self.echo(False,self.http_data.url,self.payloads.title,data=data_)
                elif isinstance(self.http_data.headers,dict):
                    headers = self.http_data.headers.get(self.payloads.level)
                    random_ = "".join(random.sample(string.ascii_lowercase,10))    
                    payload_ = self.payloads.request.payload.replace("[random]",random_) if self.payloads.request.payload else ""
                    header_ = eval(headers.replace('*',payload_))
                    if self.http_data.ptype == "POST":
                        status = SendRequest(self.http_data.url,self.http_data.data,cookie,header_,timeout).sendReqStatus_()
                    else:
                        status = SendRequest(self.http_data.url,"",cookie,header_,timeout).sendReqStatus_()
                    if status == 200:
                        time.sleep(3)
                        flag = SendRequest(self.payloads.response.url.replace("[random]",random_),"",cookie,header,timeout).sendReqRex("True")
                        self.echo(flag,self.http_data.url,self.payloads.title,data=self.http_data.data,header=header_)
                    else:
                        self.echo(False,self.http_data.url,self.payloads.title,data=self.http_data.data,header=header_)
                elif isinstance(self.http_data.cookie,dict):
                    cookies = self.http_data.cookie.get(self.payloads.level)
                    random_ = "".join(random.sample(string.ascii_lowercase,10))
                    payload_ = self.payloads.request.payload.replace("[random]",random_).replace(";"," | ") if self.payloads.request.payload else ""
                    cookies_ = eval(cookies.replace('*',payload_))
                    
                    if self.http_data.ptype == "POST":
                        status = SendRequest(self.http_data.url,self.http_data.data,cookies_,header,timeout).sendReqStatus_()
                    else:
                        status = SendRequest(self.http_data.url,"",cookies_,header,timeout).sendReqStatus_()
            
                    if status == 200:
                        time.sleep(2)
                        flag = SendRequest(self.payloads.response.url.replace("[random]",random_),"",cookie,header,timeout).sendReqRex("True")
                        self.echo(flag,self.http_data.url,self.payloads.title,data=self.http_data.data,cookie=cookies_)
                    else:
                        self.echo(False,self.http_data.url,self.payloads.title,data=self.http_data.data,cookie=cookies_)
                else:
                    print '暂时还不能设置这个位置的参数'

            if self.http_data.place == None:
                if self.http_data.ptype == "GET":
                    url = get_url(self.http_data.url)
                    count = url.count("*")
                    for i in range(count):
                        random_ = "".join(random.sample(string.ascii_lowercase,10))
                        length = findStr(url,'*',i)
                        if self.payloads.level == 'level2': 
                            signlength = url[:length].rfind("=")
                            url = "%s%s"%(url[:signlength+1],url[length:])
                        url_ = replaceStr(url,findStr(url,'*',i),self.payloads.request.payload.replace("[random]",random_) if self.payloads.request.payload else "").replace("*","")
                        status = SendRequest(url_,"",cookie,header,timeout).sendReqStatus_()
                        if status == 200:
                            time.sleep(3)
                            flag = SendRequest(self.payloads.response.url.replace("[random]",random_),"",cookie,header,timeout).sendReqRex("True")
                            self.echo(flag,url_,self.payloads.title)
                        else:
                            self.echo(False,url_,self.payloads.title)
                        url = get_url(self.http_data.url)
                    
                else:
                    data = get_url(self.http_data.data)
                    count = data.count("*")
                    for i in range(count):
                        random_ = "".join(random.sample(string.ascii_lowercase,10))
                        length = findStr(data,'*',i)
                        if self.payloads.level == 'level2': 
                            signlength = data[:length].rfind("=")
                            data = "%s%s"%(data[:signlength+1],data[length:])
                        data_ = replaceStr(data,findStr(data,'*',i),self.payloads.request.payload.replace("[random]",random_) if self.payloads.request.payload else "").replace("*","")
                        status = SendRequest(self.http_data.url,data_,cookie,header,timeout).sendReqStatus_()
                        if status == 200:
                            time.sleep(3)
                            flag = SendRequest(self.payloads.response.url.replace("[random]",random_),"",cookie,header,timeout).sendReqRex("True")
                            self.echo(flag,self.http_data.url,self.payloads.title,data=data_)
                        else:
                            self.echo(False,self.http_data.url,self.payloads.title,data=data_)
                        data = get_url(self.http_data.data)

        
