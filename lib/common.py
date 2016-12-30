#!/usr/bin/env python
#_*_coding:utf-8_*_

import os
import re
import signal
import urlparse
import logging
import requests
import datetime
from config import *
from splinter import Browser


def print_(context,color,background):
    print "%s%s%s"%(color,context,background)

def banner():
    print """%s

    Lscan/1.0-dev -  Automatic scanning tool for RXSS,SXSS,SSRF,OSCI,TRAV,etc..
    
    %s"""%(G,W)

def get_netloc(link):
    """
    这个函数的主要作用是得到url的域名
    参数： url链接
    """
    netloc = urlparse.urlparse(link).netloc
    if netloc:
        return netloc

def get_netloc_path(link):
    """
    这个函数的主要作用是得到url的协议域名路径
    参数：url链接
     
    """
    netloc = urlparse.urlparse(link).netloc
    scheme = urlparse.urlparse(link).scheme
    path = urlparse.urlparse(link).path
    request_url = "{scheme}://{netloc}{path}".format(scheme=scheme,netloc=netloc,path=path)
    return request_url

def get_baseurl(link):
    """
    这个函数的主要作用是得到url的协议域名路径
    参数： url链接
    """
    netloc = urlparse.urlparse(link).netloc
    scheme = urlparse.urlparse(link).scheme
    path = urlparse.urlparse(link).path
    query = urlparse.urlparse(link).query
    base_url = "{scheme}://{netloc}{path}?{query}".format(scheme=scheme,netloc=netloc,path=path,query=query)
    return base_url

def get_standard_cookie(cookies):
    """
    cookie格式化
    cookies_list参数：初始化的cookie
    cookie参数：增加的cookie

    """
    cookie ={}
    if cookies:
        cookies_list = cookies.split(";")
        for index in cookies_list:
            indexs = index.split('=',1)
            cookie[indexs[0].strip()] = indexs[1].strip()
    return cookie

def get_origi_url(link):
    """
    把url转换成特定的格式，方便操作url中的参数
    eg: level = 0  http://test.com/path?name=123&pass=admin ==> http://test.com/path?name=123*&pass=admin*
        level = 1  http://test.com/path?name=123&pass=admin ==> http://test.com/path?name=*&pass=*
    """
    urls = {}
    url1,num1 = re.subn(r"(=[^&]+)(&|$)","=*\g<2>*",link)
    url2,num2 = re.subn(r"(=[^&]+)(&|$)","\g<1>*\g<2>*",link)
    urls['level1'] = url1
    urls['level2'] = url2
    return urls
 
def get_standard_param(link,param):
    """
    设置p参数之后的url
    eg: level = 0  http://test.com/path?name=123&pass=admin ==> http://test.com/path?name=123*&pass=admin*
        level = 1  http://test.com/path?name=123&pass=admin ==> http://test.com/path?name=*123&pass=*admin

    """
    #返回两种结果供检测时调用
    urls = {}
    url1,num1 = re.subn(r"(&|\?)({param}=[^&]+)".format(param=param),"\g<1>\g<2>*",link)
    url2,num2 = re.subn(r"(&|\?)({param}=)[^&]+".format(param=param),"\g<1>\g<2>*",link)
    urls['level1'] = url1
    urls['level2'] = url2
    return urls
def get_standard_data(data,param):
    """
    对post中的data进行标志
    """

    datas = {}
    data1,num1 = re.subn(r"(&|^)({param}=[^&]+)".format(param=param),"\g<1>\g<2>*",data)
    data2,num2 = re.subn(r"(&|^)({param}=)[^&]+".format(param=param),"\g<1>\g<2>*",data)
    datas['level1'] = data1
    datas['level2'] = data2
    return datas


def get_flag_url(link):
    """
    设置p参数之后的url
    eg: level = 0  http://test.com/path?name=123*&pass=admin ==> http://test.com/path?name=123*&pass=admin
        level = 1  http://test.com/path?name=123*&pass=admin ==> http://test.com/path?name=*&pass=admin

    """
    #返回两种结果供检测时调用
    urls = {}
    url1,num1 = re.subn(r"(=[^&]+)\*","=*",link)
    urls['level1'] = link
    urls['level2'] = url1
    return urls

def get_flag_data(data):
    """
    对post中的data进行标志
    """

    datas = {}
    data1,num1 = re.subn(r"(=[^&]+)\*","=*",data)  
    datas['level1'] = data
    datas['level2'] = data1
    return datas
def get_url(link):
    """
    把url转换成特定的格式，方便操作url中的参数
    eg: level = 0  http://test.com/path?name=123&pass=admin ==> http://test.com/path?name=123*&pass=admin*
    url={}
    url,num1 = re.subn(r"(=[^&]+)(&|$)","\g<1>*\g<2>",link)
    url1,num2 = re.subn(r"(=[^&]+)(&|$)","=*\g<2>",link)
    urls['level1'] = url
    urls['level2'] = url1
    return urls
    """
    url,num1 = re.subn(r"(=[^&]+)(&|$)","\g<1>*\g<2>",link)

    return url

def get_flag_header(header):
    """
    在header中设置标志位
    {'level1': "{'X-Forworded-For':'127.0.0.1','Referer':'http://www.baidu.com*'}"
    {'level2': "{'X-Forworded-For':'127.0.0.1','Referer':'*'}"
    """
    headers = {}
    header1,num1 = re.subn(r"(\:\s*')[^,]+(\*')",'\g<1>\g<2>',header)
    headers['level1'] = header
    headers['level2'] = header1
    return headers

def logger():
    """
    日志记录初始化
    """
    logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s %(message)s',
                    datefmt='%a, %d %b %Y %H:%M:%S',
                    filename='/test.log',
                    filemode='w')

def send_get_req(url,headers,cookies,timeout):
    """
    模拟GET请求
    可以设置url的headers,cookies,timeout参数
    """
    try:
        resp = requests.Session().get(url, headers = headers, cookies= cookies,timeout=timeout)
    except Exception as e:
        resp = ""
        pass
    return resp

def get_browser_url(url):
    """
    模拟浏览器的url请求
    """
    try:
       browser = Browser("phantomjs")
       browser.visit(url)
       resp = browser.html
       browser.quit()
       return resp
    except Exception,e:
        return ""

def send_post_req(url,data,headers,cookies,timeout):
    """
    模拟POST请求
    可以设置url的data,headers,cookies,timeout参数
    """
    try:
        resp = requests.Session().post(url, data,headers = headers, cookies= cookies,timeout=timeout)
    except Exception as e:
        resp = ""
        pass
    return resp

def getResponse(response):
    """
    请求返回的内容
    """
    
    if response:
        try:
    	    if hasattr(response, "text"):
        	    return response.text
    	    else:
        	    return response.content
        except Exception,e:
            return ""
    else:
        return ""

def regex(mode,content):
    """
    获取正则匹配的返回值
    """
    pattern = re.compile(mode)
    result = pattern.findall(content)
    if result:
        return True
    else:
        return False

def findStr(string, subStr, findCnt):
    """
    查找子字符串subStr的位置,findCnt为第几个子字符串，最后一位-1改为正数表示
    """
    listStr = string.split(subStr,findCnt)
    
    if len(listStr) <= findCnt:
        return -1

    return len(string)-len(listStr[-1])-len(subStr) if (len(string)-len(listStr[-1])-len(subStr)) != -1 else len(string)-1

def replaceStr(string, num, replace):
    """
    替换num位置的字符串string，replace为替换的字符
    """
    string2 = ''
    for i in range(len(string)):
        if i == num:
            string2 += replace
        else:
            string2 += string[i]
    return string2

def current_time():
    """
    输出当前时间
    """
    now = datetime.datetime.now()
    current_time = now.strftime("%H:%M:%S")
    return current_time

def kill_phantomjs():
    """
    phantomjs访问部分网站时会超时，如果超时自动杀死
    """
    own = os.getpid()
    result = os.popen('ps aux')
    res = result.read()
    for line in res.splitlines():
        if 'phantomjs' in line:
            pid = int(line.split(None,2)[1])
            if pid != own:
                os.kill(pid,signal.SIGKILL)

