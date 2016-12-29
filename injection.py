#!/usr/bin/env python2.7
#_*_coding:utf-8_*_

import types
from lib.common import regex
from lib.common import getResponse
from lib.common import send_get_req
from lib.common import send_post_req
from lib.common import get_browser_url


class SendRequest(object):

	def __init__(self,url,data,cookie,header,timeout):
		self.url = url
		self.data = data
		self.cookie = cookie
		self.headers = header
		self.timeout = timeout


	def sendReq(self):
		"""
		获取函数网页返回内容
		"""
        
		if self.data == "":
			resp = send_get_req(self.url,self.headers,self.cookie,self.timeout)
		else:
			resp = send_post_req(self.url,self.data,self.headers,self.cookie,self.timeout)
		return resp
	
	def sendReqRex(self,keyword):
		"""
		利用程序进行正则匹配页面关键词的类
		静态http请求
		"""

		response = getResponse(self.sendReq())
		return regex(keyword,response)

	def sendReqLength(self):
		"""
		得到Response长度
		"""

		response = getResponse(self.sendReq())
		length = len(response)
		return length

	def sendReqStatus(self):
		"""
		Response返回值状态
        正常访问的情况
		"""
        	
		if type(self.sendReq()) !=types.StringType:
			code = self.sendReq().status_code
		else:
			code = 404
		return code

	def sendReqStatus_(self):
		"""
		返回值，针对命令执行的
		"""
		self.sendReq() 
		return 200
class BrowserRequest(object):
	"""
	浏览器请求模拟
	"""
	def __init__(self,url):
		self.url = url

	def sendReqRex(self,keyword):
		"""
		浏览器模拟的请求
		匹配其中的关键词
		"""
		resp = get_browser_url(self.url)
		return regex(keyword,resp)


