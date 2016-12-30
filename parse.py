#!/usr/bin/env python
#_*_coding:utf-8_*_

from xml.etree import ElementTree as et
from lib.datatype import AttribDict
from collections import deque

class Payload(object):

    def __init__(self):
        """
	xmlfile是测试payload的文件地址
	"""
        self.payloads = deque()
	self.xmlfile ="./payload/payload.xml"
    
    def parseXmlNode(self):
        """
	解析payload.xml中的数据
	"""
        doc = et.parse(self.xmlfile)
	root = doc.getroot()
	for element in root.getiterator('test'):
	    test = AttribDict()
	    for child in element.getchildren():
	        if child.text and child.text.strip():
		    test[child.tag] = child.text
                else:
		    if len(child.getchildren()) == 0:
		        test[child.tag] = None
			continue
                    else:
		        test[child.tag] = AttribDict()
                    for gchild in child.getchildren():
			test[child.tag][gchild.tag] = gchild.text
            self.payloads.append(test)
        return self.payloads

