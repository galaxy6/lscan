#!/usr/sbin/env python
#_*_coding:utf-8_*_

import sys
import optparse
import datetime
from lib.config import G,W

def cmdLineParser():
    """
    命令行中初始化各参数
    """

    parser = optparse.OptionParser(usage='Usage: python xx.py [Options] [URL]')
    parser.add_option("--version", dest="showVersion",action="store_true",help="Show program's version number and exit")
    parser.add_option("--url", dest="url", help="Parser URL (e.g. \"http://www.xxx.com/vuln.php?id=1\")")
    parser.add_option("--data", dest="data",help="Data string to be sent through POST")
    parser.add_option("--cookie", dest="cookie",help="HTTP Cookie header")
    parser.add_option("--headers", dest="headers",help="Extra headers (e.g. \"Accept-Language: fr\\nETag: 123\")")
    parser.add_option("--param", dest="testParameter",help="Testable parameter(s)")
    parser.add_option("--level", dest="level", type="int",default=1,help="Level of tests to perform (1-5, default 1)")
    parser.add_option("--technique", dest="tech",help="SQL injection techniques to use")
    (options,args) = parser.parse_args()
    return (options,args)


def option_():
    """
    判断输出的参数是否正
    """
    option,args = cmdLineParser()
    if option.url == None or option.url =="None":
        print G+'Usage: python controller.py -h or --help'+W
        sys.exit(0)
