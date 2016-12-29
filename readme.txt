read.me

使用说明

Lscan

安全测试工具，检测常见的web漏洞，包括文件遍历(TRAV)、命令执行(OSCI)、反射型XSS(RXSS)、存储型XSS(SXSS)、服务器端请求伪造(SSRF)等web漏洞。

Introduce

1.系统环境kail，脚本环境python2.x
2.类似于sqlmap安全测试工具，可以在payload.xml中自定义扩展测试的payload.

Installation

splinter
phantomjs

Usage



例子

get型参数检测
--param
root@kali2:~/Lscan# python lscan.py --url "http://demo.aisec.cn/demo/aisec/html_link.php?mid=2&id=1&action=2" --param id
设置*
root@kali2:~/Lscan# python lscan.py --url "http://demo.aisec.cn/demo/aisec/html_link.php?mid=2&id=1*&action=2"
无参数设置
root@kali2:~/Lscan# python lscan.py --url "http://demo.aisec.cn/demo/aisec/html_link.php?mid=2&id=1&action=2"
正常使用

post型参数检测
无参数检测
root@kali2:~/Lscan# python lscan.py --url "http://192.168.76.224/test_cmd" --data "id=1*&cmd=test&action=read"
--param
root@kali2:~/Lscan# python lscan.py --url "http://192.168.76.224/test_cmd" --data "id=1&cmd=test&action=read" --param read
设置*
root@kali2:~/Lscan# python lscan.py --url "http://192.168.76.224/test_cmd" --data "id=1&cmd=test*&action=read"

cookie/header检测
字典要用单引号
--header的检测
python lscan.py --url "http://192.168.76.224/test_cmd" --data "id=1&cmd=test&action=read" --header "{'id':'test','cmd':'test','X-Forwarded—For','test*'}"
--cookie的检测
python lscan.py --url "http://192.168.76.224/test_cmd" --data "id=1&cmd=test&action=read" --cookie "{'id':'test','cmd':'test','X-Forwarded—For','test*'}"
出现漏洞


显示情况介绍等 

显示的例子等等
