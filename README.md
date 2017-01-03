#Lscan

##Lscan

安全测试工具，检测常见的web漏洞，包括文件遍历(TRAV)、命令执行(OSCI)、反射型XSS(RXSS)、存储型XSS(SXSS)、服务器端请求伪造(SSRF)等web漏洞。


##Introduce

1.系统环境kail，脚本环境python2.7

2.类似于sqlmap安全测试工具，可以在payload.xml中自定义扩展测试的payload.

##Installation

安装包

splinter

phantomjs

##Usage

漏洞检测

		利用param参数检测
		#python lscan.py --url "http://demo.xxx.cn/demo/xxx/html_link.php?mid=2&id=1&action=2" --param id
		
		设置星号标记检测，同sqlmap中的星号
		#python lscan.py --url "http://demo.xxx.cn/demo/xxx/html_link.php?mid=2&id=1*&action=2"
		
		直接提交请求，不设置参数就是全参数检测，同sqlmap
		#python lscan.py --url "http://demo.xxx.cn/demo/xxx/html_link.php?mid=2&id=1&action=2"
  
		post请求检测,同样支持*号设置和全参数检测
		#python lscan.py --url "http://demo.xxx.cn/demo/xxx/" --data "id=1&cmd=test&action=read" --param cmd
  
		cookie/header检测
		cookie和header仅仅支持星号类型的检测方式。字典要用单引号。
		#python lscan.py --url "http://demo.xxx.cn/demo/xxx/" --data "id=1&cmd=test&action=read" --header "{'cmd':'test','X-Forwarded—For','test*'}"
		#python lscan.py --url "http://demo.xxx.cn/demo/xxx/" --data "id=1&cmd=test&action=read" --cookie "{'id':'test','cmd':'test','admin','test*'}"


漏洞显示

		无漏洞情况
		[10:48:20] [INFO] testing 'RXSS [Payload] [";document.title="[random]";//]'

		存在漏洞的情况，kail系统下红色高亮提示，并提示利用的payload
		[10:48:23] [INFO] testing 'RXSS [Payload] [<svg onload=document.title="[random]">]'
		Title: RXSS [Payload] [<svg onload=document.title="[random]">]
		Type: GET
		Payload: http://demo.xxx.net/search.aspx?txtSearch=aa<svg onload=document.title="prtguzwycf">
  
		存储型XSS如果插入失败的情况
		[11:38:56] [INFO] testing 'SXSS [Payload] [<svg onload=alert(/StoredXssBySvgTag/)>]'
  
		存储型XSS插入成功的情况，并进行蓝色高亮显示，是否成功需手动到输出点分析查看XSS是否触发。
		[11:38:55] [INFO] testing 'SXSS [Payload] [<svg onload=prompt(/StoredXssBySvgTag/)>]' [RESULT] 'Saved successfully !' 


##Extend
总结的只是部分payload,可以根据自己的要求增加测试的payload。

各个参数的解析，可以根据具体情况扩展payload。

		<test>
		    <title>Reflected XSS [Payload] [<![CDATA['"><script>document.title="[random]";</script>]]>]</title>
		    <stype>T</stype>
		    <tech>3</tech>
		    <level>level1</level>
		    <request>
		        <payload><![CDATA['"><script>document.title="[random]";</script>]]></payload>
		    </request>
		    <response>
		        <grep></grep>
		    </response>
		    <details>
		        <versions>Linux,Windows</version>
		        <info>Reflected XSS</info>
		    </details>
		</test>

		title是漏洞的类型，利用的payload
		stype标签暂无意义，后续更新版本使用
		tech对于请求和验证的方式 
		  tech=1 普通请求，并匹配grep标签中的关键词，用于返回信息在网页中的请求，比如文件遍历漏洞。
		  tech=2 普通请求，仅仅判断这个请求是否提交成功，比如存储型XSS漏洞。
		  tech=3 模拟浏览器请求，并匹配grep标签中的关键词，比如反射型XSS漏洞检测。
		  tech=4 普通请求，主要是针对dnslog去检测的payload，比如命令执行漏洞检测。
		level标签是请求时参数是否带值
		request中的payload是我们要检测的标签
		response中grep标签根据tech标签填写相应关键词
		details标签中，主要是漏洞的版本和详细信息。

    
