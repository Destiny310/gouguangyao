from scapy.all import *
import scapy
import http
from scapy.utils import PcapWriter
import time
import queue
import pymysql
import re
import datetime


works = queue.Queue()				#队列（正常的数据）
xinbao = queue.Queue() 				#队列（异常危险的数据）
with open('C:/Users/admin/Desktop/lkd/text.txt','r') as f:     #调用规则库
	txt = f.read().split('\n') 		#指定分隔符对字符串进行切片


def packet_callback(mail_packet):
	#print(mail_packet['TCP'])
	if "Raw" in mail_packet['TCP']:	#进入抓取数据包的Raw
		
		s= str(mail_packet['TCP']['Raw'].load).split('\t\n')[0].split()[1]    #分割字符获取URL得到目录		
		Time=time.strftime('%Y,%m,%d %H:%M:%S',time.localtime(time.time()))   #时间格式化 

		for xxx in txt:
			if xxx in s:
				print('该语句中含有危险字符，请自重 =3= ')
				d = {
					 'ip':mail_packet['IP'].src,
                    'url':s,
                    'time': Time
				}
				xinbao.put(d)
				print("[*] %s" % mail_packet['IP'].src)   #访问者IP
				print("[*]%s" % s)		 #打印危险URL
				print('TTime:',Time)     #打印出包的抓取时间
				break


def write():            #写入数据库
    mydb = pymysql.connect(       #打开数据库连接
        # host="localhost",       # 数据库主机地址
        user="root",    		# 数据库用户名
        passwd="budanchun",   # 数据库密码
        database="sql"
    )
    mycursor = mydb.cursor()        #创建一个游标对象
    sql = "INSERT INTO sites(IP,Data,url) values ('%s','%s','%s')"   #创建数据库表名
    while 1:
        a = xinbao.get()          #上传判断危险字符
        #print(type(a['url']))
        url = re.sub("'",r'\'',a['url'])  #转义单引号
        sqli = sql %(a['ip'],a['time'],url)
        #print(sqli)
        mycursor.execute(sqli)      #使用execute()执行SQL查询
        mydb.commit()           	#数据表内容有更新，必须使用此语句


import threading  #线程
print('预备备、开始')
# for i in range(10):
#     thread = threading.Thread(target=packet_callback)
#     thread.start()
thread = threading.Thread(target=write)   #单线程 调用write
thread.start()


sniff(filter="tcp and dst port 80 and dst host 10.60.18.33",prn=packet_callback)