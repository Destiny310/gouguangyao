from scapy.all import *
import scapy
import http
from scapy.utils import PcapWriter
import time
import queue
import pymysql
import re
import datetime


works = queue.Queue()   #队列（正常的数据）
caijixin = queue.Queue()     #队列（异常危险的数据）
with open('C:/Users/admin/Desktop/lkd/text.txt','r') as f:   #调用规则库
    txt = f.read().split('\n')  #指定分隔符对字符串进行切片


def packet_callback(mail_packet):
    #print(pack['IP'].src)  #输出抓包的IP中的src
    # while 1:
        # mail_packet = works.get()
    print(mail_packet['TCP'])
    # if mail_packet['TCP'].dport =='443'
    if "Raw" in mail_packet['TCP']:       #进入抓取数据包的Raw
        print(mail_packet['TCP']['Raw'].load, '-'*10)
        print("[*] %s" % mail_packet['IP'].src)
        # print("[*] %s" % mail_packet[IP].src)
        #IP=packet[IP].dst
        #print("[*] %s" % packet[TCP][Raw].load)
        Time=time.strftime('%Y,%m,%d %H:%M:%S',time.localtime(time.time()))   #时间格式化         
        # a=re.findall(r'Referer:(.*?)\\r\\n',str(packet[TCP][Raw].load)) 
        s = str(mail_packet['TCP']['Raw'].load).split('\r\n')[0].split()[1]  #分割字符获取URL得到目录
        print("[*] %s" % s)  #打印字符串
        print('Timestamp: ',Time) #打印出包的抓取时间
        #print(a)
        #a=re.findall(r'Referer:(.*)\\r\\nConnection',str(packet[TCP][Raw].load))
        for i in txt:
        #print(txt) 
        # #print(i)
            if i in s.lower():
                print('该语句中存在危险字符')
                d = {
                    'ip':mail_packet['IP'].src,
                    'url':s,
                    'time': Time
                    # str(datetime.datetime.utcfromtimestamp(Time))
                }
                caijixin.put(d)
                break

# def add_work(pack):
#     print('add_work')
#     print(pack['IP'].src)
#     works.put(pack)

def write():            #写入数据库
    mydb = pymysql.connect(       #打开数据库连接
        # host="localhost",       # 数据库主机地址
        user="root",    # 数据库用户名
        passwd="budanchun",   # 数据库密码
        database="sql"
    )
    mycursor = mydb.cursor()        #创建一个游标对象
    sql = "INSERT INTO sites(IP,Data,url) values ('%s','%s','%s')"   #创建数据库表名
    while 1:
        a = caijixin.get()          #上传判断危险字符
        print(type(a['url']))
        url = re.sub("'",r'\'',a['url'])  #转义单引号
        sqli = sql %(a['ip'],a['time'],url)
        print(sqli)
        mycursor.execute(sqli)      #使用execute()执行SQL查询
        mydb.commit()           #数据表内容有更新，必须使用此语句

import threading  #线程
print(1)
# for i in range(10):
#     thread = threading.Thread(target=packet_callback)
#     thread.start()
thread = threading.Thread(target=write)   #单线程 调用write
thread.start()

sniff(filter="tcp and dst port 80 and dst host 10.60.18.33",prn=packet_callback,store=0)
                #抓取从80端口访问本机的数据                            add_work