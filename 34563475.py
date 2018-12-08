from scapy.all import *
import scapy
import http
from scapy.utils import PcapWriter
import time
import mysql.connector
#http://www.lysxjr.org/index.php?m=xdcms&c=login&f=fcrmzf
with open('C:/Users/admin/Desktop/lkd/text.txt','r') as f:
    txt = f.read().split('\n')
def packet_callback(packet):

        Data=time.strftime('%Y,%m,%d %H:%M:%S',time.localtime(time.time()))
        dstIP=packet[IP].dst
        mail_packet = packet
        if "Raw" in mail_packet:
       	  #print(str(packet[TCP][Raw].load))
          if 'GET' in str(packet[TCP][Raw].load):
            print(re.findall(r'Cookie:(.*?)\\r\\nUpgrade-Insecure-Requests',str(packet[TCP][Raw].load),flags=re.I))
            cookie=re.findall(r'Cookie:(.*?)\\r\\nUpgrade-Insecure-Requests',str(packet[TCP][Raw].load),flags=re.I)
            #cookie=str(cookie)
            # cookie=cookie.split(';')

            for i in txt:
              if i in str(cookie):
                print('危险----------------------')
                break
            #print(re.findall(r'GET(.*?)HTTP',str(packet[TCP][Raw].load)))
            url=re.findall(r'GET(.*?)HTTP',str(packet[TCP][Raw].load),flags=re.I)
            if 'php' in str(url):
              print(str(url))
              for i in txt:
              #print(i)
                if i in str(url):
                  print('危险---------------------------------')
                  break

          if 'POST' in str(packet[TCP][Raw].load):
              print(re.findall(r'Upgrade-Insecure-Requests: 1\\r\\n\\r\\n(.*)',str(packet[TCP][Raw].load),flags=re.I))
              post=re.findall(r'Upgrade-Insecure-Requests: 1\\r\\n\\r\\n(.*)',str(packet[TCP][Raw].load),flags=re.I)
              post=str(post)
              post=post.split('&')
              print(post[0].split('=')[-1])
              print(post[1].split('=')[-1])
              for i in txt:
                if i in str(post):
                  print('危险--------------------------------')
                  break
              print(re.findall(r'Cookie:(.*?)\\r\\n',str(packet[TCP][Raw].load),flags=re.I))
              cookie=re.findall(r'Cookie:(.*?)\\r\\n',str(packet[TCP][Raw].load),flags=re.I)
              cookie=str(cookie)
              cookie=cookie.split(';')
              print(cookie)
              print(cookie[0].split('=')[1])
              print(cookie[1].split('=')[1])
              for i in txt:
               #print(i)
               if i in str(cookie):
                print('危险----------------------------------')
                break
              #return Data,dstIP



        #     print(re.findall(r'Cookie:(.*?);',str(packet[TCP][Raw].load),flags=re.I))
        #     cookie=re.findall(r'Cookie:(.*?);',str(packet[TCP][Raw].load),flags=re.I)
        #     #print(re.findall(r'Referer:(.*?)\\r\\n',str(packet[TCP][Raw].load),flags=re.I))
        #     #cookie=re.findall(r'Cookie:(.*?);',str(packet[TCP][Raw].load),flags=re.I)


        #     for i in txt:
        #       #print(i)
        #       if i in str(url):
        #         print('危险---------------------------------')
        #       if i in str(cookie):
        #         print('危险--------------------------------')
        #         break

  
sniff(filter="tcp and dst port 80 ",prn=packet_callback,store=0)

def savemysql():
  mydb = mysql.connector.connect(
    host="localhost",       # 数据库主机地址
    user="root",    # 数据库用户名
    passwd="root",   # 数据库密码
    database="sql"
  )
  Data.dstIP = packet_callback()
  mycursor = mydb.cursor()
    #mycursor.execute("CREATE TABLE sites (id INT AUTO_INCREMENT PRIMARY KEY, IP VARCHAR(255), Data VARCHAR(255), url VARCHAR(255))")
  sql = "INSERT INTO sites(IP,Data,url) values (%s,%s,%s)"
  val= [
  ("22","Data","url")
  ]
  mycursor.executemany(sql, val)
  mydb.commit()