from scapy.all import *
from scapy.sendrecv import sniff
from scapy.utils import wrpcap

dpkt = sniff(count = 100)  #这里是针对单网卡的机子，多网卡的可以在参数中指定网卡
wrpcap("demo.pcap", dpkt)

'''
def sui(pack):
	print(pack['IP'].src)  #输出抓包的IP中的src

	bian = pack

	if "Raw" in bian:
	print("[*] %s" % pack[IP].dst)

    print("[*] %s" % pack[TCP][Raw].load)

sniff(filter='tcp and dst post 80',prn=sui,store=0)  #回调函数
'''
