import os
import sys
import time
import socket
import logging
import array
import requests
import json
import httplib

from ryu.lib import alert
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
# 注意和snort指定的unixsocket通信的路径是一样的
SOCKFILE = "/tmp/temp1/snort_alert"
BUFSIZE = 65863
# 控制器IP
CONTROLLER_IP = '127.0.0.1'
# 控制器RESTful API访问的端口以及URL
CONTROLLER_PORT="8080"
CONTROLLER_URL="http://"+CONTROLLER_IP+":"+CONTROLLER_PORT+"/wm/snort/alerts/json"
# 控制器socket通信的端口
CONTROLLER_PORT = 51234

class SnortListener():

    def __init__(self):
        self.unsock = None
        self.nwsock = None
    def packet_print(self, pkt,alert):
	s=''

        pkt = packet.Packet(array.array('B', pkt))
        eth = pkt.get_protocol(ethernet.ethernet)
        _ipv4 = pkt.get_protocol(ipv4.ipv4)
        _icmp = pkt.get_protocol(icmp.icmp)
        _tcp = pkt.get_protocol(ipv4.tcp.tcp)
        _udp = pkt.get_protocol(ipv4.udp.udp)
        if _tcp:
            s= "%r" %_tcp
        if _udp:
            s+="%r" %_udp
        if _icmp:
            s+= "%r" %_icmp
        if _ipv4:
            s+= "%r" %_ipv4
        if eth:
            s+= "%r" % eth
        s={'alert':alert,'src-ip':_ipv4.src,'dst-ip':_ipv4.dst,'src-mac':eth.src,'dst-mac':eth.dst}
	return s

    def start_send(self):
        '''Open a client on Network Socket'''
        self.nwsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.nwsock.connect((CONTROLLER_IP, CONTROLLER_PORT))
        except Exception, e:
            logger.info("Network socket connection error: %s" % e)
            sys.exit(1)

    def start_recv(self):
        if os.path.exists(SOCKFILE):
            os.unlink(SOCKFILE)

        self.unsock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.unsock.bind(SOCKFILE)
        logger.info("Unix Domain Socket listening...")
        self.recv_loop()

    def recv_loop(self):

        self.start_send()#establish network socket
        while True:
            data = self.unsock.recv(BUFSIZE)
            time.sleep(0.5)
            if data:
                logger.debug("Send {0} bytes of data.".format
                             (sys.getsizeof(data)))
                self.tcp_send(data)
            else:
                pass

    def send_json(self,data):
	s=json.dumps(data)
	r=requests.post(CONTROLLER_URL,data=s)

    def tcp_send(self, data):
        data2 = data[:BUFSIZE]
        msg = alert.AlertPkt.parser(data2)
        s1= '%s' % ''.join(msg.alertmsg)
        s2=self.packet_print(msg.pkt,s1)
        self.send_json(s2)# 用RESTful API发送警告
	#self.nwsock.sendall(json.dumps(s2)+'\n') # 用socket发送警告
        logger.info("Send the alert messages to floodlight.")


if __name__ == '__main__':
    server = SnortListener()
    server.start_recv()
