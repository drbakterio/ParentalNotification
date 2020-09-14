from os import system
from optparse import OptionParser
from datetime import datetime
import tldextract
import socket
import telebot

domainsCache = {}
TOKEN = 'INSERT TELEGRAM BOT TOKEN HERE'

def check(file_name, string_to_search):
    with open(file_name, 'r') as read_obj:
        for line in read_obj:
            if string_to_search in line:
                return True
    return False

def process(pkt):
    ip46 = IPv6 if IPv6 in pkt else IP
    if pkt.haslayer(DNSQR) and UDP in pkt and pkt[UDP].sport == 53 and ip46 in pkt:
		# pkt[IP].dst == IP source of the DNS request
		# pkt[IP].src == IP of the DNS server
		# pkt[DNS].qd.qname == DNS name
        domainURI = pkt[DNS].qd.qname.decode("utf-8") if pkt[DNS].qd != None else "?"
        extracted = tldextract.extract(domainURI)
        domain = "{}.{}".format(extracted.domain, extracted.suffix)
        now = datetime.now()
        if not domain in domainsCache:
            domainsCache[domain] = 'adult' if check('ad_cnt.txt', domain) else 'clean'
        if domainsCache[domain] == 'adult':
            tb.send_message('CHAT ID HERE', socket.gethostbyaddr(pkt[IP].dst)[0] + '[' + pkt[IP].dst + ']' + ' - ' + now.strftime("%H:%M:%S") + '\n' + domain)
            # print(socket.gethostbyaddr(pkt[IP].dst)[0] + '[' + pkt[IP].dst + ']' + ' - ' + now.strftime("%H:%M:%S") + '\n' + domain)
            # print(domainsCache)

if __name__ == "__main__":
    try:
        from scapy.all import sniff
        from scapy.all import ARP
        from scapy.all import DNSQR
        from scapy.all import UDP
        from scapy.all import IP
        from scapy.all import IPv6
        from scapy.all import DNS
    except ImportError:
        from sys import exit
        exit("\033[31mYou need to setup python3-scapy\033[0m\nsudo apt install python3-scapy")

    tb = telebot.TeleBot(TOKEN)
    sniff(filter='udp port 53', store=0, prn=process)
