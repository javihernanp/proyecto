#!/usr/bin/env python
from scapy.all import *
import sys
import time
import os
cont=0
#obtenemos las MAC de los paquetes ARP que hemos enviado
def obtener_mac(ip):
    pkt = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip)
    resultado =srp(pkt , timeout=3, verbose= False)[0]
    return resultado[0][1].hwsrc

def main(paquete):
    if paquete.haslayer(ARP):
        if paquete[ARP].op == 2:
            try:
                real_mac = obtener_mac(paquete[ARP].psrc)
                fake_mac = paquete[ARP].hwsrc
                if real_mac != fake_mac:
                    print '\n Te estan atacando, REAL-MAC '+real_mac.upper()+ ',FAKE_MAC: '+fake_mac.upper()
                    time.sleep(2)
                    comprobacion()
            except IndexError:
                pass
def comprobacion():
    global cont
    cont+=1
    if cont == 5:
        print '\n Revisa tu seguridad y vuelve a ejecutar este script'
        opcion=raw_input('Continuar prueba ("si" para coninuar"): ')
        if opcion.lower() == 'si':
            cont=0
            sniff(iface=interface, prn=main, store=0)
            print '\n No se han encontado evidencias de ARPpoison'
            sys.exit(0)
        else:
            sys.exit(0)
interface=raw_input('Introduce la interfaz: ')
print '\n Comenzando sniffing'
sniff(iface=interface, prn=main, store=0)
print '\n No se han encontado evidencias de ARPpoison'
