#!/usr/bin/env python
from scapy.all import *
import sys
import argparse
def obt_argumentos():
    parser=argparse.ArgumentParser()
    parser.add_argument("-t","--target",dest="target",help="ESpecifica el objetivo <192.168.1.x> o la red <192.168.1.0/24>")
    return parser.parse_args()
argumentos=obt_argumentos()
obj=argumentos.target
if not obj:
    print "\n Especifica una ip o red para identificar las MAC o introduce: <"+sys.argv[0]+ " -h>"
    sys.exit(1)
conf.verb=0
ans,unans=srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=obj),timeout=2)
print "\n\tMAC \t  \tIP"

for env,res in ans:
    print res.sprintf("%Ether.src% --> %ARP.psrc%")
