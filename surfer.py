import os
import sys
import time
import random

import re
from scapy.all import *
import requests

G = '\033[92m'
Y = '\033[93m'
R = '\033[91m'
C = '\033[96m'
W = '\033[0m' #res

hosts = {}

def get_if():
    ifs = get_if_list()
    print(f"\n{C}Available interfaces:{W}")
    for i, f in enumerate(ifs):
        print(f"{i}) {f}")
    idx = int(input(f"\n{C}Select interface index: {W}"))
    return ifs[idx]

def pk_cb(pkt):
    if pkt.haslayer(ARP):
        ip, mac = pkt[ARP].psrc, pkt[ARP].hwsrc
        if ip != "0.0.0.0" and ip not in hosts:
            hosts[ip] = mac
            print(f"[{G}+{W}] ARP detected: {G}{ip}{W} ({Y}{mac}{W})")
            
    if pkt.haslayer(DHCP):
        mac = pkt[Ether].src
        req_ip = "Unknown"
        for opt in pkt[DHCP].options:
            if opt[0] == 'requested_addr': req_ip = opt[1]
        print(f"[!] DHCP DISCOVER from {Y}{mac}{W}. Requested: {C}{req_ip}{W}")

def ch_ip(iface, t_ip):
    net = ".".join(t_ip.split(".")[:-1])
    while True:
        new_ip = f"{net}.{random.randint(2, 254)}"
        if new_ip != t_ip and new_ip not in hosts: break
    print(f"[*] Adapting {C}{iface}{W} to {G}{new_ip}{W}...")
    os.system(f"sudo ifconfig {iface} {new_ip} netmask 255.255.255.0 up")
    time.sleep(1)

def h_grab(ip, port):
    try:
        r = requests.get(f"http://{ip}:{port}", timeout=2)
        title = re.search('<title>(.*?)</title>', r.text, re.I)
        title = title.group(1).strip() if title else "No Title"
        srv = r.headers.get('Server', 'Unknown')
        print(f"    {G}>> HTTP {port}:{W} [{Y}{srv}{W}] Title: {C}{title}{W}")
    except: pass

def a_scan(ip):
    print(f"[*] Scanning {G}{ip}{W}...")
    os.system(f"sudo nmap -Pn -sV -p 80,81,443,554,8000,8080 {ip} > scan.tmp")
    with open("scan.tmp", "r") as f:
        for line in f:
            if "/tcp" in line and "open" in line:
                p = line.split("/")[0]
                print(f"[{G}*{W}] Port {p} is OPEN")
                if p in ["80", "81", "8080", "8000"]: h_grab(ip, p)
    os.remove("scan.tmp")

if __name__ == "__main__":
    if os.getuid() != 0:
        print(f"{R}[-] Error: Run as root!{W}")
        sys.exit(1)

    iface = get_if()
    print(f"\n{C}=== NetSurfer Scan [IFACE: {iface}] ==={W}")
    print(f"[*] Sniffing 60s...")
    
    sniff(iface=iface, prn=pk_cb, store=0, timeout=60)

    if not hosts:
        print(f"{R}[-] No targets found.{W}")
        sys.exit(0)

    print(f"\n{C}--- Targets ---{W}")
    ips = list(hosts.keys())
    for i, ip in enumerate(ips):
        print(f"{i}) {G}{ip:<15}{W} | {Y}{hosts[ip]}{W}")

    idx = int(input(f"\n{C}Target index: {W}"))
    t_ip = ips[idx]

    ch_ip(iface, t_ip)
    a_scan(t_ip)