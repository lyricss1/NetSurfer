import os
import sys
import time
import random

import re
from scapy.all import *
import requests
from requests.auth import HTTPBasicAuth, HTTPDigestAuth

#clr
G, Y, R, C, W = '\033[92m', '\033[93m', '\033[91m', '\033[96m', '\033[0m'

hosts = {}

def get_if():
    ifs = get_if_list()
    print(f"\n{C}Available interfaces:{W}")
    for i, f in enumerate(ifs): print(f"{i}) {f}")
    return ifs[int(input(f"\n{C}Select interface index: {W}"))]

def pk_cb(pkt):
    if pkt.haslayer(ARP):
        ip, mac = pkt[ARP].psrc, pkt[ARP].hwsrc
        if ip != "0.0.0.0" and ip not in hosts:
            hosts[ip] = mac
            print(f"[{G}+{W}] ARP detected: {G}{ip}{W} ({Y}{mac}{W})")
    if pkt.haslayer(DHCP):
        mac, req_ip = pkt[Ether].src, "Unknown"
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
    url = f"http://{ip}:{port}"
    creds = [('admin', 'admin'), ('admin', '12345'), ('root', ''), ('admin', 'password')]
    try:
        r = requests.get(url, timeout=3)
        if r.status_code == 401:
            for u, p in creds:
                for am in [HTTPBasicAuth, HTTPDigestAuth]:
                    try:
                        ra = requests.get(url, auth=am(u, p), timeout=2)
                        if ra.status_code == 200:
                            r = ra
                            print(f"    {G}[!] Auth Bypass: {u}:{p} ({am.__name__}){W}")
                            break
                    except: continue
                if r.status_code == 200: break
        t = re.search('<title>(.*?)</title>', r.text, re.I)
        t = t.group(1).strip() if t else "No Title"
        srv = r.headers.get('Server', 'Unknown')
        print(f"    {G}>> HTTP {port}:{W} [{Y}{srv}{W}] Title: {C}{t}{W}")
    except: print(f"    {R}>> HTTP {port}: Request failed{W}")

def a_scan(ip):
    print(f"\n[*] Probing {G}{ip}{W} ports...")
    ports = [80, 81, 443, 554, 8000, 8080]
    found = []
    for p in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            if s.connect_ex((ip, p)) == 0:
                print(f"[{G}*{W}] Port {G}{p}{W} is OPEN")
                found.append(p)
    
    for p in found:
        if p in [80, 81, 8000, 8080]: h_grab(ip, p)

#def snf(iface):
    #custom time

if __name__ == "__main__":
    if os.getuid() != 0:
        print(f"{R}[-] Run as root!{W}"); sys.exit(1)

    iface = get_if()
    print(f"\n{C}=== NetSurfer Scan [IFACE: {iface}] ==={W}")
    print(f"[*] Sniffing 60s...")
    sniff(iface=iface, prn=pk_cb, store=0, timeout=60)

    while True:
        if not hosts:
            print(f"{R}[-] No targets.{W}"); break

        print(f"\n{C}--- Targets ---{W}")
        ips = list(hosts.keys())
        for i, ip in enumerate(ips): print(f"{i}) {G}{ip:<15}{W} | {Y}{hosts[ip]}{W}")
        print(f"{len(ips)}) {R}Rescan Network{W}")
        print(f"{len(ips)+1}) {R}Exit{W}")

        idx = int(input(f"\n{C}Selection: {W}"))
        
        if idx == len(ips):
            print(f"[*] Resniffing..."); sniff(iface=iface, prn=pk_cb, store=0, timeout=30)
            continue
        if idx == len(ips)+1: break

        t_ip = ips[idx]
        ch_ip(iface, t_ip)
        a_scan(t_ip)
        input(f"\n{Y}Press Enter to return to target list...{W}")