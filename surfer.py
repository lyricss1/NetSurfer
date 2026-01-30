import os
import sys
import time
import random

import re
import socket
from scapy.all import *
import requests
from requests.auth import HTTPBasicAuth, HTTPDigestAuth

#clr
G, Y, R, C, W = '\033[92m', '\033[93m', '\033[91m', '\033[96m', '\033[0m'
hosts = {}


#port
def get_p():
    lvls = {"B": [80, 81, 8080, 8000, 554, 21, 22, 23, 53, 139, 445, 1900, 5000, 5353, 8443, 1024, 32400, 49152, 54321, 3389, 3306, 5900, 8081], "E": [110, 143, 993, 995, 2049, 3000, 5432, 5672, 6379, 9000, 9200, 27017]}
    if os.path.exists("ports.cfg"):
        with open("ports.cfg", "r") as f:
            for line in f:
                line = line.split('#')[0].strip()
                if not line: continue
                if line.startswith("BASE:"):
                    lvls["B"] = [int(p.strip()) for p in line.split(":")[1].split(",") if p.strip().isdigit()]
                if line.startswith("EXT:"):
                    lvls["E"] = [int(p.strip()) for p in line.split(":")[1].split(",") if p.strip().isdigit()]
    return lvls

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
    except: pass

def do_scan(ip, p_list):
    print(f"\n[*] Probing {G}{len(p_list)}{W} ports on {G}{ip}{W}...")
    found = []
    for p in p_list:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.3)
            if s.connect_ex((ip, p)) == 0:
                print(f"[{G}*{W}] Port {G}{p}{W} is OPEN")
                found.append(p)
    for p in found:
        if p in [80, 81, 8000, 8080, 8443, 8081]: h_grab(ip, p)
    if not found: print(f"{Y}[!] No open ports found.{W}")

def a_scan(ip):
    p_data = get_p()
    do_scan(ip, p_data["B"])
    
    while True:
        print(f"\n{C}Next actions for {G}{ip}:{W}")
        print(f"1) Extended Scan ({len(p_data['E'])} more ports)")
        print(f"2) Custom Scan")
        print(f"0) Back to targets")
        
        m = input(f"\n{C}Mode: {W}")
        if m == "0": break
        if m == "1": do_scan(ip, p_data["E"])
        elif m == "2":
            c_ports = [int(x.strip()) for x in input("Enter ports (e.g. 21,22): ").split(",") if x.strip().isdigit()]
            do_scan(ip, c_ports)

def start_sniff(iface):
    v = input(f"\n{C}Sniff time (Enter for 60s): {W}")
    sec = int(v) if v.strip().isdigit() else 60
    print(f"[*] Sniffing {Y}{sec}s{W} on {C}{iface}{W}...")
    sniff(iface=iface, prn=pk_cb, store=0, timeout=sec)

if __name__ == "__main__":
    if os.getuid() != 0:
        print(f"{R}[-] Run as root!{W}"); sys.exit(1)

    iface = get_if()
    print(f"\n{C}=== NetSurfer Scan [IFACE: {iface}] ==={W}")
    start_sniff(iface)

    while True:
        if not hosts:
            print(f"{R}[-] No targets detected.{W}")
            start_sniff(iface)
            if not hosts: break

        print(f"\n{C}--- Targets ---{W}")
        ips = list(hosts.keys())
        for i, ip in enumerate(ips): print(f"{i}) {G}{ip:<15}{W} | {Y}{hosts[ip]}{W}")
        print(f"{len(ips)}) {R}Rescan Network{W}")
        print(f"{len(ips)+1}) {R}Exit{W}")

        idx = input(f"\n{C}Selection: {W}")
        if not idx.isdigit(): continue
        idx = int(idx)
        
        if idx == len(ips):
            start_sniff(iface); continue
        if idx == len(ips)+1: break

        t_ip = ips[idx]
        ch_ip(iface, t_ip)
        a_scan(t_ip)