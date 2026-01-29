import os
import sys
import time
from scapy.all import *

discovered_hosts = {}

def packet_callback(pkt):
    if pkt.haslayer(ARP):
        ip = pkt[ARP].psrc
        mac = pkt[ARP].hwsrc
        if ip != "0.0.0.0" and ip not in discovered_hosts:
            discovered_hosts[ip] = mac
            print(f"[+] ARP: {ip} ({mac})")
            
    if pkt.haslayer(DHCP):
        mac = pkt[Ether].src
        requested_ip = "Unknown"
        for option in pkt[DHCP].options:
            if option[0] == 'requested_addr':
                requested_ip = option[1]
        print(f"[!] DHCP DISCOVER from {mac}. needs IP: {requested_ip}")

def change_my_ip(target_ip):
    subnet = ".".join(target_ip.split(".")[:-1])
    my_new_ip = f"{subnet}.222"
    print(f"[*] Changing IP on {my_new_ip}...")
    os.system(f"sudo ifconfig eth0 {my_new_ip} netmask 255.255.255.0 up")
    time.sleep(2)

def active_scan(ip):
    print(f"[*] Active scanning {ip}...")
    os.system(f"sudo nmap -Pn -p 80,81,443,554,8000,8080 {ip}")

if __name__ == "__main__":
    if os.getuid() != 0:
        print("[-] Error: You need sudo!")
        sys.exit(1)

    print("=== NetSurfer Predator Mode ===")
    print("[*] Sniffing 60sec (ARP/DHCP sniffing)...")
    
    sniff(iface="eth0", prn=packet_callback, store=0, timeout=60)

    if not discovered_hosts:
        print("[-] No one here")
        sys.exit(0)

    print("\n--- List of targets ---")
    hosts_list = list(discovered_hosts.keys())
    for i, ip in enumerate(hosts_list):
        print(f"{i}) IP: {ip} | MAC: {discovered_hosts[ip]}")

    choice = int(input("\nSelect the target number to attack: "))
    target_ip = hosts_list[choice]

    change_my_ip(target_ip)
    active_scan(target_ip)
