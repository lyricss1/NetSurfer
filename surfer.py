import os
import sys
import time
import random

from scapy.all import *

discovered_hosts = {}

def get_interfaces():
    interfaces = get_if_list()
    print("\nAvailable interfaces:")
    for i, iface in enumerate(interfaces):
        print(f"{i}) {iface}")
    choice = int(input("\nSelect interface index: "))
    return interfaces[choice]

def packet_callback(pkt):
    if pkt.haslayer(ARP):
        ip = pkt[ARP].psrc
        mac = pkt[ARP].hwsrc
        if ip != "0.0.0.0" and ip not in discovered_hosts:
            discovered_hosts[ip] = mac
            print(f"[+] ARP detected: {ip} ({mac})")
            
    if pkt.haslayer(DHCP):
        mac = pkt[Ether].src
        requested_ip = "Unknown"
        for option in pkt[DHCP].options:
            if option[0] == 'requested_addr':
                requested_ip = option[1]
        print(f"[!] DHCP DISCOVER from {mac}. Requested: {requested_ip}")

def ch_ip(interface, target_ip):
    subnet = ".".join(target_ip.split(".")[:-1])
    while True:
        random_host = random.randint(2, 254)
        new_ip = f"{subnet}.{random_host}"
        if new_ip != target_ip and new_ip not in discovered_hosts:
            break
            
    print(f"[*] Adapting interface {interface} to {new_ip}...")
    os.system(f"sudo ifconfig {interface} {new_ip} netmask 255.255.255.0 up")
    time.sleep(2)

def active_scan(ip):
    print(f"[*] Starting active scan on {ip}...")
    os.system(f"sudo nmap -Pn -sV -p 80,81,443,554,8000,8080 {ip}")

if __name__ == "__main__":
    if os.getuid() != 0:
        print("[-] Error: Run with sudo!")
        sys.exit(1)

    selected_iface = get_interfaces()

    print(f"\n=== NetSurfer Scan Mode [IFACE: {selected_iface}] ===")
    print("[*] Sniffing network for 60 seconds...")
    
    sniff(iface=selected_iface, prn=packet_callback, store=0, timeout=60)

    if not discovered_hosts:
        print("[-] No hosts found.")
        sys.exit(0)

    print("\n--- Target List ---")
    hosts_list = list(discovered_hosts.keys())
    for i, ip in enumerate(hosts_list):
        print(f"{i}) IP: {ip} | MAC: {discovered_hosts[ip]}")

    target_idx = int(input("\nSelect target index: "))
    target_ip = hosts_list[target_idx]

    ch_ip(selected_iface, target_ip)
    active_scan(target_ip)