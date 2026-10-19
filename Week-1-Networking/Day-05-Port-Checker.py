# Week 1, Day 5 - Basic Python Port Checker
# Objective: Use the built-in Python socket library to check if Port 80 is open on a target server.

import socket

def check_port(target_host, target_port):
    print(f"[*] Attempting to connect to {target_host} on port {target_port}...")
    
    # Create a new socket object (IPv4, TCP)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Set a timeout so the script doesn't hang forever if the port is closed
    s.settimeout(2.0)
    
    try:
        # Attempt to connect to the target IP and Port
        result = s.connect_ex((target_host, target_port))
        
        # connect_ex returns 0 if the connection was successful (port is open)
        if result == 0:
            print(f"[+] SUCCESS: Port {target_port} is OPEN on {target_host}!")
        else:
            print(f"[-] FAILURE: Port {target_port} is CLOSED on {target_host}.")
            
    except Exception as e:
        print(f"[!] Error occurred: {e}")
        
    finally:
        # Always close the socket connection when finished
        s.close()

# Execute the function against the authorized Nmap testing server
check_port("scanme.nmap.org", 80)
