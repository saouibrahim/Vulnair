
#need lirbaries that can write bash commands

import os
import sys
import subprocess
import re
import time
import json
import requests
import socket
import threading
import queue
import logging
import logging.handlers
import argparse
import ipaddress
import platform

# Need to use the nmap library
try:
    import nmap
except ImportError:
    print("nmap library not found, please install it using 'pip install python-nmap'")
    sys.exit(1)

# Before starting the scan, we need the user to precise the type of the target, a netwtork, a ip or a domain, or a file containing a list of targets

def get_target_type(target):
    if os.path.isfile(target):
        return 'file'
    elif '/' in target:
        return 'network'
    elif '.' in target:
        return 'domain'
    else:
        return 'ip'
    
# Use of the socket library to get the ip address of a domain

def get_ip_from_domain(domain):
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except:
        return None

def scan_domain(domain, ports):
    ip = get_ip_from_domain(domain)
    if ip:
        nm = nmap.PortScanner()
        nm.scan(hosts=ip, arguments='-sV -p ' + ports)
        return nm[ip]
    else:
        return None

    
# Use of the ipaddress library to check if the ip address is valid

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except:
        return False

def scan_target(target, ports):
    nm = nmap.PortScanner()
    scan_results = []
    for target in target:
        nm.scan(hosts=target, arguments='-sV -p ' + ports)
        scan_results.append(nm[target])
    return scan_results


# Use of the ipaddress library to check if the network is valid

def is_valid_network(network):
    try:
        ipaddress.ip_network(network)
        return True
    except:
        return False

def scan_network(network, ports):
    nm = nmap.PortScanner()
    nm.scan(hosts=network, arguments='-sP -n')
    hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
    return hosts_list




# if the target is a file, we need to read the file and extract the targets

def get_targets_from_file(file):
    with open(file, 'r') as f:
        #add the targets to a list of targets to scan
        targets = [x.strip() for x in f.readlines()]
        
    return targets

def scan_targets(targets, ports):
    nm = nmap.PortScanner()
    scan_results = []
    for target in targets:
        nm.scan(hosts=target, arguments='-sV -p ' + ports)
        scan_results.append(nm[target])
    return scan_results


# Now we know how to identify the target, we can start the scan

def scan(target, ports, output_file):
    # Check the type of the target
    target_type = get_target_type(target)

    # If the target is a domain, we need to get the ip address
    if target_type == 'domain':
        
        #first is domain valid
        if not is_valid_domain(target):
            print(f"{target} is not a valid domain")
            return
        
        
    
    # If the target is a single ip address

    if target_type == 'ip':
        if not is_valid_ip(target):
            print(f"{target} is not a valid ip address")
            return
        targets = [target]

    # If the target is a network

    if target_type == 'network':
        if not is_valid_network(target):
            print(f"{target} is not a valid network")
            return
        targets = scan_network(target, ports)
    
    # If the target is a file

    if target_type == 'file':
        targets = get_targets_from_file(target)

    # Start the scan

    #the results of the scan will be stored in a file for the AI to analyze it

    
    

    



