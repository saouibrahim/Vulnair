
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

# Use of nmap to scan the network

def scan_network(network, ports):
    nm = nmap.PortScanner()
    nm.scan(hosts=network, arguments='-sP -n')
    hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
    return hosts_list
