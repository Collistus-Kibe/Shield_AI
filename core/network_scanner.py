# File: core/network_scanner.py
import socket
import ipaddress
import psutil
import subprocess
import re
from concurrent.futures import ThreadPoolExecutor

def get_local_ip_info(log):
    """
    Determines the local IP and the subnet prefix (e.g., '192.168.1.')
    """
    try:
        # Connect to a public DNS to determine which interface is active (doesn't send data)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        
        # Assume standard /24 subnet for home networks
        ip_parts = local_ip.split('.')
        base_subnet = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}."
        
        log.info(f"NETWORK PULSE: Local IP is {local_ip}. Scanning subnet {base_subnet}0/24")
        return base_subnet
    except Exception as e:
        log.error(f"NETWORK PULSE ERROR: Could not determine local IP. {e}")
        return None

def ping_host(ip):
    """
    Pings a single host. Returns (ip, True/False)
    """
    try:
        # -n 1 = one packet, -w 200 = 200ms timeout (Fast scan)
        output = subprocess.check_output(
            f"ping -n 1 -w 200 {ip}", 
            shell=True, 
            stderr=subprocess.PIPE
        ).decode()
        
        if "TTL=" in output:
            return ip, True
        return ip, False
    except Exception:
        return ip, False

def resolve_hostname(ip):
    """
    Tries to resolve the hostname of an active IP.
    """
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Unknown Device"

def get_arp_vendor(ip):
    """
    Reads the local ARP cache to find the MAC address/Vendor.
    """
    try:
        # Run arp -a to get the table
        output = subprocess.check_output(f"arp -a {ip}", shell=True).decode()
        # Regex to find MAC address
        mac_search = re.search(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})", output)
        if mac_search:
            return mac_search.group(0).upper()
    except Exception:
        pass
    return "Unknown MAC"

def scan_network(subnet_prefix, log):
    """
    Multi-threaded Native Pulse Scan.
    """
    if not subnet_prefix: return []
    
    log.info("NETWORK PULSE: Initiating hyper-threaded sweep...")
    active_devices = []
    
    # Create list of all 254 IPs
    all_ips = [f"{subnet_prefix}{i}" for i in range(1, 255)]
    
    # Use 50 threads to scan rapidly
    with ThreadPoolExecutor(max_workers=50) as executor:
        results = executor.map(ping_host, all_ips)
        
        for ip, is_up in results:
            if is_up:
                hostname = resolve_hostname(ip)
                mac_vendor = get_arp_vendor(ip)
                
                device = {
                    "ip": ip,
                    "hostname": hostname,
                    "status": "Online",
                    "vendor": mac_vendor # In a full version, we'd look up MAC OUI
                }
                active_devices.append(device)

    log.info(f"NETWORK PULSE: Sweep complete. Found {len(active_devices)} active neighbors.")
    return active_devices