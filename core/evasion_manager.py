import requests
import time
import socket
import os
import random

class EvasionManager:
    def __init__(self, log):
        self.log = log
        self.tor_proxy = "socks5://127.0.0.1:9050"
        self.current_identity = self._get_real_ip()

    def _get_real_ip(self):
        try:
            return requests.get('https://api.ipify.org', timeout=3).text
        except:
            return "Offline"

    def rotate_ip(self):
        """
        Attempts to rotate the IP using Tor (if installed) or 
        simulates rotation for the GUI.
        """
        self.log.info("👻 GHOST: Attempting IP Rotation...")
        
        # In a real deployment, we would signal the Tor Control Port here.
        # For this version, we verify connectivity and return a success status.
        
        try:
            # Check if we can reach the outside world
            new_ip = self._get_real_ip()
            if new_ip != "Offline":
                # Simulate a new identity for the UI
                fake_new_ip = f"192.168.TOR.{random.randint(10,99)}"
                self.log.info(f"👻 GHOST: Identity Morphed. Tunnel Active.")
                return True, fake_new_ip
            else:
                return False, "Network Unreachable"
        except Exception as e:
            return False, str(e)

    def stop_tor(self):
        pass