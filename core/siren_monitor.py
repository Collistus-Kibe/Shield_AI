# File: core/siren_monitor.py
import socket
import threading
import time
from .firewall_manager import block_ip_inbound # We will need to add this function

# Ports to trap. 21(FTP), 23(Telnet), 445(SMB-Fake), 8080(Proxy-Fake)
TRAP_PORTS = [21, 23, 8080, 1337]

class SirenMonitor:
    def __init__(self, log, digest_callback):
        self.log = log
        self.digest = digest_callback
        self.running = False
        self.listeners = []
        self.caught_ips = set()

    def _start_listener(self, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind(('0.0.0.0', port))
            s.listen(5)
            self.listeners.append(s)
            self.log.info(f"SIREN: Trap set on Port {port}")

            while self.running:
                try:
                    conn, addr = s.accept()
                    attacker_ip = addr[0]
                    
                    # Close connection immediately (Don't let them interact)
                    conn.close()
                    
                    if attacker_ip not in self.caught_ips:
                        self.caught_ips.add(attacker_ip)
                        self.log.critical(f"SIREN TRIGGERED: Intrusion attempt on Port {port} from {attacker_ip}")
                        self.digest("INTRUSION DETECTED", f"Device {attacker_ip} triggered Siren Trap (Port {port}). Blocking...")
                        
                        # ACTIVE DEFENSE: Block the IP
                        block_ip_inbound(attacker_ip, self.log)
                        
                except Exception:
                    pass # Socket closed or error
        except Exception as e:
            self.log.warning(f"SIREN: Could not bind port {port}. {e}")

    def start(self):
        self.running = True
        self.log.info("SIREN PROTOCOL: Engaging Network Honeypots...")
        for port in TRAP_PORTS:
            t = threading.Thread(target=self._start_listener, args=(port,), daemon=True)
            t.start()

    def stop(self):
        self.running = False
        for s in self.listeners:
            try: s.close()
            except: pass
        self.listeners.clear()