import requests
import json
import time
import socket

# CONFIGURATION
# In a real deployment, this would be your Cloud Server IP (e.g., http://142.93.x.x:5000)
# For now, we point it to your local server.
HIVE_SERVER_URL = "http://127.0.0.1:5000"
MY_NODE_ID = socket.gethostname() + "_" + str(socket.gethostbyname(socket.gethostname()))

class HiveLink:
    def __init__(self, log):
        self.log = log
        self.threat_cache = set()

    def sync_intelligence(self):
        """Downloads the latest threats from the Swarm."""
        try:
            url = f"{HIVE_SERVER_URL}/intelligence"
            response = requests.get(url, timeout=3)
            
            if response.status_code == 200:
                data = response.json()
                new_threats = set(data.get('threats', []))
                
                # Calculate how many NEW threats we just learned
                count = len(new_threats - self.threat_cache)
                self.threat_cache.update(new_threats)
                
                if count > 0:
                    self.log.info(f"✅ HIVE SYNC: Learned {count} new threat signatures from the Swarm.")
                return list(self.threat_cache)
            
        except requests.exceptions.ConnectionError:
            self.log.warning("⚠️ HIVE LINK: Cannot reach Server. Operating in Offline Mode.")
        except Exception as e:
            self.log.error(f"HIVE ERROR: {e}")
        
        return list(self.threat_cache)

    def report_threat(self, threat_type, value):
        """
        Reports a neutralized threat to the Swarm so others stay safe.
        threat_type: 'ip' or 'hash'
        value: The actual IP address or file hash
        """
        payload = {
            "node_id": MY_NODE_ID,
            "type": threat_type,
            "value": value
        }
        
        try:
            url = f"{HIVE_SERVER_URL}/report_threat"
            # We use a short timeout because we don't want to freeze the antivirus while uploading
            requests.post(url, json=payload, timeout=2)
            self.log.info(f"🚀 SWARM BROADCAST: Reported {threat_type} ({value}) to Hive Mind.")
            return True
        except Exception:
            # Silently fail if server is down; protection comes first
            return False