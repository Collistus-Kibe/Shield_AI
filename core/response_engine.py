import time
import os
import shutil
import psutil

# REMOVED: from .evasion_manager import activate_evasion (This caused the crash)

class ResponseEngine:
    def __init__(self, log, gui_callback):
        self.log = log
        self.gui_callback = gui_callback

    def execute_playbook(self, threat_type, context):
        """
        Executes a pre-defined response based on the threat type.
        """
        self.log.info(f"⚡ RESPONSE ENGINE: Activating playbook for {threat_type}")
        
        if threat_type == "BAD_DOWNLOAD":
            self._handle_bad_download(context)
        elif threat_type == "RANSOMWARE":
            self._handle_ransomware(context)
        elif threat_type == "network_intrusion":
            self._handle_network_intrusion(context)

    def _handle_bad_download(self, context):
        file_path = context.get('path')
        score = context.get('score')
        
        # 1. Notify User
        self.gui_callback("THREAT BLOCKED", f"Malicious file detected (Score: {score})")
        
        # 2. Kill the process if it's running
        try:
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                if proc.info['exe'] == file_path:
                    proc.kill()
                    self.log.info(f"RESPONSE: Killed process {proc.info['name']}")
        except Exception:
            pass

        # 3. Quarantine (Move to safe vault)
        # Note: Actual quarantine logic is handled by 'actions.py', 
        # but we can force a delete if needed here.
        if os.path.exists(file_path):
            try:
                # Rename to .virus to stop execution
                new_name = file_path + ".virus"
                os.rename(file_path, new_name)
                self.log.info(f"RESPONSE: File neutralized -> {new_name}")
            except Exception as e:
                self.log.error(f"RESPONSE FAILED: {e}")

    def _handle_ransomware(self, context):
        self.gui_callback("CRITICAL ALERT", "Ransomware behavior detected!")
        # In a real scenario, this would trigger a system-wide lock
        # For now, we rely on ShieldCore to kill the specific PID
        pass

    def _handle_network_intrusion(self, context):
        ip = context.get('ip')
        self.gui_callback("NETWORK BLOCKED", f"Intrusion attempt from {ip}")
        # Firewall block logic is handled by ShieldCore