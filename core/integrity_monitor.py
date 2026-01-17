# File: core/integrity_monitor.py
import os
import hashlib
import time

# Files to protect (The "DNA" of the system)
CRITICAL_FILES = {
    "HOSTS": r"C:\Windows\System32\drivers\etc\hosts",
    "SYSTEM_INI": r"C:\Windows\system.ini"
}

class IntegrityMonitor:
    def __init__(self, log):
        self.log = log
        self.baseline_hashes = {}
        self._create_baseline()

    def _get_hash(self, path):
        try:
            if not os.path.exists(path): return None
            sha256 = hashlib.sha256()
            with open(path, 'rb') as f:
                while chunk := f.read(4096): sha256.update(chunk)
            return sha256.hexdigest()
        except Exception: return None

    def _create_baseline(self):
        self.log.info("DNA SENTINEL: Creating integrity baseline...")
        for name, path in CRITICAL_FILES.items():
            h = self._get_hash(path)
            if h: self.baseline_hashes[name] = h
            else: self.log.warning(f"DNA: Could not read {name} at {path}")

    def check_integrity(self):
        """
        Checks if critical files have changed since baseline.
        Returns a list of alerts.
        """
        alerts = []
        for name, path in CRITICAL_FILES.items():
            current_hash = self._get_hash(path)
            baseline_hash = self.baseline_hashes.get(name)
            
            if current_hash and baseline_hash and current_hash != baseline_hash:
                alerts.append(f"CRITICAL: System DNA Modified! ({name})")
                # Auto-update baseline to prevent infinite spam, 
                # effectively "acknowledging" the change after alert.
                self.baseline_hashes[name] = current_hash
        
        return alerts