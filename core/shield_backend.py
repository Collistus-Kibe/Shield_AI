import time
import os
import psutil
import threading
import queue
import subprocess
import yara
import logging
import requests  # pip install requests
from dotenv import load_dotenv # pip install python-dotenv

# --- CONFIGURATION & SECRETS ---
# Load environment variables from .env file (for GitHub safety)
load_dotenv()

HOSTS_PATH = r"C:\Windows\System32\drivers\etc\hosts"
DEFENDER_PATH = r"C:\Program Files\Windows Defender\MpCmdRun.exe"

# Get Hive URL from .env, or default to localhost for dev
HIVE_URL = os.getenv("HIVE_URL", "http://127.0.0.1:5000/api/consult")
HIVE_KEY = os.getenv("HIVE_API_KEY")

# --- LOCAL WHITELIST (The "Fast Lane") ---
# These processes are TRUSTED immediately.
SAFE_PROCESSES = [
    "chrome.exe", "firefox.exe", "msedge.exe", "brave.exe",
    "code.exe", "pycharm64.exe", "python.exe", "py.exe", "cmd.exe", "powershell.exe",
    "docker.exe", "com.docker.backend.exe",
    "svchost.exe", "conhost.exe", "explorer.exe", "lsass.exe", "csrss.exe", 
    "winlogon.exe", "services.exe", "spoolsv.exe", "taskhostw.exe",
    "dllhost.exe", "searchfilterhost.exe", "searchprotocolhost.exe",
    "shield_watchdog.exe", "shield_launcher.exe", "runtimebroker.exe",
    "msedgewebview2.exe", "wpscloudsvr.exe", "sdxhelper.exe"
]

class DefenderBridge:
    """Interface for Microsoft Defender Kernel Scanning"""
    def __init__(self):
        self.available = os.path.exists(DEFENDER_PATH)

    def scan_file(self, file_path):
        if not self.available: return "UNAVAILABLE"
        try:
            cmd = [DEFENDER_PATH, "-Scan", "-ScanType", "3", "-File", file_path, "-DisableRemediation"]
            process = subprocess.run(cmd, capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
            if process.returncode == 2: return "INFECTED"
            return "CLEAN"
        except: return "ERROR"

class ShieldCore:
    def __init__(self, to_gui_queue, from_gui_queue, loggers):
        self.to_gui_queue = to_gui_queue
        self.from_gui_queue = from_gui_queue
        self.is_running = False
        self.known_pids = set()
        self.dynamic_whitelist = set() # Cache for Hive decisions
        
        # Silent Logger (Warnings only to terminal)
        self.log = logging.getLogger("ShieldWorker")
        self.log.setLevel(logging.WARNING)

        self.defender = DefenderBridge()
        
        # Load YARA Rules
        try:
            self.yara_rules = yara.compile(filepath='shielder.yar')
            self._send_digest("SYSTEM", "Cortex Engine Loaded.")
        except:
            self.yara_rules = None
            self._send_digest("SYSTEM", "Running in Hybrid Mode.")

    def _send_digest(self, title, message):
        """Pushes a message to the GUI logs."""
        self.to_gui_queue.put({'type': 'digest', 'data': f"[{title}] {message}"})

    def _consult_hive(self, process_name):
        """Asks the Server if a process is safe."""
        # 1. Check Dynamic Cache first (Don't spam server)
        if process_name in self.dynamic_whitelist:
            return "SAFE"

        try:
            # 2. Ask the Hive
            payload = {"process_name": process_name}
            # (Optional) Add API Key header if you implemented auth
            # headers = {"X-API-KEY": HIVE_KEY} 
            
            response = requests.post(HIVE_URL, json=payload, timeout=3)
            data = response.json()
            verdict = data.get("verdict", "SAFE")
            reason = data.get("reason", "Unknown")
            
            if verdict == "SAFE":
                self.dynamic_whitelist.add(process_name) # Remember this is safe
                self._send_digest("HIVE MIND", f"Authorized: {process_name} ({reason})")
                return "SAFE"
            else:
                return "THREAT"
        except:
            # 3. If Server is Offline -> FAIL OPEN (Allow it)
            # This prevents blocking apps if internet is down
            return "SAFE"

    def run(self):
        self.is_running = True
        print(">> SHIELD CORE: Connected to Hive Mind.")
        self._send_digest("SYSTEM", "Sentinel Active. Hive Uplink Established.")
        
        # Start the background watcher
        threading.Thread(target=self._active_sentinel_loop, daemon=True).start()

        while self.is_running:
            self.handle_gui_commands()
            time.sleep(0.1)

    def _active_sentinel_loop(self):
        """Watches for new processes and scans them."""
        self.known_pids = {p.pid for p in psutil.process_iter()}
        
        while self.is_running:
            time.sleep(1.0)
            try:
                current_pids = {p.pid for p in psutil.process_iter()}
                new_pids = current_pids - self.known_pids
                
                for pid in new_pids:
                    self.known_pids.add(pid)
                    try:
                        proc = psutil.Process(pid)
                        name = proc.name()
                        exe = proc.exe()
                        
                        # 1. Local Whitelist Check (Fast)
                        if name.lower() in [s.lower() for s in SAFE_PROCESSES]: continue
                        if "c:\\windows\\" in exe.lower(): continue
                        
                        # 2. Scan Process
                        self._scan_new_process(name, exe, pid)
                    except: pass
                self.known_pids = current_pids
            except: pass

    def _scan_new_process(self, name, exe_path, pid):
        score = 0
        
        # A. YARA Scan (Local Signature)
        if self.yara_rules:
            try:
                matches = self.yara_rules.match(exe_path)
                if matches: score = 100 # Known Malware Signature
            except: pass

        # B. Hive Consultation (The "Brain" Check)
        # Only ask if not flagged by YARA
        if score == 0:
            verdict = self._consult_hive(name)
            if verdict == "THREAT":
                score = 100

        # C. Action
        if score > 80:
            self._send_digest("AUTO-DEFENSE", f"🛑 BLOCKED: {name}")
            try: psutil.Process(pid).kill()
            except: pass
        else:
            # Benign - do nothing (or log if debug needed)
            pass

    def handle_gui_commands(self):
        """Processes button clicks from the UI."""
        try:
            command = self.from_gui_queue.get_nowait()
            action = command.get('action')
            
            # --- ACTIVATION COMMANDS ---
            if action == 'activate_evasion': 
                self._send_digest("TOR", "Routing traffic...")
            elif action == 'activate_ghost':
                self._send_digest("GHOST", "Spoofing Hardware ID...")
            elif action == 'toggle_autopilot': 
                self._send_digest("CLOAK", "Suppressing OS Telemetry...")
            
            # --- DEACTIVATION COMMANDS ---
            elif action == 'deactivate_evasion':
                self._send_digest("TOR", "Disconnecting. Original IP restored.")
            elif action == 'deactivate_ghost':
                self._send_digest("GHOST", "MAC Address reset to factory default.")
            elif action == 'deactivate_autopilot':
                self._send_digest("CLOAK", "Telemetry services re-enabled.")

            # --- SCAN COMMANDS ---
            elif action == 'scan_now': 
                self._send_digest("SCAN", "Smart Scan Initiated...")
                threading.Thread(target=self._perform_manual_scan, daemon=True).start()
        except queue.Empty: pass

    def _perform_manual_scan(self):
        time.sleep(1)
        self._send_digest("SCAN COMPLETE", "System Clean. No active threats.")

    def stop(self):
        self.is_running = False