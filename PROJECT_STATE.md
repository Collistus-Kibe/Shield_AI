# SHIELD AI: PROJECT STATE SNAPSHOT
# Generated on: 2025-11-13T12:58:23.252500




================================================================================
## 📦 shield_gui.py
================================================================================
```py
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import queue
import threading
import os
import logging
from logging.handlers import RotatingFileHandler
from utils.gui_logger import QueueLogHandler
from core.shield_backend import ShieldCore
from core.pin_auth import PINAuthWindow
from core.config_manager import is_pin_set, set_pin

class ThreatPopup(tk.Toplevel):
    def __init__(self, parent, proc_data, action_queue):
        super().__init__(parent)
        self.parent = parent
        self.proc = proc_data
        self.action_queue = action_queue
        self.title("🚨 Threat Detected!")
        self.geometry("450x220")
        self.resizable(False, False)
        self.configure(bg="#212121")
        self.transient(parent)
        self.grab_set()
        details_frame = ttk.Frame(self, padding="15"); details_frame.pack(fill="both", expand=True)
        ttk.Label(details_frame, text=f"Process: {self.proc['name']}", font=("Consolas", 11, "bold")).pack(anchor="w")
        ttk.Label(details_frame, text=f"PID: {self.proc['pid']}").pack(anchor="w")
        ttk.Label(details_frame, text=f"Threat Level: {self.proc['threat_level']} (Score: {self.proc['threat_score']})").pack(anchor="w")
        ttk.Label(details_frame, text=f"Reasons: {', '.join(self.proc['reasons'])}", wraplength=400).pack(anchor="w", pady=10)
        button_frame = ttk.Frame(self, padding="10"); button_frame.pack(fill="x", expand=True)
        ttk.Button(button_frame, text="Quarantine", command=self.quarantine).pack(side="left", expand=True, padx=5, pady=5)
        ttk.Button(button_frame, text="Trust", command=self.trust).pack(side="left", expand=True, padx=5, pady=5)
        ttk.Button(button_frame, text="Ignore", command=self.ignore).pack(side="left", expand=True, padx=5, pady=5)
        analysis_button = ttk.Button(button_frame, text="Static Analysis", command=self.analyze)
        analysis_button.pack(side="left", expand=True, padx=5, pady=5)
        if "python.exe" not in self.proc.get('name', ''): analysis_button.configure(state="disabled")

    def request_authorization(self, action_name):
        self.withdraw()
        main_app_instance = self.parent.winfo_toplevel().app_instance
        auth_window = PINAuthWindow(self.parent, callback=lambda success: self.on_auth_complete(success, action_name, main_app_instance))

    def on_auth_complete(self, was_successful, action_name, main_app_instance):
        if was_successful:
            main_app_instance.log_message("✅ PIN Authorization successful. Executing command.")
            self.action_queue.put({'action': action_name, 'proc': self.proc})
        else:
            main_app_instance.log_message("⚠️ PIN Authorization failed or was cancelled. Ignoring threat.")
            self.action_queue.put({'action': 'ignore', 'proc': self.proc})
        self.destroy()

    def quarantine(self): self.request_authorization('quarantine')
    def trust(self): self.request_authorization('trust')
    def analyze(self): self.request_authorization('analyze')
    def ignore(self): self.action_queue.put({'action': 'ignore', 'proc': self.proc}); self.destroy()

class ShieldGUI:
    def __init__(self, root):
        self.root = root; self.root.app_instance = self
        self.root.title("Shield AI - Guardian Console v3.0"); self.root.geometry("950x650")
        self.to_gui_queue = queue.Queue(); self.from_gui_queue = queue.Queue()
        self.log, self.cef_log = self.setup_gui_logging()
        self.backend = None; self.backend_thread = None
        self._build_ui(); self.process_queue()
        
        if not is_pin_set():
            self.status_text.set("Status: PIN Required")
            self.log_message("SECURITY: No Guardian PIN detected. Please set your 6-digit PIN.")
            self.force_pin_setup()

    def setup_gui_logging(self):
        logger = logging.getLogger("ShieldAI"); logger.setLevel(logging.INFO)
        if logger.hasHandlers(): logger.handlers.clear()
        queue_handler = QueueLogHandler(self.to_gui_queue); logger.addHandler(queue_handler)
        human_log_handler = RotatingFileHandler('shield_log.log', encoding='utf-8', maxBytes=5*1024*1024, backupCount=2); human_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'); human_log_handler.setFormatter(human_formatter); logger.addHandler(human_log_handler)
        cef_logger = logging.getLogger("ShieldAI_CEF"); cef_logger.setLevel(logging.INFO)
        if cef_logger.hasHandlers(): cef_logger.handlers.clear()
        cef_log_handler = RotatingFileHandler('shield.cef.log', encoding='utf-8', maxBytes=10*1024*1024, backupCount=5); cef_formatter = logging.Formatter('%(message)s'); cef_log_handler.setFormatter(cef_formatter); cef_logger.addHandler(cef_log_handler)
        return logger, cef_logger

    def _build_ui(self):
        self.root.configure(bg="#212121"); self.style = ttk.Style(); self.style.theme_use('clam')
        self.style.configure("TFrame", background="#212121"); self.style.configure("TLabel", background="#212121", foreground="#E0E0E0", font=("Consolas", 10)); self.style.configure("TNotebook.Tab", background="#333333", foreground="#FFFFFF", lightcolor="#212121", borderwidth=0); self.style.map("TNotebook.Tab", background=[("selected", "#007ACC")])
        self.header_frame = ttk.Frame(self.root, padding="10"); self.header_frame.pack(side="top", fill="x"); self.title_label = ttk.Label(self.header_frame, text="🛡️ SHIELD AI - GUARDIAN CONSOLE"); self.title_label.pack(side="left"); self.status_text = tk.StringVar(value="Status: Offline"); self.status_label = ttk.Label(self.header_frame, textvariable=self.status_text); self.status_label.pack(side="right"); self.notebook = ttk.Notebook(self.root, style="TNotebook"); self.notebook.pack(side="top", fill="both", expand=True, padx=10, pady=5)
        log_frame = ttk.Frame(self.notebook, padding=5); privacy_frame = ttk.Frame(self.notebook, padding=5); web_guard_frame = ttk.Frame(self.notebook, padding=5); quarantine_frame = ttk.Frame(self.notebook, padding=5)
        self.notebook.add(log_frame, text=" Event Log "); self.notebook.add(privacy_frame, text=" Privacy Dashboard "); self.notebook.add(web_guard_frame, text=" Web Guard "); self.notebook.add(quarantine_frame, text=" Quarantine ")
        self.log_viewer = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, bg="#1A1A1A", fg="#4CAF50", font=("Consolas", 9)); self.log_viewer.pack(fill="both", expand=True); self.log_viewer.configure(state='disabled')
        net_cols = ("pid", "process", "remote_addr", "city", "country"); self.network_tree = ttk.Treeview(privacy_frame, columns=net_cols, show='headings')
        for col in net_cols: self.network_tree.heading(col, text=col.replace('_', ' ').title()); self.network_tree.column(col, width=140, anchor=tk.W)
        self.network_tree.column("remote_addr", width=180); self.network_tree.pack(fill="both", expand=True)
        ttk.Label(web_guard_frame, text="Enter a suspicious URL to analyze:").pack(anchor="w", padx=5, pady=5); self.url_entry = ttk.Entry(web_guard_frame, font=("Consolas", 10)); self.url_entry.pack(fill="x", padx=5, pady=2); self.scan_url_button = ttk.Button(web_guard_frame, text="Analyze URL", command=self.scan_url_command); self.scan_url_button.pack(anchor="w", padx=5, pady=10); ttk.Label(web_guard_frame, text="Analysis Report:").pack(anchor="w", padx=5, pady=5); self.url_results_viewer = scrolledtext.ScrolledText(web_guard_frame, wrap=tk.WORD, height=10, bg="#1A1A1A", fg="#E0E0E0", font=("Consolas", 9)); self.url_results_viewer.pack(fill="both", expand=True, padx=5, pady=2); self.url_results_viewer.configure(state='disabled')
        q_button_frame = ttk.Frame(quarantine_frame); q_button_frame.pack(fill='x', pady=5)
        ttk.Button(q_button_frame, text="Refresh List", command=self.refresh_quarantine_list).pack(side='left', padx=5); ttk.Button(q_button_frame, text="Restore Selected", command=self.restore_selected).pack(side='left', padx=5); ttk.Button(q_button_frame, text="Delete Selected", command=self.delete_selected).pack(side='left', padx=5); self.debrief_button = ttk.Button(q_button_frame, text="Debrief Selected", command=self.debrief_selected); self.debrief_button.pack(side='left', padx=5)
        q_cols = ("file_name", "date", "original_path"); self.quarantine_tree = ttk.Treeview(quarantine_frame, columns=q_cols, show='headings', height=8);
        for col in q_cols: self.quarantine_tree.heading(col, text=col.replace('_', ' ').title()); self.quarantine_tree.column(col, anchor=tk.W)
        self.quarantine_tree.column("original_path", width=400); self.quarantine_tree.pack(fill='both', expand=True, side='top')
        ttk.Label(quarantine_frame, text="Threat Debriefing Report:").pack(anchor="w", padx=5, pady=(10, 5)); self.debrief_viewer = scrolledtext.ScrolledText(quarantine_frame, wrap=tk.WORD, bg="#1A1A1A", fg="#4CAF50", font=("Consolas", 9)); self.debrief_viewer.pack(fill="both", expand=True, side='bottom'); self.debrief_viewer.insert(tk.END, "Select a quarantined item and click 'Debrief Selected' to generate a report."); self.debrief_viewer.configure(state='disabled')
        self.footer_frame = ttk.Frame(self.root, padding="10"); self.footer_frame.pack(side="bottom", fill="x"); self.start_button = ttk.Button(self.footer_frame, text="Engage Shield Core", command=self.start_backend_thread); self.start_button.pack(side="left", padx=5); self.baseline_button = ttk.Button(self.footer_frame, text="Create Baseline", command=self.create_baseline_command, state="disabled"); self.baseline_button.pack(side="left", padx=5)
        self.set_pin_button = ttk.Button(self.footer_frame, text="Set/Change PIN", command=self.force_pin_setup); self.set_pin_button.pack(side="left", padx=1More);
        self.focus_mode_var = tk.BooleanVar(); self.focus_mode_button = ttk.Checkbutton(self.footer_frame, text="Focus Mode", style="TButton", variable=self.focus_mode_var, command=self.toggle_focus_mode); self.focus_mode_button.pack(side="right", padx=5)
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def force_pin_setup(self):
        self.log_message("SECURITY: Awaiting new 6-digit PIN...")
        auth_window = PINAuthWindow(self.root, callback=self.on_pin_set, is_setting_pin=True)
        self.root.wait_window(auth_window)

    def on_pin_set(self, new_pin):
        if new_pin:
            self.from_gui_queue.put({'action': 'set_pin', 'data': new_pin})
            self.status_text.set("Status: PIN Set. Ready to Engage.")
        else:
            self.log_message("SECURITY: PIN setup was cancelled.")

    def toggle_focus_mode(self): is_active = self.focus_mode_var.get(); mode_text = "ACTIVATED" if is_active else "DEACTIVATED"; self.log_message(f"Operator Command: Focus Mode {mode_text}."); self.from_gui_queue.put({'action': 'toggle_focus_mode', 'data': is_active})
    def refresh_quarantine_list(self): self.log_message("Requesting updated quarantine list..."); self.from_gui_queue.put({'action': 'list_quarantine'})
    
    def get_selected_quarantine_item_key(self):
        selected_item = self.quarantine_tree.focus()
        if not selected_item: self.log_message("QUARANTINE: No file selected."); return None
        return self.quarantine_tree.item(selected_item)['values'][0]

    def restore_selected(self):
        selected_file = self.get_selected_quarantine_item_key()
        if selected_file: self.from_gui_queue.put({'action': 'restore_file', 'data': selected_file})
    def delete_selected(self):
        selected_file = self.get_selected_quarantine_item_key()
        if selected_file: self.from_gui_queue.put({'action': 'delete_file', 'data': selected_file})
    def debrief_selected(self):
        selected_item_key = self.get_selected_quarantine_item_key()
        if not selected_item_key or not hasattr(self, 'quarantine_manifest'): self.log_message("DEBRIEF: Please select an item from the refreshed list first."); return
        threat_details = self.quarantine_manifest.get(selected_item_key)
        # report = generate_debriefing(threat_details) # This line will be added in Day 31
        report = "Threat Debriefing AI is offline. Feature pending."
        self.debrief_viewer.configure(state='normal'); self.debrief_viewer.delete('1.0', tk.END)
        # --- THIS IS THE CORRECTED LINE ---
        self.debrief_viewer.insert(tk.END, report)
        # --- END CORRECTION ---
        self.debrief_viewer.configure(state='disabled')

    def scan_url_command(self):
        url = self.url_entry.get()
        if url: self.url_results_viewer.configure(state='normal'); self.url_results_viewer.delete('1.0', tk.END); self.url_results_viewer.insert(tk.END, f"Analyzing: {url}\n" + "-"*50 + "\n"); self.url_results_viewer.configure(state='disabled'); self.from_gui_queue.put({'action': 'scan_url', 'data': url})
        else: self.log_message("Web Guard: Please enter a URL to analyze.")
    def display_url_analysis(self, result):
        self.url_results_viewer.configure(state='normal'); self.url_results_viewer.insert(tk.END, f"Threat Score: {result['score']}\n\nReasons:\n")
        for reason in result['reasons']: self.url_results_viewer.insert(tk.END, f"- {reason}\n")
        self.url_results_viewer.configure(state='disabled'); self.notebook.select(2)
    def create_baseline_command(self): self.log_message("Issuing command to create new system baseline..."); self.from_gui_queue.put({'action': 'create_baseline'})
    
    def start_backend_thread(self):
        if not is_pin_set():
            messagebox.showerror("PIN Required", "You must set a 6-digit PIN before engaging the core.", parent=self.root)
            return
        if self.backend_thread and self.backend_thread.is_alive(): return
        loggers = (self.log, self.cef_log); self.backend = ShieldCore(self.to_gui_queue, self.from_gui_queue, loggers)
        self.backend_thread = threading.Thread(target=self.backend.run, daemon=True); self.backend_thread.start()
        self.start_button.configure(text="Core Engaged", state="disabled"); self.baseline_button.configure(state="normal")
    
    def process_queue(self):
        try:
            message = self.to_gui_queue.get_nowait()
            msg_type = message.get('type'); data = message.get('data')
            if msg_type == 'status': self.status_text.set(f"Status: {data}")
            elif msg_type == 'log': self.log_message(data)
            elif msg_type == 'threat': ThreatPopup(self.root, data, self.from_gui_queue)
            elif msg_type == 'network_update': self.update_network_display(data)
            elif msg_type == 'url_analysis_result': self.display_url_analysis(data)
            elif msg_type == 'quarantine_list_update': self.update_quarantine_display(data)
        except queue.Empty: pass
        finally: self.root.after(200, self.process_queue)

    def update_network_display(self, connections):
        if not hasattr(self, 'network_tree'): return
        for i in self.network_tree.get_children(): self.network_tree.delete(i)
        for conn in connections: self.network_tree.insert("", "end", values=(conn['pid'],conn['process'],conn['remote_addr'],conn['city'],conn['country']))
    def update_quarantine_display(self, manifest):
        if not hasattr(self, 'quarantine_tree'): return
        self.quarantine_manifest = manifest
        for i in self.quarantine_tree.get_children(): self.quarantine_tree.delete(i)
        for name, details in manifest.items(): self.quarantine_tree.insert("", "end", values=(name, details['date_quarantined'], details['original_path']))
    def log_message(self, message):
        self.log_viewer.configure(state='normal'); self.log_viewer.insert(tk.END, f"{message}\n"); self.log_viewer.see(tk.END); self.log_viewer.configure(state='disabled')
    def on_closing(self):
        if self.backend: self.backend.stop()
        self.root.destroy()
if __name__ == "__main__":
    root = tk.Tk()
    app = ShieldGUI(root)
    root.mainloop()
```



================================================================================
## 📦 core/shield_backend.py
================================================================================
```py
import time
import os
import configparser
from .monitoring import create_baseline, check_for_new_processes, analyze_processes, sync_global_intelligence
from .actions import quarantine_threat, trust_process, list_quarantined_files, restore_quarantined_file, delete_quarantined_file
from .firewall_manager import block_pid_outbound
from .policy_manager import load_policy
from .static_analyzer import analyze_script_content
from .network_monitor import get_active_connections
from .directory_services import load_directory
from .web_guard import analyze_url
from .config_manager import set_pin
from utils.cef_formatter import format_cef

class ShieldCore:
    def __init__(self, to_gui_queue, from_gui_queue, loggers):
        self.log = loggers[0]
        self.cef_log = loggers[1]
        self.to_gui_queue = to_gui_queue
        self.from_gui_queue = from_gui_queue
        self.is_running = False
        self.paused = False
        self.focus_mode = False
        self.scan_counter = 0
        config = configparser.ConfigParser()
        config.read('config.ini')
        self.scan_interval = config.getint('SHIELD_SETTINGS', 'scan_interval_seconds', fallback=20)

    def _send_log_to_gui(self, message, level="INFO"):
        if level == "INFO": self.log.info(message)
        elif level == "WARN": self.log.warning(message)
        self.to_gui_queue.put({'type': 'log', 'data': message})

    def run(self):
        self.is_running = True
        self._send_log_to_gui("Shield Core backend thread started.")
        self.to_gui_queue.put({'type': 'status', 'data': 'Initializing...'})
        policy = load_policy(self.log)
        global_intelligence = sync_global_intelligence(self.log)
        corporate_directory = load_directory(self.log)
        self.to_gui_queue.put({'type': 'status', 'data': 'Active Monitoring'})
        while self.is_running:
            self.handle_gui_commands()
            self.scan_counter += 1
            if self.focus_mode and self.scan_counter % 3 != 1:
                time.sleep(self.scan_interval)
                continue
            if not self.paused:
                self.run_scan_cycle(global_intelligence, policy, self.log, corporate_directory)
                self._send_log_to_gui(f"Scan cycle complete. Standby for {self.scan_interval}s.")
                time.sleep(self.scan_interval)
            else:
                time.sleep(1)

    def stop(self):
        self.is_running = False

    def handle_gui_commands(self):
        try:
            command = self.from_gui_queue.get_nowait()
            action = command.get('action')
            data = command.get('data', None)
            
            if action == 'toggle_focus_mode':
                self.focus_mode = data
                mode_text = "ACTIVATED" if self.focus_mode else "DEACTIVATED"
                self._send_log_to_gui(f"Focus Mode Protocol {mode_text}.", "WARN")
                return
            
            if action == 'set_pin':
                self._send_log_to_gui("SECURITY: Received new PIN. Hashing and saving securely.")
                set_pin(data, self.log)
                return

            if action == 'create_baseline':
                self._send_log_to_gui("GUI_COMMAND: Received order to CREATE BASELINE.", "WARN")
                create_baseline(self.log)
                self.paused = False
                self.to_gui_queue.put({'type': 'status', 'data': 'Active Monitoring'})
                return

            if action == 'scan_url':
                self._send_log_to_gui(f"Web Guard: Analyzing URL -> {data}", "INFO")
                result = analyze_url(data)
                self.to_gui_queue.put({'type': 'url_analysis_result', 'data': result})
                return
            
            if action == 'list_quarantine':
                files = list_quarantined_files()
                self.to_gui_queue.put({'type': 'quarantine_list_update', 'data': files})
                return
            if action == 'restore_file':
                restore_quarantined_file(data, self.log)
                self.from_gui_queue.put({'action': 'list_quarantine'})
                return
            if action == 'delete_file':
                delete_quarantined_file(data, self.log)
                self.from_gui_queue.put({'action': 'list_quarantine'})
                return

            proc = command.get('proc')
            proc_name = proc.get('name', 'Unknown')
            pid = proc.get('pid')

            if action == 'quarantine':
                self._send_log_to_gui(f"GUI_COMMAND: Received order to QUARANTINE {proc_name}.", "CRITICAL")
                cef_msg = format_cef("CRITICAL", "ManualQuarantine", f"Operator quarantined threat {proc_name}", f"pid={pid}")
                self.cef_log.info(cef_msg)
                quarantine_threat(proc, self.log)
            elif action == 'trust':
                self._send_log_to_gui(f"GUI_COMMAND: Received order to TRUST {proc_name}.", "WARN")
                cef_msg = format_cef("INFO", "ManualTrust", f"Operator trusted process {proc_name}", f"pid={pid}")
                self.cef_log.info(cef_msg)
                trust_process(proc_name, self.log)
            elif action == 'analyze':
                self._send_log_to_gui(f"GUI_COMMAND: Received order to ANALYZE script for {proc_name}.", "WARN")
                analyze_script_content('payload.py', self.log)
            
            self.paused = False
            self.to_gui_queue.put({'type': 'status', 'data': 'Active Monitoring'})
        except Exception:
            pass

    def run_scan_cycle(self, global_intelligence, policy, log, corporate_directory):
        self._send_log_to_gui("Scanning for new processes...")
        new_processes = check_for_new_processes()
        if new_processes is None:
            self.to_gui_queue.put({'type': 'status', 'data': 'Baseline Needed!'})
            self.paused = True
            return

        if new_processes:
            analyzed_list = analyze_processes(new_processes, global_intelligence, corporate_directory)
            threat_order = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
            significant_threats = [p for p in analyzed_list if threat_order.get(p.get('threat_level'), 0) >= threat_order["MEDIUM"]]
            all_threats = [p for p in analyzed_list if p.get('threat_level') != "NONE"]

            if significant_threats:
                if self.focus_mode:
                    self._send_log_to_gui("FOCUS MODE: High-level threat detected. Engaging autonomous quarantine.", "CRITICAL")
                    for proc in significant_threats:
                        quarantine_threat(proc, self.log)
                else:
                    self.paused = True
                    self.to_gui_queue.put({'type': 'status', 'data': 'Awaiting Command...'})
                    for proc in significant_threats:
                        self.to_gui_queue.put({'type': 'threat', 'data': proc})
            
            for proc in all_threats:
                if proc not in significant_threats:
                    self._send_log_to_gui(f"LOW-LEVEL EVENT: Detected '{proc['name']}' (Score: {proc['threat_score']})")
        else:
             self._send_log_to_gui("✅ System Nominal. No new processes detected.")

        active_conns = get_active_connections(log)
        self.to_gui_queue.put({'type': 'network_update', 'data': active_conns})
```



================================================================================
## 📦 core/actions.py
================================================================================
```py
# File: shield_ai/core/actions.py
import psutil
import json
import os
import shutil
import hashlib
import requests
from datetime import datetime

# --- Module Constants ---
USER_TRUST_FILE = 'user_trust.json'
GLOBAL_INTELLIGENCE_FILE = "global_intelligence.json"
QUARANTINE_DIR = r"C:\ProgramData\ShieldAI\Quarantine"
MANIFEST_FILE = os.path.join(QUARANTINE_DIR, 'quarantine_manifest.json')
HIVE_SERVER_URL = "http://127.0.0.1:5000/report"

# --- Helper Functions ---
def _load_manifest():
    if not os.path.exists(MANIFEST_FILE): return {}
    try:
        with open(MANIFEST_FILE, 'r') as f: return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError): return {}

def _save_manifest(manifest_data, log):
    try:
        os.makedirs(QUARANTINE_DIR, exist_ok=True)
        with open(MANIFEST_FILE, 'w') as f: json.dump(manifest_data, f, indent=4)
    except Exception as e:
        log.error(f"Failed to save quarantine manifest: {e}")

def _calculate_file_hash(file_path, log):
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        log.error(f"HASHING FAILED: Could not hash file {file_path}. Reason: {e}")
        return None

def _terminate_process_by_pid(pid, log):
    try:
        process = psutil.Process(pid)
        proc_name = process.name()
        process.terminate()
        log.warning(f"ACTION: Terminated process {proc_name} (PID: {pid}).")
        return True
    except psutil.NoSuchProcess:
        log.info(f"ACTION: Process with PID {pid} already terminated.")
        return False
    except psutil.AccessDenied:
        log.critical(f"ACTION FAILED: Access denied. Cannot terminate PID {pid}.")
        return False

# --- Primary Action Functions ---
def report_threat_to_hive(proc, file_path, log):
    log.info("TRANSMITTING: Reporting new threat telemetry to the Hive...")
    file_hash = _calculate_file_hash(file_path, log)
    if not file_hash:
        log.error("Could not calculate file hash. Aborting telemetry report.")
        return

    telemetry_data = {
        "threat_name": proc.get('name'),
        "file_hash": file_hash,
        "threat_score": proc.get('threat_score'),
        "reasons": proc.get('reasons', [])
    }

    try:
        response = requests.post(HIVE_SERVER_URL, json=telemetry_data, timeout=5)
        if response.status_code == 200:
            log.info("✅ Telemetry successfully received by the Hive.")
        else:
            log.warning(f"Hive server responded with status code: {response.status_code}")
    except requests.exceptions.RequestException:
        log.error(f"⛔ Could not connect to the Hive server. Ensure hive_server.py is running and firewall rule is set.")

def quarantine_threat(proc, log):
    pid = proc.get('pid')
    if not pid:
        log.error("QUARANTINE FAILED: Missing PID.")
        return False

    try:
        p = psutil.Process(pid)
        target_file_to_move = p.exe()

        if p.name().lower() in ['python.exe', 'pythonw.exe']:
            cmdline = p.cmdline()
            script_path = next((arg for arg in cmdline if arg.lower().endswith('.py')), None)
            if script_path and os.path.exists(script_path):
                target_file_to_move = os.path.abspath(script_path)
                log.info(f"Python script detected. Targeting '{target_file_to_move}' for quarantine.")

        # --- THIS IS THE FIX ---
        # This call was missing in the previous version.
        report_threat_to_hive(proc, target_file_to_move, log)

        file_name = os.path.basename(target_file_to_move)
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        quarantined_name = f"{timestamp}-{file_name}.quarantined"
        destination_path = os.path.join(QUARANTINE_DIR, quarantined_name)

        log.warning(f"QUARANTINE: Moving '{target_file_to_move}' to '{destination_path}'")
        shutil.move(target_file_to_move, destination_path)

        manifest = _load_manifest()
        manifest[quarantined_name] = {
            "original_path": target_file_to_move,
            "date_quarantined": datetime.now().isoformat(),
            "threat_name": proc.get('name'),
            "threat_score": proc.get('threat_score'),
            "threat_level": proc.get('threat_level'),
            "reasons": proc.get('reasons', [])
        }
        _save_manifest(manifest, log)

        log.critical(f"✅ THREAT NEUTRALIZED: File '{file_name}' has been quarantined.")

    except (psutil.NoSuchProcess, FileNotFoundError):
        log.error(f"QUARANTINE FAILED: Process or file for PID {pid} not found.")
    except PermissionError:
        log.error(f"QUARANTINE FAILED: Permission denied to move file for PID {pid}.")
    except Exception as e:
        log.critical(f"QUARANTINE FAILED: An unexpected error occurred. Reason: {e}")
    finally:
        return _terminate_process_by_pid(pid, log)

def trust_process(process_name, log):
    trusted_list = []
    if os.path.exists(USER_TRUST_FILE):
        with open(USER_TRUST_FILE, 'r') as f:
            try: trusted_list = json.load(f)
            except json.JSONDecodeError: pass

    if process_name not in trusted_list:
        trusted_list.append(process_name)
        with open(USER_TRUST_FILE, 'w') as f:
            json.dump(trusted_list, f, indent=4)
        log.info(f"ACTION: {process_name} has been added to the LOCAL trusted list.")
    else:
        log.info(f"INFO: {process_name} is already on the local trusted list.")

# --- Quarantine Management Functions ---
def list_quarantined_files():
    return _load_manifest()

def restore_quarantined_file(quarantined_name, log):
    manifest = _load_manifest()
    if quarantined_name not in manifest:
        log.error(f"RESTORE FAILED: '{quarantined_name}' not found in manifest.")
        return False

    item_data = manifest[quarantined_name]
    original_path = item_data['original_path']
    quarantined_path = os.path.join(QUARANTINE_DIR, quarantined_name)

    try:
        log.warning(f"RESTORING: Moving '{quarantined_path}' back to '{original_path}'")
        os.makedirs(os.path.dirname(original_path), exist_ok=True)
        shutil.move(quarantined_path, original_path)
        del manifest[quarantined_name]
        _save_manifest(manifest, log)
        log.info(f"✅ File '{os.path.basename(original_path)}' restored successfully.")
        return True
    except Exception as e:
        log.error(f"⛔ RESTORE FAILED: Could not move file. Reason: {e}")
        return False

def delete_quarantined_file(quarantined_name, log):
    manifest = _load_manifest()
    if quarantined_name not in manifest:
        log.error(f"DELETE FAILED: '{quarantined_name}' not found in manifest.")
        return False

    quarantined_path = os.path.join(QUARANTINE_DIR, quarantined_name)

    try:
        log.warning(f"PERMANENTLY DELETING: '{quarantined_path}'")
        os.remove(quarantined_path)
        del manifest[quarantined_name]
        _save_manifest(manifest, log)
        log.info(f"✅ File '{quarantined_name}' permanently deleted.")
        return True
    except Exception as e:
        log.error(f"⛔ DELETE FLED: Could not delete file. Reason: {e}")
        return False
```



================================================================================
## 📦 core/monitoring.py
================================================================================
```py
import psutil
import json
import os
from utils.helpers import calculate_entropy
from .directory_services import get_user_privilege_level # <-- NEW IMPORT

BASELINE_FILE = "baseline.json"
USER_TRUST_FILE = "user_trust.json"
GLOBAL_INTELLIGENCE_FILE = "global_intelligence.json"

def sync_global_intelligence(log):
    log.info("Syncing with Global Intelligence...")
    intelligence = {'trusted': set(), 'threats': set()}
    try:
        with open(GLOBAL_INTELLIGENCE_FILE, 'r') as f:
            data = json.load(f)
        intelligence['trusted'] = set(data.get("trusted_processes", []))
        intelligence['threats'] = set(data.get("confirmed_threats", []))
        log.info(f"✅ Sync successful. Loaded {len(intelligence['trusted'])} trusted entries and {len(intelligence['threats'])} threats.")
        return intelligence
    except Exception as e:
        log.warning(f"⚠️ Sync failed. Could not read intelligence file. Reason: {e}")
        return intelligence

def get_active_processes():
    process_list = []
    for process in psutil.process_iter(['pid', 'name', 'username', 'ppid']):
        try:
            process_list.append(process.info)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return process_list

def create_baseline(log):
    log.info("Creating new security baseline...")
    processes = get_active_processes()
    baseline_process_names = {p['name'] for p in processes if p['name']}
    
    with open(BASELINE_FILE, 'w') as f:
        json.dump(list(baseline_process_names), f, indent=4)
        
    log.info(f"Baseline created successfully with {len(baseline_process_names)} processes.")
    return True

def check_for_new_processes():
    try:
        with open(BASELINE_FILE, 'r') as f:
            baseline_process_names = set(json.load(f))
    except FileNotFoundError:
        return None 
    ALWAYS_ANALYZE = {'python.exe', 'powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe'}
    current_processes = get_active_processes()
    current_process_names = {p['name'] for p in current_processes if p['name']}
    new_process_names = current_process_names - baseline_process_names
    processes_to_analyze_names = new_process_names.union(
        {name for name in current_process_names if name in ALWAYS_ANALYZE}
    )
    return [p for p in current_processes if p['name'] in processes_to_analyze_names]

def analyze_processes(process_list, global_intelligence, corporate_directory):
    global_trusted_set = global_intelligence.get('trusted', set())
    global_threat_set = global_intelligence.get('threats', set())
    user_trusted_set = set()
    if os.path.exists(USER_TRUST_FILE):
        with open(USER_TRUST_FILE, 'r') as f:
            try: user_trusted_set = set(json.load(f))
            except json.JSONDecodeError: pass

    full_trusted_set = global_trusted_set.union(user_trusted_set)
    analyzed_results = []
    safe_parents = {'explorer.exe', 'svchost.exe', 'services.exe', 'wininit.exe', 'System', 'powershell.exe', 'cmd.exe'}

    for process in process_list:
        score = 0
        reasons = []

        if process['name'] in global_threat_set:
            score = 100
            reasons.append("BLACKLISTED: Confirmed global threat.")
            level = "CRITICAL"
        else:
            # --- NEW: User Privilege Heuristic ---
            privilege_level = get_user_privilege_level(process.get('username'), corporate_directory)
            is_high_risk_name = process['name'] in {'powershell.exe', 'cmd.exe', 'python.exe'}
            is_trusted = process['name'] in full_trusted_set

            if not is_trusted and is_high_risk_name and privilege_level < 10:
                score += 40
                reasons.append(f"High-risk process run by non-admin (Privilege: {privilege_level})")
            
            # --- Existing Heuristics ---
            if is_trusted: score -= 100; reasons.append("On trusted list")
            else: score += 20; reasons.append("Not on trusted lists")
            if process.get('username') is None: score += 30; reasons.append("No user context")
            
            entropy = calculate_entropy(process['name'])
            if entropy > 3.5:
                score += 50
                reasons.append(f"High filename entropy ({entropy:.2f})")
            
            try:
                parent = psutil.Process(process['ppid'])
                parent_name = parent.name()
                if parent_name not in safe_parents and not is_trusted:
                    score += 35
                    reasons.append(f"Launched by unusual parent: {parent_name}")
            except psutil.NoSuchProcess:
                reasons.append("Parent process no longer exists.")
            except Exception: pass

            if score < 0: level = "NONE"
            elif score < 30: level = "LOW"
            elif score < 60: level = "MEDIUM"
            elif score < 90: level = "HIGH"
            else: level = "CRITICAL"

        process['threat_score'], process['threat_level'], process['reasons'] = score, level, reasons
        analyzed_results.append(process)
        
    return analyzed_results
```



================================================================================
## 📦 core/network_monitor.py
================================================================================
```py
import psutil
import geoip2.database
import os
from ipaddress import ip_address

# Path to the GeoIP database
DB_PATH = os.path.join('data', 'GeoLite2-City.mmdb')
reader = None

# Load the database reader once when the module is imported
try:
    if os.path.exists(DB_PATH):
        reader = geoip2.database.Reader(DB_PATH)
except Exception as e:
    print(f"Could not load GeoIP database: {e}. Location data will not be available.")

def get_geoip_location(ip):
    """Looks up the geographic location of an IP address."""
    if not reader or not ip:
        return "N/A", "N/A"
    
    try:
        # Ignore private/local IP addresses
        if ip_address(ip).is_private or ip_address(ip).is_loopback:
            return "Local", "Private Network"
            
        response = reader.city(ip)
        country = response.country.name or "Unknown"
        city = response.city.name or "Unknown"
        return country, city
    except geoip2.errors.AddressNotFoundError:
        return "Unknown", "N/A"
    except Exception:
        return "Error", "N/A"

def get_active_connections(log):
    """
    Scans for active TCP connections and enriches them with GeoIP data.
    """
    connections = []
    try:
        net_conns = psutil.net_connections(kind='tcp')
        for conn in net_conns:
            if conn.status == 'ESTABLISHED' and conn.raddr:
                proc_name = "?"
                try:
                    p = psutil.Process(conn.pid)
                    proc_name = p.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
                
                remote_ip = conn.raddr.ip
                country, city = get_geoip_location(remote_ip)

                connections.append({
                    'pid': conn.pid or "N/A",
                    'process': proc_name,
                    'remote_addr': f"{remote_ip}:{conn.raddr.port}",
                    'country': country,
                    'city': city
                })
    except Exception as e:
        log.error(f"NETWORK_MONITOR: Failed to retrieve connections. Reason: {e}")

    return connections
```



================================================================================
## 📦 core/policy_manager.py
================================================================================
```py
import configparser

POLICY_FILE = 'policy.ini'

def load_policy(log):
    """
    Loads automation policies from the policy.ini file.
    Returns a dictionary with policy settings.
    """
    config = configparser.ConfigParser()
    policy = {
        'enabled': False,
        'auto_terminate_threshold': 101 # Default to a safe, high value
    }

    try:
        if not config.read(POLICY_FILE):
            log.warning(f"Policy file '{POLICY_FILE}' not found. Automation is disabled.")
            return policy

        # Read settings from the [AUTOMATION_POLICY] section
        if 'AUTOMATION_POLICY' in config:
            policy['enabled'] = config.getboolean('AUTOMATION_POLICY', 'enabled', fallback=False)
            policy['auto_terminate_threshold'] = config.getint('AUTOMATION_POLICY', 'auto_terminate_threshold', fallback=101)
            log.info("Automation policy loaded successfully.")
            if not policy['enabled']:
                log.info("Automation is currently disabled in policy.ini.")
        else:
            log.warning("No [AUTOMATION_POLICY] section in policy.ini. Automation disabled.")

    except Exception as e:
        log.error(f"Error loading policy file: {e}. Automation disabled.")
        policy['enabled'] = False # Ensure it's disabled on error

    return policy
```



================================================================================
## 📦 core/config_manager.py
================================================================================
```py
import configparser
import hashlib

CONFIG_FILE = 'config.ini'

def _hash_pin(pin):
    """Hashes a PIN using SHA-256."""
    return hashlib.sha256(pin.encode()).hexdigest()

def set_pin(pin, log):
    """Securely saves a new PIN hash to the config file."""
    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)
    
    pin_hash = _hash_pin(pin)
    
    if 'SECURITY' not in config:
        config.add_section('SECURITY')
        
    config.set('SECURITY', 'pin_hash', pin_hash)
    
    try:
        with open(CONFIG_FILE, 'w') as f:
            config.write(f)
        log.info("CONFIG: Secure PIN has been set.")
        return True
    except Exception as e:
        log.error(f"CONFIG: Failed to set PIN. {e}")
        return False

def verify_pin(pin):
    """Verifies a given PIN against the stored hash."""
    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)
    
    if 'SECURITY' not in config or 'pin_hash' not in config['SECURITY']:
        return False # No PIN set
        
    stored_hash = config.get('SECURITY', 'pin_hash')
    input_hash = _hash_pin(pin)
    
    return input_hash == stored_hash

def is_pin_set():
    """Checks if a PIN hash already exists in the config."""
    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)
    return 'SECURITY' in config and 'pin_hash' in config['SECURITY']
```



================================================================================
## 📦 core/pin_auth.py
================================================================================
```py
import tkinter as tk
from tkinter import ttk, messagebox
from .config_manager import verify_pin

class PINAuthWindow(tk.Toplevel):
    def __init__(self, parent, callback, is_setting_pin=False):
        super().__init__(parent)
        self.callback = callback
        self.is_setting_pin = is_setting_pin
        
        self.title("Authorization Required")
        self.geometry("300x150")
        self.resizable(False, False)
        self.configure(bg="#212121")
        self.transient(parent)
        self.grab_set()

        self.style = ttk.Style()
        self.style.configure("TLabel", background="#212121", foreground="#E0E0E0")
        self.style.configure("TButton", padding=5)
        
        if is_setting_pin:
            self.main_label = ttk.Label(self, text="Create your 6-Digit Guardian PIN:", font=("Consolas", 10))
            self.button_text = "Set PIN"
        else:
            self.main_label = ttk.Label(self, text="Enter 6-Digit PIN to Authorize:", font=("Consolas", 10))
            self.button_text = "Authorize"
            
        self.main_label.pack(pady=10)
        
        self.pin_entry = ttk.Entry(self, width=10, font=("Consolas", 12), show="*")
        self.pin_entry.pack(pady=5)
        
        self.submit_button = ttk.Button(self, text=self.button_text, command=self.check_pin)
        self.submit_button.pack(pady=10)
        
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

    def check_pin(self):
        pin = self.pin_entry.get()
        
        if not pin.isdigit() or len(pin) != 6:
            messagebox.showerror("Invalid PIN", "PIN must be exactly 6 digits.", parent=self)
            return

        if self.is_setting_pin:
            self.callback(pin) # Send the new PIN back to be set
            self.destroy()
        else:
            if verify_pin(pin):
                self.callback(True) # Authorization successful
                self.destroy()
            else:
                messagebox.showerror("Access Denied", "Invalid PIN.", parent=self)
                self.callback(False) # Authorization failed

    def on_closing(self):
        """Called when the window is closed."""
        if not self.is_setting_pin:
            self.callback(False) # Report back failure
        self.destroy()
```



================================================================================
## 📦 core/static_analyzer.py
================================================================================
```py
import re
from utils.helpers import calculate_entropy

def analyze_script_content(file_path, log):
    """
    Performs static analysis on a script file to identify malicious characteristics.
    """
    log.info(f"STATIC_ANALYSIS: Initiating for '{file_path}'...")
    report = {
        'score': 0,
        'reasons': []
    }
    
    try:
        with open(file_path, 'r', errors='ignore') as f:
            content = f.read()

        # 1. Check for suspicious keywords and imports (e.g., eval, exec)
        suspicious_keywords = re.findall(r'(eval|exec|subprocess|base64\.b64decode|requests\.post)', content)
        if suspicious_keywords:
            hits = list(set(suspicious_keywords)) # Get unique hits
            report['score'] += 25 * len(hits)
            report['reasons'].append(f"Suspicious keywords found: {hits}")

        # 2. Check for suspicious string patterns (IPs, sensitive paths)
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        sensitive_paths = r'(/etc/passwd|~/\.ssh/|C:\\Windows\\System32)'
        if re.search(ip_pattern, content):
            report['score'] += 20
            report['reasons'].append("IP address found in string literal.")
        if re.search(sensitive_paths, content):
            report['score'] += 30
            report['reasons'].append("Reference to sensitive system path found.")
            
        # 3. Check for high entropy (obfuscation/packed code)
        entropy = calculate_entropy(content)
        if entropy > 4.5: # Entropy threshold is higher for a whole file
            report['score'] += 35
            report['reasons'].append(f"High content entropy ({entropy:.2f}) suggests obfuscation.")
        
        # Log the final report
        if report['score'] > 0:
            log.warning("--- [ START STATIC ANALYSIS REPORT ] ---")
            log.warning(f"File: {os.path.basename(file_path)}")
            log.warning(f"Final Threat Score: {report['score']}")
            log.warning("Reasons:")
            for reason in report['reasons']:
                log.warning(f"  - {reason}")
            log.warning("--- [ END STATIC ANALYSIS REPORT ] ---")
        else:
            log.info(f"STATIC_ANALYSIS: '{file_path}' appears clean. Score: 0.")

    except FileNotFoundError:
        log.error(f"STATIC_ANALYSIS_FAILED: File not found at '{file_path}'.")
    except Exception as e:
        log.critical(f"STATIC_ANALYSIS_FAILED: An unexpected error occurred. {e}")
```



================================================================================
## 📦 core/web_guard.py
================================================================================
```py
import re
from urllib.parse import urlparse

def analyze_url(url):
    """
    Performs a heuristic analysis of a URL to detect signs of phishing or malware.
    """
    score = 0
    reasons = []

    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        
        if not hostname:
            raise ValueError("Invalid URL provided")

        # Heuristic 1: IP Address in Hostname
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hostname):
            score += 40
            reasons.append("URL uses an IP address instead of a domain name.")

        # Heuristic 2: Presence of '@' symbol in URL (common phishing trick)
        if '@' in url.split('/')[2]:
            score += 30
            reasons.append("URL contains '@' symbol in the authority part, which can obscure the real domain.")

        # Heuristic 3: Number of subdomains
        if hostname.count('.') > 3:
            score += 25
            reasons.append(f"URL has an unusually high number of subdomains ({hostname.count('.')}).")

        # Heuristic 4: Suspicious Top-Level Domains (TLDs)
        suspicious_tlds = ['.xyz', '.top', '.buzz', '.tk', '.link', '.club']
        if any(tld for tld in suspicious_tlds if hostname.endswith(tld)):
            score += 35
            reasons.append("URL uses a TLD commonly associated with spam or malware.")

        # Heuristic 5: Presence of sensitive keywords in the path or subdomain
        sensitive_keywords = ['login', 'verify', 'account', 'secure', 'password', 'update']
        if any(keyword in url.lower() for keyword in sensitive_keywords):
            score += 20
            reasons.append("URL contains sensitive keywords, often used in phishing attempts.")

    except Exception as e:
        return {'score': -1, 'reasons': [f"Error analyzing URL: {e}"]}

    if not reasons:
        reasons.append("URL appears to be safe based on heuristics.")
        
    return {'score': score, 'reasons': reasons}
```



================================================================================
## 📦 core/directory_services.py
================================================================================
```py
import json

def load_directory(log):
    """Loads the corporate directory from the JSON file."""
    try:
        with open('corporate_directory.json', 'r') as f:
            log.info("Corporate directory loaded successfully.")
            return json.load(f)
    except FileNotFoundError:
        log.warning("corporate_directory.json not found. Running without user context analysis.")
        return None
    except json.JSONDecodeError:
        log.error("Failed to decode corporate_directory.json. Check for syntax errors.")
        return None

def get_user_privilege_level(username, directory):
    """Finds a user's privilege level from the directory."""
    if not directory or not username:
        return 3 # Default to a low-medium privilege if directory/user is unknown

    user_roles = directory.get('user_roles', {})
    role_permissions = directory.get('role_permissions', {})
    
    user_role = user_roles.get(username, "Standard_User") # Default to Standard_User
    privilege_level = role_permissions.get(user_role, {}).get('privilege_level', 3)
    
    return privilege_level


```



================================================================================
## 📦 core/firewall_manager.py
================================================================================
```py
import subprocess
import os

def block_pid_outbound(pid, log):
    """
    Finds the executable path for a given PID and creates a Windows Firewall rule
    to block all outbound connections for that specific executable.
    """
    try:
        # Use PowerShell to get the full path of the executable from the PID
        # This is more reliable than psutil for system processes
        ps_command = f"(Get-Process -Id {pid}).Path"
        result = subprocess.run(["powershell", "-Command", ps_command], capture_output=True, text=True, check=True)
        exe_path = result.stdout.strip()

        if not exe_path or not os.path.exists(exe_path):
            log.error(f"FIREWALL: Could not find executable path for PID {pid}. Cannot create rule.")
            return False

        exe_name = os.path.basename(exe_path)
        rule_name = f"ShieldAI-Block-{exe_name}-{pid}"

        log.info(f"FIREWALL: Creating outbound block rule for '{exe_path}' (PID: {pid})")

        # Construct the netsh command to add a new firewall rule
        # This rule will block all outbound traffic for the specific program path
        firewall_command = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}",
            "dir=out",
            "action=block",
            f'program="{exe_path}"',
            "enable=yes"
        ]

        # Execute the command with administrator privileges
        subprocess.run(firewall_command, check=True, capture_output=True, text=True)
        
        log.warning(f"FIREWALL: Successfully created rule '{rule_name}'. All outbound connections for '{exe_name}' are now blocked.")
        return True

    except subprocess.CalledProcessError as e:
        # This error often happens if the script is not run as an Administrator
        log.critical(f"FIREWALL: FAILED to create rule. Error: {e.stderr}")
        log.critical("Ensure Shield AI is running with Administrator privileges.")
        return False
    except Exception as e:
        log.error(f"FIREWALL: An unexpected error occurred while creating rule for PID {pid}: {e}")
        return False
```



================================================================================
## 📦 utils/gui_logger.py
================================================================================
```py
import logging

class QueueLogHandler(logging.Handler):
    """
    A custom logging handler that puts messages into a queue for a GUI to process.
    """
    def __init__(self, message_queue):
        super().__init__()
        self.message_queue = message_queue

    def emit(self, record):
        """
        This method is called by the logging framework for each log message.
        """
        log_entry = self.format(record)
        # We put a structured message into the queue for the GUI to process
        self.message_queue.put({'type': 'log', 'data': log_entry})
```



================================================================================
## 📦 utils/helpers.py
================================================================================
```py
import math
from collections import Counter

def calculate_entropy(text):
    """
    Calculates the Shannon entropy of a string.
    High entropy suggests randomness, a potential indicator of malware.
    """
    if not text:
        return 0
    # Get the frequency of each character
    entropy = 0
    text_len = len(text)
    for count in Counter(text).values():
        # calculate probability
        p_x = count / text_len
        # calculate entropy
        entropy += - p_x * math.log2(p_x)
    return entropy
```



================================================================================
## 📦 utils/cef_formatter.py
================================================================================
```py
import datetime

def format_cef(log_level, event_name, message, details=""):
    """
    Formats a log message into the Common Event Format (CEF).
    
    CEF Format: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
    """
    version = "0"
    vendor = "ShieldAI"
    product = "ErevosCore"
    device_version = "2.0"
    
    # Map our internal log levels to CEF severity standard (0-10 integer)
    severity_map = {
        'INFO': '3',
        'WARN': '6',      # Using WARN for GUI alerts
        'CRITICAL': '9'
    }
    severity = severity_map.get(log_level, "1")

    # The CEF standard requires escaping certain characters in the extension field.
    # For our prototype, we will keep it simple.
    
    header = f"CEF:{version}|{vendor}|{product}|{device_version}|{event_name}|{event_name}|{severity}|"
    extension = f"msg={message} {details}"

    return header + extension
```



================================================================================
## 📦 config.ini
================================================================================
```ini
[SHIELD_SETTINGS]
# Time in seconds between each scan cycle.
scan_interval_seconds = 20

# Minimum threat level to trigger a manual alert (LOW, MEDIUM, HIGH, CRITICAL).
alert_threshold = MEDIUM

[IDENTITY]
# The authorized operator of this Shield instance.
creator = Collistus
```



================================================================================
## 📦 policy.ini
================================================================================
```ini
[AUTOMATION_POLICY]
# Set to 'true' to enable autonomous actions, 'false' for manual override only.
enabled = true

# If a process threat score is AT or ABOVE this value, it will be terminated automatically.
# Set to a high value (e.g., 101) to disable auto-termination.
auto_terminate_threshold = 75

# (Future feature) A comma-separated list of vendors to automatically trust.
# auto_trust_vendors = Microsoft Corporation, Google LLC
```



================================================================================
## 📦 corporate_directory.json
================================================================================
```json
{
    "user_roles": {
        "Admin": "Administrator",
        "SYSTEM": "System_Account",
        "j.doe": "Standard_User",
        "s.smith": "Standard_User",
        "m.intern": "Intern_Limited"
    },
    "role_permissions": {
        "Administrator": {
            "privilege_level": 10
        },
        "System_Account": {
            "privilege_level": 10
        },
        "Standard_User": {
            "privilege_level": 5
        },
        "Intern_Limited": {
            "privilege_level": 1
        }
    }
}
```



================================================================================
## 📦 global_intelligence.json
================================================================================
```json
{
    "trusted_processes": [
        "svchost.exe",
        "lsass.exe",
        "wininit.exe",
        "services.exe",
        "explorer.exe",
        "Code.exe",
        "chrome.exe",
        "python.exe"
    ],
    "confirmed_threats": [
        "CodeSetup-stable-f220831ea2d946c0dcb0f3eaa480eb435a2c1260.tmp",
        "CodeSetup-stable-f220831ea2d946c0dcb0f3eaa480eb435a2c1260.exe",
        "com.docker.build.exe"
    ]
}
```



================================================================================
## 📦 payload.py
================================================================================
```py
import time
import os

def malicious_simulation():
    # This simulates a malicious script trying to find sensitive data
    # in a loop, as if it's waiting for an opportunity.
    sensitive_file = os.path.expanduser('~/.ssh/id_rsa')
    if os.path.exists(sensitive_file):
        print("Threat Simulation: Sensitive file detected.")
    else:
        # This will be the normal output
        print("Threat Simulation: Scanning for target files...")

if __name__ == "__main__":
    print("Payload Activated. Running in persistent mode...")
    while True:
        malicious_simulation()
        time.sleep(10) # Run the check every 10 seconds
```



================================================================================
## 📦 requirements.txt
================================================================================
```txt
blinker==1.9.0
certifi==2025.8.3
charset-normalizer==3.4.3
click==8.2.1
colorama==0.4.6
Flask==3.1.1
idna==3.10
itsdangerous==2.2.0
Jinja2==3.1.6
MarkupSafe==3.0.2
psutil==7.0.0
requests==2.32.4
urllib3==2.5.0
Werkzeug==3.1.3

```



================================================================================
## 📦 ../shield_hive/hive_server.py
================================================================================
```py
# File: shield_hive/hive_server.py
from flask import Flask, request, jsonify
import json
import os
from datetime import datetime

app = Flask(__name__)
HIVE_DB = 'hive_database.json'

@app.route('/report', methods=['POST'])
def receive_report():
    report_data = request.json
    if not report_data:
        return jsonify({"status": "error", "message": "No data received"}), 400

    timestamp = datetime.now().isoformat()
    report_data['first_seen'] = timestamp

    print(f"✅ Received threat report from agent: {report_data.get('threat_name')} (Hash: ...{report_data.get('file_hash', '')[-10:]})")

    db = {}
    if os.path.exists(HIVE_DB):
        with open(HIVE_DB, 'r') as f:
            try: db = json.load(f)
            except json.JSONDecodeError: pass

    threat_key = report_data.get('file_hash')
    if threat_key:
        if threat_key not in db:
            db[threat_key] = { "threat_name": report_data.get('threat_name'), "reports": [], "validated": False }
        db[threat_key]["reports"].append(timestamp)
        db[threat_key]["report_count"] = len(db[threat_key]["reports"])

    with open(HIVE_DB, 'w') as f:
        json.dump(db, f, indent=4)

    return jsonify({"status": "success", "message": "Report received"}), 200

if __name__ == '__main__':
    print("🚀 Shield AI Hive Server is online. Awaiting agent reports...")
    app.run(host='0.0.0.0', port=5000)
```
