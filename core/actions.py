import psutil
import json
import os
import hashlib
import requests
import shutil
import time
from datetime import datetime, UTC

# --- INTERNAL IMPORTS ---
try:
    from .crypto_utils import generate_quantum_signature
except ImportError:
    # Fallback if crypto_utils isn't present yet (prevents crash)
    def generate_quantum_signature(s): return "LEGACY_SIG"

try:
    from .sandbox_manager import isolate_file, restore_file_from_sandbox, delete_file_from_sandbox, SANDBOX_DIR
except ImportError:
    # Fallback sandbox logic if module missing
    SANDBOX_DIR = r"C:\ProgramData\ShieldAI\Sandbox"
    def isolate_file(src, log): return None
    def restore_file_from_sandbox(name, original_path, log): return False
    def delete_file_from_sandbox(name, log): return False

# --- CONFIGURATION ---
USER_TRUST_FILE = 'user_trust.json'
HIVE_SERVER_URL = "http://127.0.0.1:5000/report"
QUARANTINE_MANIFEST = os.path.join(SANDBOX_DIR, 'quarantine_manifest.json')

# API KEY (Must match Hive Server)
API_KEY = "8f4b2e1c9d3a5b7e6f8c1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d"

# --- HELPER FUNCTIONS ---

def _calculate_file_hash(file_path, log):
    """Calculates SHA-256 hash of a file safely."""
    if not os.path.exists(file_path): return None
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        log.error(f"HASH ERROR: {e}")
        return None

def _load_manifest():
    if not os.path.exists(QUARANTINE_MANIFEST): return {}
    try:
        with open(QUARANTINE_MANIFEST, 'r') as f: return json.load(f)
    except Exception: return {}

def _save_manifest(data):
    try:
        with open(QUARANTINE_MANIFEST, 'w') as f: json.dump(data, f, indent=4)
    except Exception: pass

def _terminate_process_by_pid(pid, log):
    """Ruthlessly kills a process."""
    try:
        if pid == 0: return False # Cannot kill system idle
        p = psutil.Process(pid)
        name = p.name()
        p.kill() # Force kill
        log.info(f"TERMINATOR: Process {name} (PID: {pid}) executed.")
        return True
    except psutil.NoSuchProcess:
        return False
    except psutil.AccessDenied:
        log.error(f"TERMINATOR FAILED: Access Denied to PID {pid}. (Rootkit?)")
        return False
    except Exception as e:
        log.error(f"TERMINATOR ERROR: {e}")
        return False

# --- MAIN ACTIONS ---

def report_threat_to_hive(proc, file_path, log):
    """
    Sends encrypted telemetry to the Hive Server.
    """
    if not file_path: return
    
    file_hash = _calculate_file_hash(file_path, log)
    if not file_hash: return

    # Payload
    telemetry = {
        "threat_name": proc.get('name', 'Unknown'),
        "file_hash": file_hash,
        "threat_score": proc.get('threat_score', 0),
        "reasons": proc.get('reasons', [])
    }
    
    # SIGNATURE GENERATION (Quantum Ready)
    # We sign the hash to prove this request came from a valid Shield Agent
    signature = generate_quantum_signature(file_hash)

    headers = {
        'Content-Type': 'application/json',
        'X-API-KEY': API_KEY,
        'X-QUANTUM-SIG': signature
    }

    try:
        log.info(f"HIVE UPLINK: Reporting {proc.get('name')}...")
        response = requests.post(HIVE_SERVER_URL, json=telemetry, headers=headers, timeout=3)
        
        if response.status_code == 200:
            log.info("✅ HIVE ACKNOWLEDGED: Intelligence received.")
        else:
            log.warning(f"HIVE REJECTED: Status {response.status_code}")
            
    except requests.exceptions.RequestException:
        log.warning("HIVE UNREACHABLE: Operating in Autonomous Mode.")

def quarantine_threat(proc, log):
    """
    The Main Defense Routine:
    1. Reports to Hive
    2. Checks if System Critical (Safety)
    3. Kills Process
    4. Moves file to Dead Zone (Sandbox)
    """
    pid = proc.get('pid')
    
    # 1. Identify File Path
    target_file = None
    if proc.get('path'):
        target_file = proc['path']
    elif pid:
        try:
            p = psutil.Process(pid)
            target_file = p.exe()
        except Exception: pass
    
    if not target_file or not os.path.exists(target_file):
        # If we can't find the file, we just kill the process
        if pid: _terminate_process_by_pid(pid, log)
        return False

    # 2. Safety Check (Prevent suicide)
    sys_root = os.environ.get('SystemRoot', 'C:\\Windows').lower()
    if sys_root in os.path.normpath(target_file).lower():
        # NEVER quarantine Windows files. Just kill the process if malicious.
        log.warning(f"SAFETY INTERLOCK: Cannot quarantine system file {target_file}. Terminating process only.")
        if pid: _terminate_process_by_pid(pid, log)
        return True

    # 3. Report to Hive (Before killing, so we have the file)
    report_threat_to_hive(proc, target_file, log)

    # 4. Kill Process
    if pid: _terminate_process_by_pid(pid, log)

    # 5. Isolate (Move to Sandbox)
    # We use the sandbox manager to handle the physical move + permission locking
    sandboxed_path = isolate_file(target_file, log)
    
    if sandboxed_path:
        # Update Manifest
        manifest = _load_manifest()
        file_name = os.path.basename(sandboxed_path)
        manifest[file_name] = {
            "original_path": target_file,
            "date_quarantined": datetime.now(UTC).isoformat(),
            "threat_name": proc.get('name'),
            "threat_score": proc.get('threat_score'),
            "reasons": proc.get('reasons', [])
        }
        _save_manifest(manifest)
        return True
    
    return False

def trust_process(process_name, log):
    """Adds a process name to the User Allowlist."""
    trusted_list = []
    if os.path.exists(USER_TRUST_FILE):
        try:
            with open(USER_TRUST_FILE, 'r') as f: trusted_list = json.load(f)
        except Exception: pass
        
    if process_name not in trusted_list:
        trusted_list.append(process_name)
        try:
            with open(USER_TRUST_FILE, 'w') as f: json.dump(trusted_list, f, indent=4)
            log.info(f"POLICY UPDATE: {process_name} added to Trusted List.")
            return True
        except Exception as e:
            log.error(f"POLICY ERROR: {e}")
    return False

# --- QUARANTINE MANAGEMENT ---

def list_quarantined_files():
    """Returns the manifest of trapped files."""
    return _load_manifest()

def restore_quarantined_file(file_name, log):
    """Restores a file from the Dead Zone to its original location."""
    manifest = _load_manifest()
    if file_name not in manifest: return False
    
    original_path = manifest[file_name]['original_path']
    
    if restore_file_from_sandbox(file_name, original_path, log):
        del manifest[file_name]
        _save_manifest(manifest)
        log.info(f"RESTORE: {file_name} returned to {original_path}")
        return True
    return False

def delete_quarantined_file(file_name, log):
    """Permanently incinerates a file from the Dead Zone."""
    manifest = _load_manifest()
    if file_name in manifest:
        if delete_file_from_sandbox(file_name, log):
            del manifest[file_name]
            _save_manifest(manifest)
            log.info(f"INCINERATED: {file_name} permanently deleted.")
            return True
    return False