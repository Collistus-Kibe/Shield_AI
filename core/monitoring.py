import psutil
import json
import os
import requests
import joblib
import numpy as np

# Try/Except imports to prevent crashes if dependencies are missing
try:
    from signify.authenticode import AuthenticodeFile, AuthenticodeVerificationResult
    HAS_SIGNIFY = True
except ImportError:
    HAS_SIGNIFY = False

try:
    from utils.helpers import calculate_entropy
except ImportError:
    # Fallback if utils.helpers is missing
    def calculate_entropy(data): return 0

from .directory_services import get_user_privilege_level

# --- CONFIGURATION ---
BASELINE_FILE = "baseline.json"
USER_TRUST_FILE = "user_trust.json"
GLOBAL_INTELLIGENCE_FILE = "global_intelligence.json"
ML_MODEL_PATH = os.path.join('data', 'malware_classifier.joblib')

HIVE_INTELLIGENCE_URL = "http://127.0.0.1:5000/intelligence"
API_KEY = "8f4b2e1c9d3a5b7e6f8c1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d"

TRUSTED_PUBLISHERS = {
    "Microsoft Corporation", "Google LLC", "Docker Inc", "Mozilla Corporation",
    "The Document Foundation", "Oracle Corporation", "VideoLAN",
    "Python Software Foundation", "JetBrains s.r.o.", "VMware, Inc.",
    "GitHub, Inc."
}

def _load_ml_model(log):
    """Safely loads the AI model."""
    try:
        from utils.resource_loader import get_resource_path
        path = get_resource_path(ML_MODEL_PATH)
    except ImportError:
        path = ML_MODEL_PATH
        
    if not os.path.exists(path): return None
    try: return joblib.load(path)
    except Exception: return None

def _extract_pe_features(exe_path):
    """Extracts features from .exe files for the AI."""
    import pefile
    try:
        pe = pefile.PE(exe_path)
        features = []
        features.append(pe.OPTIONAL_HEADER.SizeOfOptionalHeader)
        features.append(pe.OPTIONAL_HEADER.Characteristics)
        features.append(pe.OPTIONAL_HEADER.MajorLinkerVersion)
        features.append(pe.FILE_HEADER.NumberOfSections)
        text_section_entropy = 0
        for section in pe.sections:
            if b'.text' in section.Name:
                text_section_entropy = section.get_entropy()
                break
        features.append(text_section_entropy)
        # Pad features to match model expectation (10 features)
        while len(features) < 10: features.append(0)
        return np.array(features).reshape(1, -1)
    except Exception:
        return None

def _check_digital_signature(exe_path, log):
    """Verifies if a file is signed by a trusted company."""
    if not HAS_SIGNIFY: return False, None
    try:
        with open(exe_path, "rb") as f:
            signed_file = AuthenticodeFile.from_stream(f)
            result_list = list(signed_file.explain_verify())
            if not result_list: return False, None
            if result_list[0] != AuthenticodeVerificationResult.OK: return False, None
            if not signed_file.signatures: return False, None 
            
            signer_info = signed_file.signatures[0].signer_info
            subject_string = signer_info.subject.human_friendly
            
            for trusted_pub in TRUSTED_PUBLISHERS:
                if trusted_pub in subject_string:
                    return True, trusted_pub
            return False, None
    except Exception: return False, None

def sync_global_intelligence(log):
    """Downloads latest threat data from Hive Server."""
    intelligence = {'trusted': set(), 'threats': set()}
    try:
        # Load local cache first
        if os.path.exists(GLOBAL_INTELLIGENCE_FILE):
            with open(GLOBAL_INTELLIGENCE_FILE, 'r') as f:
                data = json.load(f)
            intelligence['trusted'] = set(data.get("trusted_processes", []))
            intelligence['threats'] = set(data.get("confirmed_threats", []))
    except Exception: pass

    # Try to reach server
    headers = {'X-API-KEY': API_KEY}
    try:
        response = requests.get(HIVE_INTELLIGENCE_URL, headers=headers, timeout=2)
        if response.status_code == 200:
            hive_data = response.json()
            intelligence['threats'].update(set(hive_data.get('threats', [])))
            if log: log.info(f"✅ NEURAL LINK: Downloaded {len(hive_data.get('threats', []))} global threats.")
    except Exception: pass
    return intelligence

def get_active_processes():
    process_list = []
    for process in psutil.process_iter(['pid', 'name', 'username', 'ppid']):
        try: process_list.append(process.info)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess): pass
    return process_list

def create_baseline(log):
    if log: log.info("Creating new security baseline...")
    processes = get_active_processes()
    baseline_process_names = {p['name'] for p in processes if p['name']}
    try:
        with open(BASELINE_FILE, 'w') as f: json.dump(list(baseline_process_names), f, indent=4)
        return True
    except Exception: return False

def check_for_new_processes():
    try:
        with open(BASELINE_FILE, 'r') as f: baseline_process_names = set(json.load(f))
    except (FileNotFoundError, json.JSONDecodeError): return []
    
    ALWAYS_ANALYZE = {'python.exe', 'powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe'}
    current_processes = get_active_processes()
    
    results = []
    for p in current_processes:
        if not p.get('name'): continue
        if p['name'] not in baseline_process_names or p['name'] in ALWAYS_ANALYZE:
            results.append(p)
    return results

def analyze_file(file_path, global_intelligence, log, ml_model):
    """Analyzes a static file on disk."""
    score = 0
    reasons = []
    level = "NONE"
    
    if not file_path or not os.path.exists(file_path):
        return 0, "NONE", []

    file_name = os.path.basename(file_path)

    # 1. Global Intelligence Check
    if file_name in global_intelligence.get('threats', set()):
        return 100, "CRITICAL", ["HIVE MIND: Confirmed Global Threat"]

    # 2. Digital Signature Check
    is_trusted_sig, publisher = _check_digital_signature(file_path, log)
    if is_trusted_sig:
        return -100, "SAFE", [f"Trusted Developer Tool: {publisher}"]

    # 3. Predictive AI Check
    features = _extract_pe_features(file_path)
    if ml_model and features is not None:
        try:
            malicious_prob = ml_model.predict_proba(features)[0][1]
            ai_score = int(malicious_prob * 100)
            if ai_score > 60: 
                score += ai_score
                reasons.append(f"Predictive AI: {ai_score}% Malicious Probability")
        except Exception: pass
    
    # 4. Entropy Check
    entropy = calculate_entropy(file_name)
    if entropy > 4.5:
        score += 20
        reasons.append(f"Suspicious filename entropy ({entropy:.2f})")

    if score < 30: level = "LOW"
    elif score < 60: level = "MEDIUM"
    elif score < 80: level = "HIGH"
    else: level = "CRITICAL"

    if not reasons and level != "NONE":
        reasons.append("Heuristic Analysis")

    return score, level, reasons

def analyze_processes(process_list, global_intelligence, corporate_directory, log, ml_model):
    """
    Analyzes running processes.
    SAFEGUARD: Handles None/Empty inputs to prevent crashes.
    """
    if not process_list: return []
    
    analyzed_results = []
    safe_parents = {'explorer.exe', 'svchost.exe', 'services.exe', 'wininit.exe', 'System', 'powershell.exe', 'cmd.exe'}

    for process in process_list:
        if not process: continue # Skip invalid entries

        score = 0
        reasons = []
        level = "NONE"
        
        # Link to File Analyzer
        exe_path = None
        try:
            p = psutil.Process(process['pid'])
            exe_path = p.exe()
        except: pass

        if exe_path and os.path.exists(exe_path):
            try:
                f_score, f_level, f_reasons = analyze_file(exe_path, global_intelligence, log, ml_model)
                if f_level == "SAFE":
                    score = -100; reasons = f_reasons; level = "NONE"
                elif f_score > 0:
                    score = f_score; reasons.extend(f_reasons); level = f_level
            except Exception: pass

        # Heuristics
        if level != "NONE" or score >= 0:
            privilege_level = 10
            if corporate_directory:
                privilege_level = get_user_privilege_level(process.get('username'), corporate_directory)
            
            if process.get('name') in {'powershell.exe', 'cmd.exe', 'python.exe'} and privilege_level < 10:
                score += 40; reasons.append(f"High-risk process (Privilege: {privilege_level})")
            
            if process.get('username') is None:
                score += 30; reasons.append("No user context")

            if score < 0: level = "NONE"
            elif score < 30: level = "LOW"
            elif score < 60: level = "MEDIUM"
            elif score < 90: level = "HIGH"
            else: level = "CRITICAL"

        process['threat_score'] = score
        process['threat_level'] = level
        process['reasons'] = reasons
        analyzed_results.append(process)
        
    return analyzed_results