import time
import os
import datetime
import configparser
from utils.logger import setup_logger
from core.monitoring import create_baseline, check_for_new_processes, analyze_processes, sync_global_intelligence
from core.actions import terminate_process, trust_process
from core.policy_manager import load_policy
from core.firewall_manager import block_pid_outbound

# --- Configuration Loading ---
config = configparser.ConfigParser()
config.read('config.ini')

CREATOR_IDENTITY = config.get('IDENTITY', 'creator', fallback='Collistus')
SCAN_INTERVAL_SECONDS = config.getint('SHIELD_SETTINGS', 'scan_interval_seconds', fallback=30)
ALERT_THRESHOLD = config.get('SHIELD_SETTINGS', 'alert_threshold', fallback='MEDIUM')

# --- Global State for Dashboard ---
last_scan_time = "Never"
last_status = "Initializing..."
threats_detected_session = 0

def display_dashboard(log):
    """Clears the screen and displays a real-time status dashboard."""
    os.system('cls' if os.name == 'nt' else 'clear')
    current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    print("=======================================================================")
    print(f"  🛡️      S H I E L D   A I   -   O P E R A T O R   D A S H B O A R D      🛡️")
    print("=======================================================================")
    print(f"  Creator: {CREATOR_IDENTITY}        Timestamp: {current_time}")
    print("-----------------------------------------------------------------------")
    print(f"  Last Scan: {last_scan_time}      Session Threats: {threats_detected_session}")
    print(f"  System Status: {last_status}")
    print("-----------------------------------------------------------------------")
    log.info("Displaying recent activity log:")

def run_scan_cycle(log, global_intelligence, policy):
    """Executes a single, complete scan-analyze-respond cycle."""
    global last_scan_time, last_status, threats_detected_session
    
    last_scan_time = datetime.datetime.now().strftime('%H:%M:%S')
    log.info(f"Starting scan at {last_scan_time}...")
    
    new_processes = check_for_new_processes()
    if not new_processes:
        last_status = "✅ SYSTEM NOMINAL. No new processes found."
        return

    analyzed_list = analyze_processes(new_processes, global_intelligence)
    
    threat_order = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    alert_procs = [p for p in analyzed_list if p['threat_level'] != "NONE"]

    if not alert_procs:
        last_status = f"✅ New processes analyzed. No threats detected."
        return

    # Filter for alerts that are significant enough to pause for
    significant_threats = [p for p in alert_procs if threat_order.get(p['threat_level'], 0) >= threat_order.get(ALERT_THRESHOLD, 2)]
    if significant_threats:
        last_status = f"🚨 {len(significant_threats)} THREAT(S) DETECTED! Awaiting command..."
        threats_detected_session += len(significant_threats)
    
    for proc in alert_procs:
        level, score, name, pid = proc['threat_level'], proc['threat_score'], proc['name'], proc['pid']
        reasons = ', '.join(proc['reasons'])

        # Autonomous action for CRITICAL threats and those above the threshold
        if policy.get('enabled') and score >= policy.get('auto_terminate_threshold', 95):
            log.critical(f"AUTONOMOUS ACTION: Threat score {score} exceeds threshold.")
            log.critical(f"Executing neutralization protocol for {name} (PID: {pid}). Reasons: {reasons}")
            block_pid_outbound(pid, log)
            terminate_process(proc, log)
        
        # Manual override for threats that are not handled autonomously but meet the alert threshold
        else:
            if threat_order.get(level, 0) >= threat_order.get(ALERT_THRESHOLD, 2):
                display_dashboard(log)
                log.warning(f"MANUAL ALERT | LVL: {level} | SCORE: {score} | PROC: {name} ({pid})")
                action = input(f"    Action for {name} -> (T)erminate, (A)dd to Trust, (I)gnore: ").lower()
                if action == 't':
                    block_pid_outbound(pid, log)
                    terminate_process(proc, log)
                elif action == 'a':
                    trust_process(name, log)
                else:
                    log.info(f"Ignoring {name} for this session.")

# --- Main Execution Block ---
if __name__ == "__main__":
    log = setup_logger()
    policy = load_policy(log)
    global_intelligence = sync_global_intelligence(log)
    
    if not os.path.exists('baseline.json'):
        os.system('cls' if os.name == 'nt' else 'clear')
        print("--- SHIELD AI FIRST-TIME SETUP ---")
        log.warning("No baseline found. A baseline is a snapshot of a known-safe state.")
        response = input("Would you like to create one now? (y/n): ").lower()
        if response == 'y': create_baseline(log)

    try:
        while True:
            display_dashboard(log)
            run_scan_cycle(log, global_intelligence, policy)
            log.info(f"Scan cycle complete. Entering standby for {SCAN_INTERVAL_SECONDS} seconds...")
            time.sleep(SCAN_INTERVAL_SECONDS)
    except KeyboardInterrupt:
        log.info("\nShutdown signal received from Creator. Disengaging Guardian Protocol.")
        log.info("\n// END OF TRANSMISSION //")