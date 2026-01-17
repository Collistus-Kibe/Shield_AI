import subprocess
import os

def block_pid_outbound(pid, log):
    """Blocks outbound connections for a specific Process ID."""
    try:
        # Get executable path
        cmd = f"(Get-Process -Id {pid}).Path"
        result = subprocess.run(["powershell", "-Command", cmd], capture_output=True, text=True)
        exe_path = result.stdout.strip()

        if not exe_path or not os.path.exists(exe_path): return False

        exe_name = os.path.basename(exe_path)
        rule_name = f"ShieldAI_Block_PID_{pid}_{exe_name}"
        
        # Create Firewall Rule
        subprocess.run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}", "dir=out", "action=block",
            f"program={exe_path}", "enable=yes"
        ], shell=True, check=True)
        
        log.warning(f"FIREWALL: Blocked outbound traffic for {exe_name}.")
        return True
    except Exception as e:
        log.error(f"FIREWALL FAILED: {e}")
        return False

# --- NEW FUNCTION ---
def block_ip_inbound(ip_address, log):
    """
    Creates a high-priority block rule for a specific malicious IP.
    """
    rule_name = f"ShieldAI_Siren_Block_{ip_address}"
    try:
        log.warning(f"FIREWALL: Ejecting intruder {ip_address}...")
        
        # Netsh command to block all traffic FROM this IP
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}",
            "dir=in",
            "action=block",
            f"remoteip={ip_address}",
            "enable=yes"
        ]
        
        subprocess.run(cmd, shell=True, check=True)
        log.critical(f"FIREWALL: {ip_address} has been permanently banned.")
        return True
    except Exception as e:
        log.error(f"FIREWALL ERROR: Could not block IP. {e}")
        return False