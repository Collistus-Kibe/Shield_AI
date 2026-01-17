# File: core/sandbox_manager.py
import os
import subprocess
import logging

# Common SID for "Everyone" group is S-1-1-0. Using SID is safer than name "Everyone".
EVERYONE_SID = "*S-1-1-0"
SANDBOX_DIR = r"C:\ProgramData\ShieldAI\Sandbox"

def init_sandbox_zone(log):
    """
    Creates the Sandbox folder and applies Ironclad ACLs to deny execution.
    """
    try:
        if not os.path.exists(SANDBOX_DIR):
            os.makedirs(SANDBOX_DIR)
            log.info(f"SANDBOX: Created Dead Zone at {SANDBOX_DIR}")

        # ICACLS Command:
        # /deny Everyone:(OI)(CI)(X) -> Deny Execution to Object and Container (Recursive)
        # /t -> Traverse subfolders (if any)
        # /c -> Continue on error
        cmd = f'icacls "{SANDBOX_DIR}" /deny {EVERYONE_SID}:(OI)(CI)(X) /t /c'
        
        # Run silently
        subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        log.info("SANDBOX: 'Execute' permissions stripped. The cage is active.")
        return True

    except Exception as e:
        log.error(f"SANDBOX ERROR: Could not secure directory. {e}")
        return False

def isolate_file(file_path, log):
    """
    1. Moves the file to the Sandbox.
    2. Adds a specific Windows Firewall block rule for it.
    """
    import shutil
    from datetime import datetime

    try:
        file_name = os.path.basename(file_path)
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        sandboxed_name = f"{timestamp}_{file_name}"
        destination = os.path.join(SANDBOX_DIR, sandboxed_name)

        # 1. Move File
        shutil.move(file_path, destination)
        log.warning(f"SANDBOX: Moved {file_name} to the Dead Zone.")

        # 2. Firewall Block (The Wall)
        # We block OUTBOUND traffic for this specific executable path
        rule_name = f"ShieldAI_Block_{sandboxed_name}"
        fw_cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}",
            "dir=out",
            "action=block",
            f"program={destination}",
            "enable=yes"
        ]
        
        subprocess.run(fw_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        log.info(f"SANDBOX: Firewall wall erected for {sandboxed_name}.")

        return destination

    except Exception as e:
        log.error(f"SANDBOX FAILED: {e}")
        return None