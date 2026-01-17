# File: core/ghost_protocol.py
import winreg
import subprocess
import random
import re
import time

# Registry path for Network Adapters
REG_PATH = r"SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}"

def get_random_mac():
    """Generates a random, valid MAC address (Unicast, Locally Administered)."""
    # Second character must be 2, 6, A, or E to be valid on Windows
    second_char = random.choice(['2', '6', 'A', 'E'])
    mac = f"0{second_char}"
    for _ in range(5):
        mac += f"{random.randint(0, 255):02X}"
    return mac

def get_active_adapter_info():
    """Finds the Registry Key for the currently active adapter."""
    try:
        # Get active interface name (e.g., "Wi-Fi")
        cmd = 'netsh interface show interface'
        output = subprocess.check_output(cmd, shell=True).decode()
        active_name = None
        for line in output.splitlines():
            if "Connected" in line:
                # Extract the interface name from the end of the line
                parts = line.split()
                active_name = " ".join(parts[3:]) # Rejoin name parts
                break
        
        if not active_name: return None, None

        # Find matching Registry Key
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, REG_PATH) as key:
            for i in range(100):
                try:
                    subkey_name = winreg.EnumKey(key, i)
                    with winreg.OpenKey(key, subkey_name) as subkey:
                        try:
                            # Check DriverDesc or NetCfgInstanceId to match name
                            # This is a heuristic; Windows mapping is complex.
                            # We will trust the user to have standard drivers.
                            desc, _ = winreg.QueryValueEx(subkey, "DriverDesc")
                            # We return the subkey index (e.g., "0001") and Interface Name
                            return subkey_name, active_name
                        except FileNotFoundError: pass
                except OSError: break
    except Exception: pass
    return None, None

def morph_identity(log):
    """
    Executes the Ghost Protocol: Changes MAC and restarts adapter.
    """
    log.info("GHOST PROTOCOL: Initiating Identity Morph sequence...")
    
    subkey_index, interface_name = get_active_adapter_info()
    if not subkey_index or not interface_name:
        log.error("GHOST FAILED: Could not identify active network adapter.")
        return False

    new_mac = get_random_mac()
    key_path = f"{REG_PATH}\\{subkey_index}"

    try:
        # 1. Write new MAC to Registry
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_WRITE) as key:
            winreg.SetValueEx(key, "NetworkAddress", 0, winreg.REG_SZ, new_mac)
        
        log.info(f"GHOST: Registry updated. New MAC: {new_mac}")
        
        # 2. Restart Adapter to apply changes
        log.info(f"GHOST: Restarting adapter '{interface_name}'...")
        subprocess.run(f'netsh interface set interface "{interface_name}" disable', shell=True)
        time.sleep(2)
        subprocess.run(f'netsh interface set interface "{interface_name}" enable', shell=True)
        
        log.info("GHOST PROTOCOL: Identity Morph Complete.")
        return True

    except Exception as e:
        log.error(f"GHOST FAILED: Registry/Netsh error: {e}")
        return False