# File: core/config_manager.py
import configparser
import hashlib
import os

CONFIG_FILE = 'config.ini'

def _hash_pin(pin):
    """Creates a secure hash of the PIN."""
    return hashlib.sha256(pin.encode()).hexdigest()

def set_pin(pin, log):
    """Sets a new security PIN."""
    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)
    
    if 'SECURITY' not in config: config.add_section('SECURITY')
    config.set('SECURITY', 'pin_hash', _hash_pin(pin))
    
    try:
        with open(CONFIG_FILE, 'w') as f: config.write(f)
        if log: log.info("CONFIG: Secure PIN set.")
        return True
    except Exception as e:
        if log: log.error(f"CONFIG FAILED: {e}")
        return False

def verify_pin(pin):
    """Verifies if the entered PIN matches the stored hash."""
    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)
    if 'SECURITY' not in config or 'pin_hash' not in config['SECURITY']: return False
    return _hash_pin(pin) == config.get('SECURITY', 'pin_hash')

def is_pin_set():
    """Checks if a PIN has been set up."""
    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)
    return 'SECURITY' in config and 'pin_hash' in config['SECURITY']

# --- NEW FUNCTIONS FOR ARMING PROTOCOL ---

def set_armed_status(is_armed):
    """Persists the Armed/Disarmed state to the config file."""
    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)
    if 'SYSTEM' not in config: config.add_section('SYSTEM')
    config.set('SYSTEM', 'armed', str(is_armed).lower())
    try:
        with open(CONFIG_FILE, 'w') as f: config.write(f)
    except Exception: pass

def is_system_armed():
    """Reads the persistent Armed state."""
    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)
    if 'SYSTEM' in config and 'armed' in config['SYSTEM']:
        return config.get('SYSTEM', 'armed') == 'true'
    return False