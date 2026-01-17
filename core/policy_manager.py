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