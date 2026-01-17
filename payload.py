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