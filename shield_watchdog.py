import subprocess
import time
import sys
import os

def hydra_protocol():
    print("🛡️ SHIELD HYDRA: Watchdog active. Protecting the Guardian.")
    
    while True:
        try:
            print(">> Launching Shield Core...")
            # We run the LAUNCHER, not the GUI directly
            p = subprocess.Popen([sys.executable, "shield_launcher.py"])
            p.wait()
        except KeyboardInterrupt:
            print("\n🛑 HYDRA: Manual Override. Shutting down.")
            p.terminate()
            break
        except Exception as e:
            print(f"⚠️ HYDRA ERROR: {e}")
            time.sleep(5)
            
        print("⚠️ SHIELD CRASHED! Restarting in 3 seconds...")
        time.sleep(3)

if __name__ == "__main__":
    hydra_protocol()