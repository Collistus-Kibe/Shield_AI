# File: core/usb_sentinel.py
import wmi
import threading
import pythoncom
import ctypes
import time
import winsound  # For the alarm

class USBSentinel:
    def __init__(self, log, digest_callback):
        self.log = log
        self.digest_callback = digest_callback
        self.monitor_thread = None
        self.running = False

    def is_workstation_locked(self):
        """
        Checks if the Windows workstation is currently locked.
        Returns True if locked, False otherwise.
        """
        # Heuristic: If the foreground window is 0, the desktop is usually locked/secure.
        user32 = ctypes.windll.User32
        return user32.GetForegroundWindow() == 0

    def _monitor_loop(self):
        # WMI requires a COM initialization in each thread
        pythoncom.CoInitialize()
        c = wmi.WMI()
        
        # Watch for logical disk creation (USB insertion)
        watcher = c.Win32_VolumeChangeEvent.watch_for(EventType=2) # 2 = Device Arrival
        
        self.log.info("USB SENTINEL: Active and listening for hardware events.")
        
        while self.running:
            try:
                # This blocks until a USB is inserted
                device = watcher(timeout_ms=2000)
                
                # If we are here, a device was inserted
                self.log.warning("USB SENTINEL: Hardware insertion detected!")
                
                # PHYSICAL SECURITY CHECK
                if self.is_workstation_locked():
                    self.trigger_lockdown_protocol()
                else:
                    self.digest_callback("USB Event", "New device inserted while unlocked. Scanning...")
                    # Future: Automatically scan the new drive letter
                    
            except wmi.x_wmi_timed_out:
                continue # No event, loop again
            except Exception as e:
                self.log.error(f"USB SENTINEL ERROR: {e}")

    def trigger_lockdown_protocol(self):
        """
        The 'Headache' Protocol:
        Someone plugged a USB in while the user was away.
        """
        msg = "PHYSICAL ATTACK DETECTED: USB inserted while system locked!"
        self.log.critical(msg)
        self.digest_callback("PHYSICAL BREACH", msg)
        
        # 1. Audible Alarm (Beep continuously to alert anyone nearby)
        for _ in range(5):
            winsound.Beep(1000, 500) # Frequency 1000Hz, Duration 500ms
            
        # 2. (Optional) Force Shutdown to prevent RAM dumping
        # os.system("shutdown /s /t 0") 
        # Note: Commented out for safety during testing. Uncomment for production.

    def start(self):
        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()

    def stop(self):
        self.running = False