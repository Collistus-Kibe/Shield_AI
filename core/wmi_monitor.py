import threading
import pythoncom
import win32com.client
import time

class WMIMonitor:
    def __init__(self, command_queue, log):
        self.command_queue = command_queue
        self.log = log
        self.monitor_thread = None
        self.running = False

    def _monitor_loop(self):
        pythoncom.CoInitialize()
        self.log.info("WMI MONITOR: Hooking Kernel (Raw Mode)...")
        
        try:
            # Connect directly to WMI service
            wmi = win32com.client.GetObject("winmgmts:root\\cimv2")
            # Create the event watcher query
            watcher = wmi.ExecNotificationQuery("SELECT * FROM Win32_ProcessStartTrace")
            self.log.info("WMI MONITOR: Success. Listening for process creation.")
            
            while self.running:
                try:
                    # Wait up to 1000ms for an event
                    event = watcher.NextEvent(1000)
                    # Extract details
                    pid = int(event.ProcessID)
                    name = str(event.ProcessName)
                    
                    self.command_queue.put({
                        'action': 'process_event', 
                        'proc_info': {'pid': pid, 'name': name}
                    })
                except pythoncom.com_error as e:
                    # 0x80041032 is just a timeout (no event), which is normal
                    if e.hresult == -2147217358: continue
        except Exception as e:
            self.log.error(f"WMI MONITOR FAILED: {e}")
        finally:
            pythoncom.CoUninitialize()

    def start(self):
        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()

    def stop(self): self.running = False