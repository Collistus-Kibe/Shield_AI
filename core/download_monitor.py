# File: core/download_monitor.py
import os
import time
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

class DownloadHandler(FileSystemEventHandler):
    def __init__(self, command_queue, log):
        self.command_queue = command_queue
        self.log = log

    def on_created(self, event):
        self._process(event)

    def on_moved(self, event):
        self._process(event)

    def _process(self, event):
        if event.is_directory: return
        
        filename = os.path.basename(event.src_path)
        
        # Ignore temporary download files (Chrome/Edge/Firefox)
        if filename.endswith('.crdownload') or filename.endswith('.tmp') or filename.endswith('.part'):
            return

        # We wait a moment to ensure the file handle is released by the browser
        time.sleep(1)
        
        self.log.info(f"GATEKEEPER: New download detected: {filename}")
        
        # Send to backend for analysis
        self.command_queue.put({
            'action': 'scan_download',
            'file_path': event.src_path
        })

class DownloadMonitor:
    def __init__(self, command_queue, log):
        self.command_queue = command_queue
        self.log = log
        self.observer = Observer()
        self.downloads_path = os.path.expanduser("~/Downloads")

    def start(self):
        if os.path.exists(self.downloads_path):
            event_handler = DownloadHandler(self.command_queue, self.log)
            self.observer.schedule(event_handler, self.downloads_path, recursive=False)
            self.observer.start()
            self.log.info(f"GATEKEEPER: Monitoring {self.downloads_path}")
        else:
            self.log.warning("GATEKEEPER: Downloads folder not found.")

    def stop(self):
        self.observer.stop()
        self.observer.join()