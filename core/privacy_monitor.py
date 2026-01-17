# File: core/privacy_monitor.py
import winreg
import os
import psutil

class PrivacyMonitor:
    def __init__(self, log):
        self.log = log
        self.last_cam_apps = set()
        self.last_mic_apps = set()
        self.last_startup_items = self._snapshot_startup()
        self.log.info("PRIVACY SENTINEL: Initialized.")

    def _get_process_from_path(self, app_path):
        """Helper to find running PID from an executable path."""
        app_name = os.path.basename(app_path).lower()
        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                if proc.info['exe'] and os.path.normpath(proc.info['exe']).lower() == os.path.normpath(app_path).lower():
                    return {'pid': proc.info['pid'], 'name': proc.info['name']}
            except (psutil.NoSuchProcess, psutil.AccessDenied): continue
        return None

    def _check_capability(self, cap_name):
        active_paths = set()
        base_path = f"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\{cap_name}\\NonPackaged"
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, base_path)
            i = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(key, i); i += 1
                    app_path = subkey_name.replace('#', '\\')
                    subkey = winreg.OpenKey(key, subkey_name)
                    try:
                        value, _ = winreg.QueryValueEx(subkey, "LastUsedTimeStop")
                        if value == 0: active_paths.add(app_path)
                    except FileNotFoundError: pass
                    finally: winreg.CloseKey(subkey)
                except OSError: break
            winreg.CloseKey(key)
        except Exception: pass
        return active_paths

    def check_camera(self):
        current_paths = self._check_capability("webcam")
        new_paths = current_paths - self.last_cam_apps
        self.last_cam_apps = current_paths
        
        alerts = []
        for path in new_paths:
            proc_info = self._get_process_from_path(path)
            if proc_info:
                alerts.append(proc_info)
        return alerts

    def check_microphone(self):
        current_paths = self._check_capability("microphone")
        new_paths = current_paths - self.last_mic_apps
        self.last_mic_apps = current_paths
        
        alerts = []
        for path in new_paths:
            proc_info = self._get_process_from_path(path)
            if proc_info:
                alerts.append(proc_info)
        return alerts

    def _snapshot_startup(self):
        # (Keep existing snapshot logic)
        items = set()
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run")
            i = 0
            while True:
                try:
                    name, val, _ = winreg.EnumValue(key, i); items.add(f"REG: {name}"); i += 1
                except OSError: break
            winreg.CloseKey(key)
        except Exception: pass
        startup_folder = os.path.expanduser(r"~\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup")
        if os.path.exists(startup_folder):
            for f in os.listdir(startup_folder): items.add(f"FILE: {f}")
        return items

    def check_startup_changes(self):
        current = self._snapshot_startup()
        new_items = current - self.last_startup_items
        self.last_startup_items = current
        return list(new_items)