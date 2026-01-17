import sys
import os

def get_resource_path(relative_path):
    """
    Get the absolute path to a resource, works for dev and for PyInstaller.
    """
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        # If running as a script, use the current directory
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)