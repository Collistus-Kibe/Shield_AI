import threading
import queue
import tkinter as tk
import sys
import logging
from core.shield_backend import ShieldCore
from shield_gui import ShieldGUI

# --- CUSTOM LOG HANDLER ---
class GuiLogHandler(logging.Handler):
    """Intercepts logs and sends them to the GUI queue."""
    def __init__(self, log_queue):
        super().__init__()
        self.log_queue = log_queue
        # Set format to match your screenshot
        self.formatter = logging.Formatter('%(asctime)s - %(message)s', datefmt='%H:%M:%S')

    def emit(self, record):
        try:
            msg = self.format(record)
            # Send to GUI as a 'digest' message
            self.log_queue.put({'type': 'digest', 'data': msg})
        except Exception:
            self.handleError(record)

def main():
    # 1. Create Communication Queues
    gui_to_backend = queue.Queue()
    backend_to_gui = queue.Queue()

    # 2. Setup Logging Bridge
    # This captures logs from "ShieldCore" and sends them to backend_to_gui
    gui_handler = GuiLogHandler(backend_to_gui)
    
    core_logger = logging.getLogger("ShieldCore")
    core_logger.setLevel(logging.INFO)
    core_logger.addHandler(gui_handler)
    
    cef_logger = logging.getLogger("ShieldCEF")
    cef_logger.setLevel(logging.INFO)
    cef_logger.addHandler(gui_handler)

    # Also capture the Master launcher logs
    master_logger = logging.getLogger("ShieldMaster")
    master_logger.setLevel(logging.INFO)
    master_logger.addHandler(gui_handler)

    # 3. Initialize GUI
    root = tk.Tk()
    app = ShieldGUI(root, backend_to_gui, gui_to_backend)

    # 4. Initialize & Start Backend
    backend = ShieldCore(backend_to_gui, gui_to_backend, [core_logger, cef_logger])
    
    backend_thread = threading.Thread(target=backend.run, daemon=True)
    backend_thread.start()

    master_logger.info("🚀 SHIELD AI: Interface & Core Linked.")

    # 5. Run App
    try:
        root.mainloop()
    except KeyboardInterrupt:
        backend.stop()
        sys.exit()

if __name__ == "__main__":
    main()