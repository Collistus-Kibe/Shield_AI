import tkinter as tk
from tkinter import ttk, messagebox
from .config_manager import verify_pin

class PINAuthWindow(tk.Toplevel):
    def __init__(self, parent, callback, is_setting_pin=False):
        super().__init__(parent)
        
        # --- THIS IS THE FIX ---
        self.parent = parent  # Save a reference to the parent window
        # --- END FIX ---
        
        self.callback = callback
        self.is_setting_pin = is_setting_pin
        
        self.title("Authorization Required")
        self.geometry("300x150")
        self.resizable(False, False)
        self.configure(bg="#212121")
        self.transient(parent)
        self.grab_set()

        self.style = ttk.Style()
        self.style.configure("TLabel", background="#212121", foreground="#E0E0E0")
        self.style.configure("TButton", padding=5)
        
        if is_setting_pin:
            self.main_label = ttk.Label(self, text="Create your 6-Digit Guardian PIN:", font=("Consolas", 10))
            self.button_text = "Set PIN"
        else:
            self.main_label = ttk.Label(self, text="Enter 6-Digit PIN to Authorize:", font=("Consolas", 10))
            self.button_text = "Authorize"
            
        self.main_label.pack(pady=10)
        
        self.pin_entry = ttk.Entry(self, width=10, font=("Consolas", 12), show="*")
        self.pin_entry.pack(pady=5)
        
        self.submit_button = ttk.Button(self, text=self.button_text, command=self.check_pin)
        self.submit_button.pack(pady=10)
        
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

    def check_pin(self):
        pin = self.pin_entry.get()
        
        if not pin.isdigit() or len(pin) != 6:
            messagebox.showerror("Invalid PIN", "PIN must be exactly 6 digits.", parent=self)
            return

        if self.is_setting_pin:
            self.callback(pin) # Send the new PIN back to be set
            self.destroy()
        else:
            if verify_pin(pin):
                # This line will now work correctly
                self.parent.winfo_toplevel().app_instance.create_pin_session()
                self.callback(True) # Authorization successful
                self.destroy()
            else:
                messagebox.showerror("Access Denied", "Invalid PIN.", parent=self)
                self.callback(False) # Authorization failed

    def on_closing(self):
        """Called when the window is closed."""
        if not self.is_setting_pin:
            self.callback(False) # Report back failure
        self.destroy()