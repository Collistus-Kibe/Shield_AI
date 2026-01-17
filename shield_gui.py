import tkinter as tk
from tkinter import font
import threading
import time
import math
import psutil
import queue
import datetime
import socket

# --- THEME: CARBON & ORANGE ---
THEME = {
    "bg": "#121212",          # Carbon Black
    "panel_bg": "#1E1E1E",    # Dark Grey Panel
    "card_bg": "#252526",     # Module Background
    "accent": "#FF5722",      # Vibrant Orange
    "accent_dim": "#D84315",  # Darker Orange
    "text": "#E0E0E0",        # Off-White
    "text_dim": "#9E9E9E",    # Muted Grey
    "success": "#4CAF50",     # Green
    "danger": "#F44336",      # Red
}

class MidnightPanel(tk.Canvas):
    def __init__(self, parent, title, width, height, **kwargs):
        super().__init__(parent, width=width, height=height, bg=THEME["panel_bg"], highlightthickness=0, **kwargs)
        self.width = width
        self.height = height
        self.title = title
        self.draw_interface()

    def draw_interface(self):
        self.create_line(0, 0, self.width, 0, fill=THEME["accent"], width=3)
        self.create_text(20, 25, text=self.title.upper(), fill=THEME["text_dim"], anchor="w", font=("Roboto", 9, "bold"))

class CountermeasureCard(tk.Canvas):
    def __init__(self, parent, title, desc, icon_char, toggle_callback, width=560, height=80):
        super().__init__(parent, width=width, height=height, bg=THEME["panel_bg"], highlightthickness=0)
        self.toggle_callback = toggle_callback 
        self.title = title
        self.desc = desc
        self.icon = icon_char
        self.width = width
        self.height = height
        self.hover = False
        self.active_status = None 
        
        self.bind("<Enter>", self.on_enter)
        self.bind("<Leave>", self.on_leave)
        self.bind("<Button-1>", self.on_click)
        self.draw()

    def set_status(self, status_text):
        self.active_status = status_text
        self.draw()

    def draw(self):
        self.delete("all")
        bg_col = THEME["card_bg"]
        border_col = THEME["success"] if self.active_status else (THEME["accent"] if self.hover else "#333")
        icon_col = THEME["success"] if self.active_status else (THEME["accent"] if self.hover else THEME["text_dim"])
        
        self.create_rectangle(2, 2, self.width-2, self.height-2, fill=bg_col, outline=border_col, width=2 if self.active_status else (1 if self.hover else 0))
        
        self.create_rectangle(0, 0, 70, self.height, fill=bg_col, outline="")
        self.create_text(35, self.height/2, text=self.icon, fill=icon_col, font=("Segoe UI Symbol", 20))
        self.create_line(70, 10, 70, self.height-10, fill="#333", width=1)
        
        self.create_text(85, 25, text=self.title.upper(), fill=THEME["text"], anchor="w", font=("Roboto", 10, "bold"))
        
        if self.active_status:
            self.create_text(85, 50, text=f"✔ ACTIVE: {self.active_status}", fill=THEME["success"], anchor="w", font=("Consolas", 10, "bold"))
        else:
            self.create_text(85, 50, text=self.desc, fill=THEME["text_dim"], anchor="w", font=("Roboto", 9), width=self.width-100)
        
        if self.hover and not self.active_status:
            self.create_text(self.width-30, self.height/2, text="▶", fill=THEME["accent"], font=("Arial", 12))
        elif self.active_status and self.hover:
            self.create_text(self.width-30, self.height/2, text="✖", fill=THEME["danger"], font=("Arial", 12))

    def on_enter(self, e): self.hover = True; self.draw()
    def on_leave(self, e): self.hover = False; self.draw()
    def on_click(self, e): 
        is_currently_on = self.active_status is not None
        self.toggle_callback(is_currently_on)

class PulsingShield(tk.Canvas):
    def __init__(self, parent, width=200, height=200):
        super().__init__(parent, width=width, height=height, bg=THEME["panel_bg"], highlightthickness=0)
        self.cx = width // 2
        self.cy = height // 2
        self.pulse_size = 0
        self.growing = True
        self.animate()

    def draw_shield_path(self, scale=1.0):
        w = 70 * scale
        h = 80 * scale
        pts = [(self.cx - w, self.cy - h*0.7), (self.cx, self.cy - h), (self.cx + w, self.cy - h*0.7), 
               (self.cx + w, self.cy + h*0.2), (self.cx, self.cy + h), (self.cx - w, self.cy + h*0.2)]
        return pts

    def animate(self):
        self.delete("all")
        glow_color = "#FF8A65" 
        self.create_polygon(self.draw_shield_path(scale=1.15 + self.pulse_size), fill=glow_color, outline="", stipple="gray50")
        self.create_polygon(self.draw_shield_path(scale=1.05 + self.pulse_size), fill=THEME["accent"], outline="")
        self.create_polygon(self.draw_shield_path(scale=1.0), fill=THEME["bg"], outline=THEME["accent"], width=3)
        for i in range(0, 200, 20): self.create_line(self.cx-80+i, self.cy-100, self.cx-80+i, self.cy+100, fill=THEME["panel_bg"], width=1)
        self.create_text(self.cx, self.cy-5, text="S", fill=THEME["accent"], font=("Segoe UI", 48, "bold"))
        self.create_text(self.cx, self.cy+45, text="ACTIVE", fill=THEME["success"], font=("Segoe UI", 8, "bold"))
        if self.growing:
            self.pulse_size += 0.005; 
            if self.pulse_size > 0.08: self.growing = False
        else:
            self.pulse_size -= 0.005; 
            if self.pulse_size < 0: self.growing = True
        self.after(40, self.animate)

class ShieldGUI:
    def __init__(self, root, to_gui_queue, from_gui_queue):
        self.root = root
        self.to_gui_queue = to_gui_queue
        self.from_gui_queue = from_gui_queue
        self.root.title("SHIELD AI // ENTERPRISE")
        self.root.geometry("1300x800")
        self.root.configure(bg=THEME["bg"])
        self.cards = {} 
        self.build_header()
        self.build_layout()
        self.listen_for_backend()

    def build_header(self):
        header = tk.Frame(self.root, bg=THEME["bg"], height=80)
        header.pack(fill="x", padx=30, pady=20)
        
        # LEFT: Logo
        tk.Label(header, text="SHIELD AI", fg=THEME["text"], bg=THEME["bg"], font=("Roboto", 24, "bold")).pack(side="left")
        tk.Label(header, text="  //  CARBON PROTOCOL", fg=THEME["accent"], bg=THEME["bg"], font=("Roboto", 10)).pack(side="left", pady=12)

        # RIGHT: Settings Button
        settings_btn = tk.Button(header, text="⚙️ SETTINGS", bg=THEME["panel_bg"], fg=THEME["text"], 
                                 font=("Roboto", 10, "bold"), relief="flat", padx=20, pady=8,
                                 activebackground=THEME["accent"], activeforeground="white",
                                 command=self.open_settings)
        settings_btn.pack(side="right")

    def build_layout(self):
        container = tk.Frame(self.root, bg=THEME["bg"])
        container.pack(fill="both", expand=True, padx=30, pady=10)
        container.grid_columnconfigure(0, weight=1)
        container.grid_columnconfigure(1, weight=1)
        container.grid_rowconfigure(0, weight=1)

        # --- LEFT PANEL ---
        self.p_left = MidnightPanel(container, "SYSTEM INTELLIGENCE", 600, 600)
        self.p_left.grid(row=0, column=0, sticky="nsew", padx=10)
        f_left = tk.Frame(container, bg=THEME["panel_bg"])
        f_left.place(in_=self.p_left, x=20, y=50, relwidth=0.9, relheight=0.9)
        
        f_left_top = tk.Frame(f_left, bg=THEME["panel_bg"])
        f_left_top.place(relx=0, rely=0, relwidth=1, relheight=0.5)
        
        f_badge_area = tk.Frame(f_left_top, bg=THEME["panel_bg"])
        f_badge_area.place(relx=0, rely=0, relwidth=0.5, relheight=1)
        self.badge = PulsingShield(f_badge_area, width=200, height=200)
        self.badge.pack(expand=True)
        
        f_briefing_area = tk.Frame(f_left_top, bg=THEME["panel_bg"])
        f_briefing_area.place(relx=0.5, rely=0, relwidth=0.5, relheight=1)
        tk.Label(f_briefing_area, text="DAILY SECURITY BRIEFING", fg=THEME["accent"], bg=THEME["panel_bg"], font=("Roboto", 9, "bold")).pack(anchor="w", pady=(40, 5))
        now = datetime.datetime.now().strftime("%H:%M")
        tk.Label(f_briefing_area, text=f"[REPORT GENERATED AT {now}]", fg=THEME["text_dim"], bg=THEME["panel_bg"], font=("Consolas", 8)).pack(anchor="w", pady=(0, 15))
        brief_text = "• SYSTEM INTEGRITY: 100%\n• THREATS NEUTRALIZED: 0\n• NETWORK INTRUSIONS: None\n> Recommendation: Maintain posture."
        tk.Label(f_briefing_area, text=brief_text, fg=THEME["text"], bg=THEME["panel_bg"], font=("Roboto", 9), justify="left").pack(anchor="w")

        tk.Frame(f_left, height=1, bg=THEME["text_dim"]).place(relx=0, rely=0.5, relwidth=1)

        f_left_bottom = tk.Frame(f_left, bg=THEME["panel_bg"])
        f_left_bottom.place(relx=0, rely=0.51, relwidth=1, relheight=0.49)
        tk.Label(f_left_bottom, text="NEURAL NETWORK FEED", fg=THEME["accent"], bg=THEME["panel_bg"], font=("Roboto", 8, "bold")).pack(anchor="w", pady=(10, 5))
        self.log_box = tk.Text(f_left_bottom, bg=THEME["bg"], fg=THEME["text"], font=("Consolas", 9), relief="flat", highlightthickness=1, highlightbackground=THEME["accent_dim"])
        self.log_box.pack(fill="both", expand=True, pady=(0, 10))

        # --- RIGHT PANEL ---
        self.p_right = MidnightPanel(container, "ACTIVE DEFENSE OPS", 600, 600)
        self.p_right.grid(row=0, column=1, sticky="nsew", padx=10)
        f_right = tk.Frame(container, bg=THEME["panel_bg"])
        f_right.place(in_=self.p_right, x=20, y=50, relwidth=0.9, relheight=0.9)
        tk.Label(f_right, text="AVAILABLE MODULES", fg=THEME["text_dim"], bg=THEME["panel_bg"]).pack(pady=(20, 10))

        # --- MODULE CARDS ---
        self.cards['tor'] = CountermeasureCard(f_right, "ANONYMITY CIRCUIT (TOR)", "Routes traffic through 3 encrypted nodes.", "🔒", self.toggle_tor)
        self.cards['tor'].pack(pady=5, fill="x")
        
        self.cards['mac'] = CountermeasureCard(f_right, "HARDWARE ID SPOOFER", "Randomizes MAC address to bypass filters.", "🛡️", self.toggle_mac)
        self.cards['mac'].pack(pady=5, fill="x")
        
        self.cards['cloak'] = CountermeasureCard(f_right, "OS TELEMETRY CLOAK", "Suppresses Windows reporting services.", "👻", self.toggle_cloak)
        self.cards['cloak'].pack(pady=5, fill="x")
        
        # Panic button
        tk.Frame(f_right, height=2, bg=THEME["text_dim"]).pack(fill="x", pady=20)
        CountermeasureCard(f_right, "EMERGENCY SMART SCAN", "Deep heuristic scan for active threats.", "⚡", lambda _: self.send('scan_now')).pack(pady=5, fill="x")

    # --- TOGGLE LOGIC ---
    def toggle_tor(self, is_active):
        if is_active:
            self.send('deactivate_evasion')
            self.cards['tor'].set_status(None) 
            self.log("Tor Circuit Deactivated. Original IP Restored.")
        else:
            self.send('activate_evasion')
            self.log("Establishing Tor Circuit...")
            self.cards['tor'].set_status("CONNECTING...")
            self.root.after(1500, lambda: self.cards['tor'].set_status("192.168.TOR.45 (Masked)"))

    def toggle_mac(self, is_active):
        if is_active:
            self.send('deactivate_ghost')
            self.cards['mac'].set_status(None) 
            self.log("Hardware ID Reset to Factory Default.")
        else:
            self.send('activate_ghost')
            self.log("Spoofing Hardware ID...")
            self.root.after(1000, lambda: self.cards['mac'].set_status("DE:AD:BE:EF:CA:FE"))

    def toggle_cloak(self, is_active):
        if is_active:
            self.send('deactivate_autopilot')
            self.cards['cloak'].set_status(None) 
            self.log("Telemetry Cloak Disengaged.")
        else:
            self.send('toggle_autopilot')
            self.log("Disabling Telemetry...")
            self.root.after(1000, lambda: self.cards['cloak'].set_status("Services Blocked: 12"))

    # --- SETTINGS WINDOW ---
    def open_settings(self):
        top = tk.Toplevel(self.root)
        top.title("SHIELD CONFIGURATION")
        top.geometry("500x400")
        top.configure(bg=THEME["bg"])
        
        tk.Label(top, text="SYSTEM PREFERENCES", fg=THEME["text"], bg=THEME["bg"], font=("Roboto", 14, "bold")).pack(pady=20)
        
        f = tk.Frame(top, bg=THEME["bg"])
        f.pack(fill="both", expand=True, padx=40)
        
        def create_toggle(label_text, is_locked=False):
            var = tk.IntVar(value=1 if is_locked else 0)
            state = "disabled" if is_locked else "normal"
            
            cb = tk.Checkbutton(f, text=label_text, variable=var, bg=THEME["bg"], 
                                fg=THEME["text"], 
                                disabledforeground=THEME["success"], # Green when locked to show it's active
                                selectcolor=THEME["panel_bg"], activebackground=THEME["bg"], 
                                activeforeground=THEME["accent"], font=("Roboto", 11), 
                                state=state)
            cb.pack(anchor="w", pady=10)
            return var

        create_toggle("Start Shield AI on System Boot")
        create_toggle("Enable Silent Mode (No Audio Alerts)")
        
        # --- THE NON-NEGOTIABLE SETTING ---
        create_toggle("Upload Threat Reports to Hive Mind (REQUIRED)", is_locked=True)
        
        create_toggle("Allow Auto-Updates")
        
        tk.Frame(f, height=1, bg=THEME["text_dim"]).pack(fill="x", pady=20)
        tk.Label(f, text="ADVANCED", fg=THEME["danger"], bg=THEME["bg"], font=("Roboto", 10, "bold")).pack(anchor="w")
        create_toggle("Enable Kernel-Level Hooks (Experimental)")
        
        tk.Button(top, text="SAVE & CLOSE", command=top.destroy, bg=THEME["accent"], fg="white", 
                  relief="flat", font=("Roboto", 10, "bold"), padx=20, pady=10).pack(pady=20)

    def log(self, msg):
        self.log_box.config(state="normal")
        self.log_box.insert("end", f"> {msg}\n")
        self.log_box.see("end")
        self.log_box.config(state="disabled")

    def send(self, action):
        self.from_gui_queue.put({'action': action})
        self.log(f"COMMAND: {action}")

    def listen_for_backend(self):
        try:
            while not self.to_gui_queue.empty():
                msg = self.to_gui_queue.get_nowait()
                if msg['type'] == 'digest': self.log(msg['data'])
        except queue.Empty: pass
        self.root.after(100, self.listen_for_backend)

if __name__ == "__main__":
    root = tk.Tk()
    app = ShieldGUI(root, queue.Queue(), queue.Queue())
    root.mainloop()