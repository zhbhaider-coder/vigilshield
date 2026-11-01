"""VigilShield v2 UI - dark pro dashboard with cyber-girl mascot.

- Mascot (code-drawn PNGs) centered; mood follows app state:
  calm (green), scan (yellow / working), alert (red / threat blocked)
- Live threat map canvas (dotted grid, region labels, radar sweep,
  markers for blocked attacker IPs - positions approximate)
- Attack timeline canvas (recent events as colored dots)
- Quarantine manager (restore / delete), whitelist manager (add / remove)
- Guards panel: USB watch, startup guard, hosts-file guard
- Honesty disclaimer always visible in the footer.

tkinter import is guarded so the module imports cleanly on systems
without a display; run() raises a clear error there.

CLI flags (used by install.bat Task Scheduler tasks):
  --uninstall-rules : remove all VigilShield firewall rules, no GUI
  --exposure-scan   : run exposure scan headless, write report, no GUI
"""
import hashlib
import os
import queue
import sys
import threading

try:
    import tkinter as tk
    from tkinter import filedialog, messagebox, scrolledtext
except ImportError:
    tk = None

from vigilshield import common, monitor, blocker, updater, exposure, guards

BG = "#0d1117"
PANEL = "#161b24"
PANEL2 = "#1c2330"
FG = "#e8edf5"
DIM = "#8b93a5"
ACCENT = "#58c7ff"
GREEN = "#37d67a"
YELLOW = "#f5c542"
RED = "#ff5d5d"

KIND_COLORS = {
    "blocklist_hit": RED,
    "ransomware": RED,
    "suspicious_process": YELLOW,
    "usb_inserted": YELLOW,
}


def _play_alert():
    if not common.IS_WINDOWS:
        return
    try:
        import winsound
        winsound.PlaySound("SystemHand", winsound.SND_ALIAS | winsound.SND_ASYNC)
    except Exception:
        pass


class VigilShieldApp:
    def __init__(self):
        if tk is None:
            raise RuntimeError("tkinter is not available on this system.")
        self.root = tk.Tk()
        self.root.title("VigilShield")
        self.root.geometry("940x680")
        self.root.configure(bg=BG)
        self.events = queue.Queue()
        self.threats_blocked = 0
        self.alerts = 0
        self.level = "green"
        self.markers = []      # threat-map markers
        self.timeline = []     # (time, kind, short)
        self._monitor = None
        self._tray = None
        self._mood_images = {}
        self._load_mascot()
        self._build()
        self._start_monitor()
        self.root.after(500, self._pump_events)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    # ---- mascot ----------------------------------------------------------
    def _load_mascot(self):
        for mood in ("calm", "scan", "alert"):
            try:
                img = tk.PhotoImage(
                    file=common.resource_path("mascot_%s.png" % mood))
                # 400x520 -> 200x260
                img = img.subsample(2, 2)
                self._mood_images[mood] = img
            except Exception as e:
                common.log_event("WARN", "mascot %s failed to load: %s" % (mood, e))

    def _set_mood(self, mood):
        img = self._mood_images.get(mood)
        if img is not None:
            self.mascot_label.config(image=img)
            self.mascot_label.image = img

    # ---- layout ------------------------------------------------------------
    def _build(self):
        # top bar
        top = tk.Frame(self.root, bg=PANEL)
        top.pack(fill="x", padx=10, pady=(10, 6))
        tk.Label(top, text="VIGILSHIELD", font=("Segoe UI", 18, "bold"),
                 bg=PANEL, fg=FG).pack(side="left", padx=12, pady=8)
        self.level_pill = tk.Label(top, text="PROTECTED", font=("Segoe UI", 11, "bold"),
                                   bg=GREEN, fg="#0d1117", padx=14, pady=4)
        self.level_pill.pack(side="right", padx=12)

        main = tk.Frame(self.root, bg=BG)
        main.pack(fill="both", expand=True, padx=10)

        # left column: mascot + status
        left = tk.Frame(main, bg=PANEL, width=260)
        left.pack(side="left", fill="y", padx=(0, 6))
        left.pack_propagate(False)
        self.mascot_label = tk.Label(left, bg=PANEL)
        self.mascot_label.pack(pady=(8, 2))
        self._set_mood("calm")
        self.mascot_name = tk.Label(left, text="GUARDIAN", font=("Segoe UI", 10, "bold"),
                                    bg=PANEL, fg=ACCENT)
        self.mascot_name.pack()
        self.status_var = tk.StringVar(value="Watching network & processes")
        tk.Label(left, textvariable=self.status_var, font=("Segoe UI", 10),
                 bg=PANEL, fg=FG, wraplength=230).pack(pady=4)
        self.count_var = tk.StringVar(value="Threats blocked: 0\nAlerts: 0")
        tk.Label(left, textvariable=self.count_var, font=("Segoe UI", 10),
                 bg=PANEL, fg=DIM, justify="left").pack(pady=4)

        tk.Label(left, text="GUARDS", font=("Segoe UI", 10, "bold"),
                 bg=PANEL, fg=ACCENT).pack(pady=(10, 2), anchor="w", padx=12)
        self.guards_var = tk.StringVar(value="checking...")
        tk.Label(left, textvariable=self.guards_var, font=("Segoe UI", 9),
                 bg=PANEL, fg=DIM, justify="left", wraplength=230).pack(
                     anchor="w", padx=12)
        self._refresh_guards_status()

        # right column: map + timeline + events
        right = tk.Frame(main, bg=BG)
        right.pack(side="left", fill="both", expand=True)

        map_frame = tk.Frame(right, bg=PANEL)
        map_frame.pack(fill="x", pady=(0, 6))
        tk.Label(map_frame, text="LIVE THREAT MAP  (marker positions approximate)",
                 font=("Segoe UI", 9, "bold"), bg=PANEL, fg=DIM).pack(anchor="w", padx=8, pady=(6, 0))
        self.map_canvas = tk.Canvas(map_frame, width=620, height=210,
                                    bg="#0a0e18", highlightthickness=0)
        self.map_canvas.pack(padx=8, pady=6)
        self._radar_angle = 0
        self._draw_map()

        tl_frame = tk.Frame(right, bg=PANEL)
        tl_frame.pack(fill="x", pady=(0, 6))
        tk.Label(tl_frame, text="ATTACK TIMELINE", font=("Segoe UI", 9, "bold"),
                 bg=PANEL, fg=DIM).pack(anchor="w", padx=8, pady=(6, 0))
        self.tl_canvas = tk.Canvas(tl_frame, width=620, height=64,
                                   bg="#0a0e18", highlightthickness=0)
        self.tl_canvas.pack(padx=8, pady=6)
        self._draw_timeline()

        ev_frame = tk.Frame(right, bg=PANEL)
        ev_frame.pack(fill="both", expand=True)
        tk.Label(ev_frame, text="RECENT EVENTS", font=("Segoe UI", 9, "bold"),
                 bg=PANEL, fg=DIM).pack(anchor="w", padx=8, pady=(6, 0))
        self.event_box = scrolledtext.ScrolledText(ev_frame, height=6,
                                                   bg="#0a0e18", fg=FG,
                                                   font=("Consolas", 9))
        self.event_box.pack(fill="both", expand=True, padx=8, pady=6)
        self.event_box.config(state="disabled")

        # buttons
        bar = tk.Frame(self.root, bg=BG)
        bar.pack(fill="x", padx=10, pady=6)
        for text, cmd in [
                ("Exposure scan", self._run_exposure_scan),
                ("Update threat list", self._run_updater),
                ("Quarantine manager", self._quarantine_manager),
                ("Whitelist", self._whitelist_manager),
                ("Startup guard", self._startup_guard),
                ("Hosts file check", self._hosts_check),
                ("Remove firewall rules", self._remove_rules)]:
            tk.Button(bar, text=text, command=cmd, bg=PANEL2, fg=FG,
                      font=("Segoe UI", 9), relief="flat", padx=8,
                      pady=6).pack(side="left", padx=3)

        # honesty footer
        tk.Label(self.root, text=common.HONESTY_NOTE, font=("Segoe UI", 8),
                 bg=BG, fg=DIM, wraplength=900, justify="left").pack(
                     padx=10, pady=(0, 10))

    # ---- threat map ---------------------------------------------------------
    REGIONS = [("NORTH AMERICA", 105, 62), ("SOUTH AMERICA", 150, 158),
               ("EUROPE", 305, 58), ("AFRICA", 310, 118),
               ("ASIA", 440, 74), ("OCEANIA", 520, 168)]

    def _draw_map(self):
        c = self.map_canvas
        c.delete("all")
        Wd, Ht = 620, 210
        # dotted grid
        for x in range(10, Wd, 22):
            for y in range(10, Ht, 22):
                c.create_oval(x, y, x + 2, y + 2, fill="#1a2333", outline="")
        for name, x, y in self.REGIONS:
            c.create_text(x, y, text=name, fill="#2c3a52",
                          font=("Segoe UI", 8, "bold"))
        # radar sweep
        import math
        cx, cy, r = Wd // 2, Ht // 2, 150
        a = math.radians(self._radar_angle)
        c.create_line(cx, cy, cx + r * math.cos(a), cy + r * math.sin(a),
                      fill="#1f6f4a", width=2)
        c.create_oval(cx - 4, cy - 4, cx + 4, cy + 4, fill="#1f6f4a", outline="")
        # markers
        for mk in self.markers[-20:]:
            x, y, ip, tm = mk["x"], mk["y"], mk["ip"], mk["time"]
            c.create_oval(x - 6, y - 6, x + 6, y + 6, fill=RED, outline="#ffaaaa")
            c.create_text(x, y - 12, text=ip, fill="#ffb3b3", font=("Consolas", 7))
        self._radar_angle = (self._radar_angle + 6) % 360
        self.root.after(120, self._draw_map)

    def _add_marker(self, ip, tm):
        h = int(hashlib.sha256(ip.encode()).hexdigest()[:8], 16)
        x = 30 + (h % 560)
        y = 40 + ((h >> 9) % 140)
        self.markers.append({"x": x, "y": y, "ip": ip, "time": tm})

    # ---- timeline -------------------------------------------------------------
    def _draw_timeline(self):
        c = self.tl_canvas
        c.delete("all")
        Wd = 620
        items = self.timeline[-14:]
        n = max(len(items), 1)
        for i, (tm, kind, short) in enumerate(items):
            x = 30 + i * ((Wd - 60) / max(n - 1, 1)) if n > 1 else 30
            color = KIND_COLORS.get(kind, GREEN)
            c.create_oval(x - 7, 20, x + 7, 34, fill=color, outline="")
            c.create_text(x, 48, text=tm[11:] if len(tm) > 11 else tm,
                          fill=DIM, font=("Consolas", 7))
        if not items:
            c.create_text(Wd // 2, 32, text="no events yet - all quiet",
                          fill=DIM, font=("Segoe UI", 9, "italic"))

    # ---- guards status ----------------------------------------------------------
    def _refresh_guards_status(self):
        def work():
            lines = []
            usb = guards.list_removable_drives()
            lines.append("USB watch: %s" % ("watching (%d connected)" % len(usb)
                                            if usb else "watching"))
            hosts = guards.check_hosts()
            lines.append("Hosts file: %s" % ("OK" if not hosts["changed"]
                                             else "CHANGED - review!"))
            try:
                entries = guards.list_startup_entries()
                sus = guards.flag_suspicious_startups(entries)
                lines.append("Startup: %d entries (%d suspicious)" % (len(entries), len(sus)))
            except Exception:
                lines.append("Startup: unavailable")
            self.root.after(0, lambda: self.guards_var.set("\n".join(lines)))
        threading.Thread(target=work, daemon=True).start()

    # ---- monitor wiring -----------------------------------------------------------
    def _start_monitor(self):
        self._monitor = monitor.Monitor(on_event=self.events.put)
        self._monitor.start()
        self._log_ui("VigilShield started. Watching network, processes and USB.")
        self.timeline.append((common.now_stamp(), "info", "started"))
        self._draw_timeline()

    def _pump_events(self):
        try:
            while True:
                ev = self.events.get_nowait()
                self._handle_event(ev)
        except queue.Empty:
            pass
        self.root.after(500, self._pump_events)

    def _handle_event(self, ev):
        kind = ev.get("kind")
        tm = ev.get("time", "")
        self._log_ui("[%s] %s" % (tm, ev["message"]))
        self.timeline.append((tm, kind, ev["message"][:60]))
        self._draw_timeline()
        if kind == "blocklist_hit":
            ip = ev.get("detail", "")
            msg = blocker.handle_blocklist_hit(ev)
            self.threats_blocked += 1
            self._add_marker(ip, tm)
            self._set_level("red", "THREAT BLOCKED")
            self._set_mood("alert")
            self._show_alert("THREAT BLOCKED", ev["message"] + "\n\n" + msg)
        elif kind == "ransomware":
            self.alerts += 1
            self._set_level("red", "POSSIBLE RANSOMWARE")
            self._set_mood("alert")
            self._show_alert("POSSIBLE RANSOMWARE ACTIVITY", ev["message"])
        elif kind == "suspicious_process":
            self.alerts += 1
            self._set_level("yellow", "SUSPICIOUS ACTIVITY")
            self._set_mood("scan")
            self._show_alert("SUSPICIOUS PROGRAM", ev["message"] +
                             "\n\nIf you don't recognise this program, close it. "
                             "It was NOT deleted. You can whitelist it from the "
                             "Whitelist button if it is safe.")
        elif kind == "usb_inserted":
            self.alerts += 1
            self._set_level("yellow", "USB DRIVE CONNECTED")
            self._set_mood("scan")
            self._usb_popup(ev.get("detail", ""))
        self.count_var.set("Threats blocked: %d\nAlerts: %d" % (
            self.threats_blocked, self.alerts))

    def _set_level(self, level, status):
        self.level = level
        colors = {"green": GREEN, "yellow": YELLOW, "red": RED}
        self.level_pill.config(bg=colors[level],
                               text=status if level == "red" else
                               ("CAUTION" if level == "yellow" else "PROTECTED"))
        self.status_var.set(status)

    def _log_ui(self, text):
        self.event_box.config(state="normal")
        self.event_box.insert("end", text + "\n")
        self.event_box.see("end")
        self.event_box.config(state="disabled")

    # ---- alert window ---------------------------------------------------------------
    def _show_alert(self, title, message):
        _play_alert()
        win = tk.Toplevel(self.root)
        win.title("VigilShield ALERT")
        win.configure(bg="#7a0e0e")
        win.geometry("520x360")
        win.attributes("-topmost", True)
        tk.Label(win, text="⚠ " + title, font=("Segoe UI", 20, "bold"),
                 bg="#7a0e0e", fg="white", wraplength=480).pack(pady=16)
        tk.Label(win, text=message, font=("Segoe UI", 11), bg="#7a0e0e",
                 fg="white", wraplength=480, justify="left").pack(padx=16)
        tk.Label(win, text="VigilShield is still watching. You can close this window.",
                 font=("Segoe UI", 9, "italic"), bg="#7a0e0e",
                 fg="#ffd9d9").pack(pady=8)
        tk.Button(win, text="OK - I understand", command=win.destroy,
                  font=("Segoe UI", 12, "bold"), bg="white", fg="#7a0e0e",
                  padx=16, pady=6).pack(pady=10)
        self.root.after(60000, self._calm_down)

    def _calm_down(self):
        if self.level == "red":
            self._set_level("green", "PROTECTED - watching")
            self._set_mood("calm")

    # ---- USB popup ---------------------------------------------------------------------
    def _usb_popup(self, drive):
        win = tk.Toplevel(self.root)
        win.title("USB drive connected")
        win.configure(bg=PANEL)
        win.geometry("440x220")
        win.attributes("-topmost", True)
        tk.Label(win, text="USB drive connected: %s" % drive,
                 font=("Segoe UI", 14, "bold"), bg=PANEL, fg=FG,
                 wraplength=400).pack(pady=14)
        tk.Label(win, text="USB drives are a classic way malware spreads. "
                           "Scan it before opening any files.",
                 font=("Segoe UI", 10), bg=PANEL, fg=DIM,
                 wraplength=400).pack(pady=4)
        out = tk.Label(win, text="", font=("Consolas", 9), bg=PANEL, fg=FG,
                       wraplength=400, justify="left")
        out.pack(pady=4)

        def do_scan():
            out.config(text="Scanning...")
            def work():
                findings = guards.scan_usb_drive(drive)
                txt = "\n".join(findings)
                self.root.after(0, lambda: out.config(text=txt))
                common.log_event("USB", "scanned %s: %s" % (drive, txt[:200]))
            threading.Thread(target=work, daemon=True).start()

        row = tk.Frame(win, bg=PANEL)
        row.pack(pady=8)
        tk.Button(row, text="Scan drive", command=do_scan, bg=ACCENT,
                  fg="#0d1117", font=("Segoe UI", 11, "bold"),
                  padx=12, pady=4).pack(side="left", padx=6)
        tk.Button(row, text="Later", command=win.destroy, bg=PANEL2, fg=FG,
                  font=("Segoe UI", 11), padx=12, pady=4).pack(side="left", padx=6)

    # ---- buttons ---------------------------------------------------------------------------
    def _run_exposure_scan(self):
        self._log_ui("Running exposure scan...")
        self._set_mood("scan")
        self.status_var.set("Scanning for exposures...")

        def work():
            findings = exposure.scan()
            text = exposure.render_text(findings)
            risks = sum(1 for f in findings if f["level"] == "risk")
            def done():
                self._popup("Exposure report", text)
                self._set_mood("calm")
                if risks:
                    self._set_level("yellow", "ACTION NEEDED - see exposure report")
                else:
                    self._set_level("green", "PROTECTED - watching")
            self.root.after(0, done)
        threading.Thread(target=work, daemon=True).start()

    def _run_updater(self):
        self._log_ui("Updating threat list...")

        def work():
            ok, msg = updater.update()
            self.root.after(0, lambda: self._log_ui(msg))
        threading.Thread(target=work, daemon=True).start()

    def _quarantine_manager(self):
        win = tk.Toplevel(self.root)
        win.title("Quarantine manager")
        win.configure(bg=PANEL)
        win.geometry("480x360")
        tk.Label(win, text="Files here were moved, never deleted.",
                 bg=PANEL, fg=DIM, font=("Segoe UI", 9)).pack(pady=6)
        lb = tk.Listbox(win, bg="#0a0e18", fg=FG, font=("Consolas", 10))
        lb.pack(fill="both", expand=True, padx=10)

        def refresh():
            lb.delete(0, "end")
            for i in blocker.list_quarantine():
                lb.insert("end", i)
        refresh()

        def sel():
            s = lb.curselection()
            return lb.get(s[0]) if s else None

        def restore():
            name = sel()
            if not name:
                return
            dest = filedialog.askdirectory(title="Restore '%s' to..." % name)
            if not dest:
                return
            ok, src = blocker.restore_quarantine(name)
            if ok:
                try:
                    import shutil
                    shutil.move(src, os.path.join(dest, name))
                    common.log_event("INFO", "restored %s to %s" % (name, dest))
                    messagebox.showinfo("VigilShield", "Restored to %s." % dest)
                except Exception as e:
                    messagebox.showerror("VigilShield", "Restore failed: %s" % e)
            else:
                messagebox.showerror("VigilShield", src)
            refresh()

        def delete():
            name = sel()
            if not name:
                return
            if messagebox.askyesno("Confirm", "Permanently delete '%s'?" % name):
                ok, msg = blocker.delete_quarantine(name)
                messagebox.showinfo("VigilShield", msg)
                refresh()

        row = tk.Frame(win, bg=PANEL)
        row.pack(pady=8)
        tk.Button(row, text="Restore...", command=restore, bg=ACCENT,
                  fg="#0d1117", padx=10).pack(side="left", padx=4)
        tk.Button(row, text="Delete forever", command=delete, bg=RED,
                  fg="white", padx=10).pack(side="left", padx=4)

    def _whitelist_manager(self):
        win = tk.Toplevel(self.root)
        win.title("Whitelist")
        win.configure(bg=PANEL)
        win.geometry("440x340")
        tk.Label(win, text="Whitelisted IPs / programs are never blocked or flagged.",
                 bg=PANEL, fg=DIM, font=("Segoe UI", 9),
                 wraplength=400).pack(pady=6)
        lb = tk.Listbox(win, bg="#0a0e18", fg=FG, font=("Consolas", 10))
        lb.pack(fill="both", expand=True, padx=10)

        def refresh():
            lb.delete(0, "end")
            for i in sorted(common.load_whitelist()):
                lb.insert("end", i)
        refresh()

        row = tk.Frame(win, bg=PANEL)
        row.pack(pady=6)
        entry = tk.Entry(row, bg="#0a0e18", fg=FG, font=("Consolas", 10), width=26)
        entry.pack(side="left", padx=4)

        def add():
            ok, msg = common.add_whitelist(entry.get())
            messagebox.showinfo("VigilShield", msg)
            entry.delete(0, "end")
            refresh()

        def remove():
            s = lb.curselection()
            if not s:
                return
            ok, msg = common.remove_whitelist(lb.get(s[0]))
            messagebox.showinfo("VigilShield", msg)
            refresh()

        tk.Button(row, text="Add", command=add, bg=GREEN, fg="#0d1117",
                  padx=10).pack(side="left", padx=2)
        tk.Button(row, text="Remove", command=remove, bg=PANEL2, fg=FG,
                  padx=10).pack(side="left", padx=2)

    def _startup_guard(self):
        win = tk.Toplevel(self.root)
        win.title("Startup guard")
        win.configure(bg=PANEL)
        win.geometry("620x400")
        tk.Label(win, text="Programs that start with Windows. [!] = suspicious.",
                 bg=PANEL, fg=DIM, font=("Segoe UI", 9)).pack(pady=6)
        lb = tk.Listbox(win, bg="#0a0e18", fg=FG, font=("Consolas", 9))
        lb.pack(fill="both", expand=True, padx=10)
        entries = []

        def refresh():
            nonlocal_entries = guards.list_startup_entries()
            entries.clear()
            entries.extend(nonlocal_entries)
            sus_names = {e["name"] for e in guards.flag_suspicious_startups(entries)}
            lb.delete(0, "end")
            for e in entries:
                mark = "[!] " if e["name"] in sus_names else "      "
                lb.insert("end", "%s%s  (%s)" % (mark, e["name"], e["location"].split("\\")[-1]))
        refresh()

        def disable():
            s = lb.curselection()
            if not s:
                return
            e = entries[s[0]]
            if messagebox.askyesno("Confirm",
                                   "Disable '%s' from starting with Windows?\n"
                                   "A backup is saved first." % e["name"]):
                ok, msg = guards.disable_startup_entry(e)
                messagebox.showinfo("VigilShield", msg)
                refresh()

        row = tk.Frame(win, bg=PANEL)
        row.pack(pady=8)
        tk.Button(row, text="Disable selected", command=disable, bg=YELLOW,
                  fg="#0d1117", padx=12).pack()
        tk.Label(row, text="Backups: data/startup_backup.json", bg=PANEL,
                 fg=DIM, font=("Segoe UI", 8)).pack(pady=4)

    def _hosts_check(self):
        self._log_ui("Checking hosts file...")

        def work():
            res = guards.check_hosts()
            def done():
                msg = res["message"]
                if res.get("added"):
                    msg += "\n\nNew lines:\n" + "\n".join(res["added"][:20])
                if res["changed"]:
                    if messagebox.askyesno("Hosts file changed",
                                           msg + "\n\nRestore the saved baseline?"):
                        ok, m2 = guards.restore_hosts()
                        messagebox.showinfo("VigilShield", m2)
                else:
                    messagebox.showinfo("VigilShield", msg)
                self._log_ui("Hosts check: " + res["message"])
                self._refresh_guards_status()
            self.root.after(0, done)
        threading.Thread(target=work, daemon=True).start()

    def _remove_rules(self):
        if messagebox.askyesno("Confirm",
                                "Remove ALL VigilShield firewall rules?\n"
                                "This undoes every block VigilShield added."):
            ok, msg = blocker.remove_all_rules()
            messagebox.showinfo("VigilShield", msg)

    def _popup(self, title, text):
        win = tk.Toplevel(self.root)
        win.title(title)
        win.configure(bg=PANEL)
        win.geometry("560x420")
        box = scrolledtext.ScrolledText(win, bg="#0a0e18", fg=FG,
                                        font=("Consolas", 9))
        box.pack(fill="both", expand=True, padx=8, pady=8)
        box.insert("1.0", text)
        box.config(state="disabled")

    # ---- tray ----------------------------------------------------------------------------------
    def _start_tray(self):
        try:
            from pystray import Icon, Menu, MenuItem
            from PIL import Image, ImageDraw
        except Exception as e:
            common.log_event("WARN", "tray unavailable: %s" % e)
            return

        def make_icon(color):
            img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
            d = ImageDraw.Draw(img)
            d.ellipse([8, 8, 56, 56], fill=color)
            return img

        colors = {"green": (55, 214, 122), "yellow": (245, 197, 66),
                  "red": (255, 93, 93)}

        def on_show(icon, item):
            self.root.after(0, self.root.deiconify)

        def on_quit(icon, item):
            icon.stop()
            self.root.after(0, self._quit)

        menu = Menu(MenuItem("Open VigilShield", on_show),
                    MenuItem("Quit", on_quit))
        self._tray = Icon("VigilShield", make_icon(colors["green"]),
                          "VigilShield", menu)

        def refresh():
            while self._tray is not None:
                try:
                    self._tray.icon = make_icon(colors.get(self.level, colors["green"]))
                except Exception:
                    break
                threading.Event().wait(5)

        threading.Thread(target=refresh, daemon=True).start()
        threading.Thread(target=self._tray.run, daemon=True).start()

    def _on_close(self):
        self.root.withdraw()  # minimise to tray instead of quitting

    def _quit(self):
        if self._monitor:
            self._monitor.stop()
        if self._tray:
            try:
                self._tray.stop()
            except Exception:
                pass
        self.root.destroy()

    def run(self):
        self._start_tray()
        self.root.mainloop()


# ---- headless CLI modes (Task Scheduler / uninstaller) -----------------------------
def _cli_uninstall_rules():
    ok, msg = blocker.remove_all_rules()
    print(msg)
    common.log_event("INFO", "uninstall-rules: " + msg)


def _cli_exposure_scan():
    findings = exposure.scan()
    text = exposure.render_text(findings)
    report = os.path.join(common.DATA_DIR, "last_exposure_report.txt")
    try:
        with open(report, "w", encoding="utf-8") as f:
            f.write("VigilShield daily exposure scan - %s\n\n" % common.now_stamp())
            f.write(text)
    except Exception:
        pass
    risks = sum(1 for f in findings if f["level"] == "risk")
    common.log_event("INFO", "scheduled exposure scan: %d risks found" % risks)
    print(text)


def main():
    if "--uninstall-rules" in sys.argv:
        _cli_uninstall_rules()
        return
    if "--exposure-scan" in sys.argv:
        _cli_exposure_scan()
        return
    app = VigilShieldApp()
    app.run()


if __name__ == "__main__":
    main()
