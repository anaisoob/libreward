import os
import subprocess
import threading
import queue
import tkinter.filedialog as fd

import customtkinter as ctk

from config import load_config as config_load, save_config as config_save
from backends import backend
from excludes import COMMON_EXCLUDES, get_active_exclude_patterns
from scanner import (
    collect_files,
    build_clamscan_command,
    parse_clamscan_result_line,
    should_log_line,
)
from .about_window import AboutWindow
from .exclude_window import ExcludeWindow
from .scan_result_window import ScanResultWindow


class ClamAVGui(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("LibreWard")
        self.geometry("980x720")

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.process = None
        self.stop_requested = False
        self.output_queue = queue.Queue()

        self.scan_path = ctk.StringVar(value=os.path.expanduser("~"))

        self.total_files = 0
        self.scanned_files = 0
        self.counted_files = set()
        self.summary_started = False

        self.enabled_common_excludes = set()
        self.user_excludes = []
        self.exclude_window = None
        self.about_window = None

        self.load_config()
        self.create_widgets()
        self.update_exclude_summary()
        self.after(100, self.process_output_queue)

    def load_config(self):
        try:
            data = config_load()
            if data is None:
                return

            self.scan_path.set(data.get("scan_path", os.path.expanduser("~")))

            common = data.get("enabled_common_excludes", [])
            self.enabled_common_excludes = {
                item for item in common if item in COMMON_EXCLUDES
            }

            user_excludes = data.get("user_excludes", [])
            self.user_excludes = [
                os.path.abspath(path)
                for path in user_excludes
                if isinstance(path, str)
            ]

        except Exception:
            self.enabled_common_excludes = set()
            self.user_excludes = []

    def save_config(self):
        try:
            data = {
                "scan_path": self.scan_path.get().strip(),
                "enabled_common_excludes": sorted(self.enabled_common_excludes),
                "user_excludes": self.user_excludes,
            }
            config_save(data)
        except Exception as e:
            self.log(f"WARNING: Could not save config: {e}\n")

    def create_widgets(self):
        main = ctk.CTkFrame(self)
        main.pack(fill="both", expand=True, padx=15, pady=15)

        title = ctk.CTkLabel(
            main,
            text="LibreWard",
            font=ctk.CTkFont(size=22, weight="bold"),
        )
        title.pack(pady=(5, 15))

        path_frame = ctk.CTkFrame(main)
        path_frame.pack(fill="x", pady=5)

        ctk.CTkLabel(path_frame, text="Scan folder:", width=120).pack(side="left", padx=8)

        self.path_entry = ctk.CTkEntry(path_frame, textvariable=self.scan_path)
        self.path_entry.pack(side="left", fill="x", expand=True, padx=8, pady=8)

        ctk.CTkButton(
            path_frame,
            text="Choose",
            command=self.choose_scan_folder,
        ).pack(side="left", padx=5)

        ctk.CTkButton(
            path_frame,
            text="Exclude list",
            command=self.open_exclude_window,
        ).pack(side="left", padx=5)

        self.exclude_summary_label = ctk.CTkLabel(
            main,
            text="Excludes: none",
            anchor="w",
        )
        self.exclude_summary_label.pack(fill="x", pady=(4, 8))

        button_frame = ctk.CTkFrame(main)
        button_frame.pack(fill="x", pady=10)

        self.start_button = ctk.CTkButton(
            button_frame,
            text="Start verbose scan",
            command=self.start_scan,
        )
        self.start_button.pack(side="left", padx=8, pady=8)

        self.stop_button = ctk.CTkButton(
            button_frame,
            text="Stop",
            fg_color="darkred",
            hover_color="red",
            command=self.stop_scan,
            state="disabled",
        )
        self.stop_button.pack(side="left", padx=8, pady=8)

        self.clear_button = ctk.CTkButton(
            button_frame,
            text="Clear log",
            command=self.clear_log,
        )
        self.clear_button.pack(side="left", padx=8, pady=8)

        self.about_button = ctk.CTkButton(
            button_frame,
            text="About",
            command=self.open_about_window,
        )
        self.about_button.pack(side="left", padx=8, pady=8)

        self.status_label = ctk.CTkLabel(main, text="Status: ready", anchor="w")
        self.status_label.pack(fill="x", pady=(5, 3))

        self.current_file_label = ctk.CTkLabel(main, text="Current file: -", anchor="w")
        self.current_file_label.pack(fill="x", pady=(0, 5))

        self.progress = ctk.CTkProgressBar(main, mode="determinate")
        self.progress.pack(fill="x", pady=(0, 5))
        self.progress.set(0)

        self.percent_label = ctk.CTkLabel(main, text="0%", anchor="w")
        self.percent_label.pack(fill="x", pady=(0, 5))

        self.activity_label = ctk.CTkLabel(main, text="Activity: idle", anchor="w")
        self.activity_bar = ctk.CTkProgressBar(main, mode="indeterminate")
        self.activity_bar.stop()

        self.log_box = ctk.CTkTextbox(main, wrap="word")
        self.log_box.pack(fill="both", expand=True, pady=5)

    def choose_scan_folder(self):
        folder = fd.askdirectory()
        if folder:
            self.scan_path.set(folder)
            self.save_config()

    def open_exclude_window(self):
        if self.exclude_window is not None and self.exclude_window.winfo_exists():
            self.exclude_window.lift()
            self.exclude_window.focus_force()
            return

        self.exclude_window = ExcludeWindow(self)

    def update_exclude_summary(self):
        common_count = len(self.enabled_common_excludes)
        user_count = len(self.user_excludes)

        parts = []

        if common_count:
            parts.append(f"{common_count} common")

        if user_count:
            parts.append(f"{user_count} user-defined")

        text = "Excludes: none" if not parts else "Excludes: " + ", ".join(parts)
        self.exclude_summary_label.configure(text=text)

    def open_about_window(self):
        if self.about_window is not None and self.about_window.winfo_exists():
            self.about_window.lift()
            self.about_window.focus_force()
            return

        self.about_window = AboutWindow(self)

    def log(self, text):
        self.log_box.insert("end", text)
        self.log_box.see("end")

    def clear_log(self):
        self.log_box.delete("1.0", "end")

    def start_activity(self, text="Activity: running"):
        self.activity_label.configure(text=text)

        if not self.activity_label.winfo_ismapped():
            self.activity_label.pack(fill="x", pady=(0, 3), before=self.log_box)

        if not self.activity_bar.winfo_ismapped():
            self.activity_bar.pack(fill="x", pady=(0, 10), before=self.log_box)

        self.activity_bar.start()

    def stop_activity(self, text="Activity: idle"):
        self.activity_bar.stop()
        self.activity_bar.pack_forget()
        self.activity_label.configure(text=text)
        self.activity_label.pack_forget()

    def start_scan(self):
        path = self.scan_path.get().strip()

        if not path or not os.path.exists(path):
            self.log("ERROR: Scan folder does not exist.\n")
            return

        self.save_config()

        self.stop_requested = False
        self.summary_started = False
        self.total_files = 0
        self.scanned_files = 0
        self.counted_files = set()

        self.progress.set(0)
        self.percent_label.configure(text="0%")
        self.status_label.configure(text="Status: preparing...")
        self.current_file_label.configure(text="Current file: -")
        self.start_activity("Activity: preparing scan...")

        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="normal")

        active_excludes = get_active_exclude_patterns(
            self.enabled_common_excludes, self.user_excludes
        )

        self.log("\n========================================\n")
        self.log("Starting ClamAV verbose scan\n")
        self.log(f"Scan folder: {path}\n")

        if active_excludes:
            self.log("Active excludes:\n")
            for item in active_excludes:
                self.log(f"  - {item}\n")
        else:
            self.log("Active excludes: none\n")

        self.log("Mode: one clamscan process, progress parsed from --verbose output\n")
        self.log("========================================\n\n")

        thread = threading.Thread(
            target=self.run_scan,
            args=(path, active_excludes),
            daemon=True,
        )
        thread.start()

    def run_scan(self, scan_root, exclude_patterns):
        infected_found = False
        errors_found = False
        infected = []
        total = 0

        try:
            self.output_queue.put("Counting files before scan...\n")
            self.output_queue.put(("__STATUS__", "Status: counting files..."))
            self.output_queue.put(("__ACTIVITY__", "Activity: counting files..."))

            files = collect_files(
                scan_root, exclude_patterns, lambda: self.stop_requested
            )
            known_files = set(files)
            total = len(files)

            self.output_queue.put(("__SET_TOTAL__", total))

            if self.stop_requested:
                self.output_queue.put("\nScan stopped while counting files.\n")
                return

            if total == 0:
                self.output_queue.put("No files found.\n")
                return

            self.output_queue.put(f"Files to scan: {total}\n\n")

            cmd = build_clamscan_command(scan_root, exclude_patterns)

            self.output_queue.put("Command:\n")
            self.output_queue.put(" ".join(cmd) + "\n\n")

            self.output_queue.put(("__STATUS__", "Status: scanning..."))
            self.output_queue.put(("__ACTIVITY__", "Activity: clamscan is running..."))

            self.process = backend.start_process(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )

            if self.process.stdout:
                for line in self.process.stdout:
                    if self.stop_requested:
                        break

                    file_path, status = parse_clamscan_result_line(line, known_files)

                    if file_path:
                        if file_path not in self.counted_files:
                            self.counted_files.add(file_path)
                            self.scanned_files += 1

                        self.output_queue.put(("__CURRENT_FILE__", file_path))
                        self.output_queue.put(
                            ("__PROGRESS__", self.scanned_files, total, False)
                        )

                        if "FOUND" in status:
                            infected_found = True
                            infected.append((file_path, status))
                            self.output_queue.put(line)

                        elif "ERROR" in status:
                            errors_found = True
                            self.output_queue.put(line)

                        continue

                    should_log, self.summary_started = should_log_line(
                        line, self.summary_started
                    )
                    if should_log:
                        self.output_queue.put(line)

            if self.process is not None:
                return_code = self.process.wait()
            else:
                return_code = 2

            if not self.stop_requested and return_code in (0, 1):
                self.output_queue.put(("__PROGRESS__", total, total, True))

            if return_code == 1:
                infected_found = True
            elif return_code and return_code > 1:
                errors_found = True

            self.output_queue.put("\n========================================\n")
            self.output_queue.put("GUI RESULT\n")
            self.output_queue.put("========================================\n")

            if self.stop_requested:
                self.output_queue.put("Result: scan stopped by user.\n")
            elif infected_found:
                self.output_queue.put("Result: infected files found!\n")
            elif errors_found:
                self.output_queue.put("Result: scan finished with errors.\n")
            else:
                self.output_queue.put("Result: no infected files found.\n")

        except FileNotFoundError:
            self.output_queue.put("ERROR: clamscan not found. Install ClamAV first.\n")
        except Exception as e:
            self.output_queue.put(f"ERROR: {e}\n")
        finally:
            self.process = None
            result = {
                "infected": infected,
                "total": total,
                "scanned": self.scanned_files,
                "stopped": self.stop_requested,
                "errors": errors_found,
            }
            self.output_queue.put(("__SCAN_DONE__", result))

    def stop_scan(self):
        self.stop_requested = True
        self.log("\nStopping scan...\n")
        self.status_label.configure(text="Status: stopping...")

        if self.activity_label.winfo_ismapped():
            self.activity_label.configure(text="Activity: stopping...")

        if self.process and self.process.poll() is None:
            try:
                backend.stop_process(self.process)
            except Exception as e:
                self.log(f"ERROR while stopping scan: {e}\n")

    def process_output_queue(self):
        try:
            while True:
                msg = self.output_queue.get_nowait()

                if isinstance(msg, tuple) and msg[0] == "__SCAN_DONE__":
                    self.start_button.configure(state="normal")
                    self.stop_button.configure(state="disabled")

                    if self.stop_requested:
                        self.status_label.configure(text="Status: stopped")
                        self.stop_activity("Activity: stopped")
                    else:
                        self.status_label.configure(text="Status: finished")
                        self.stop_activity("Activity: finished")

                    self.current_file_label.configure(text="Current file: -")

                    ScanResultWindow(self, msg[1])

                elif isinstance(msg, tuple) and msg[0] == "__STATUS__":
                    self.status_label.configure(text=msg[1])

                elif isinstance(msg, tuple) and msg[0] == "__ACTIVITY__":
                    self.start_activity(msg[1])

                elif isinstance(msg, tuple) and msg[0] == "__SET_TOTAL__":
                    self.total_files = msg[1]
                    self.scanned_files = 0
                    self.progress.set(0)
                    self.percent_label.configure(text="0%")
                    self.status_label.configure(
                        text=f"Status: found {self.total_files} files"
                    )

                elif isinstance(msg, tuple) and msg[0] == "__PROGRESS__":
                    current, total, finished = msg[1], msg[2], msg[3]

                    if total > 0:
                        raw_percent = current / total

                        if not finished:
                            raw_percent = min(raw_percent, 0.99)

                        self.progress.set(raw_percent)

                        shown_percent = 100 if finished else int(raw_percent * 100)

                        self.percent_label.configure(text=f"{shown_percent}%")
                        self.status_label.configure(
                            text=f"Status: scanning {current} / {total}"
                        )

                elif isinstance(msg, tuple) and msg[0] == "__CURRENT_FILE__":
                    path = msg[1]
                    display = path

                    if len(display) > 125:
                        display = "..." + display[-122:]

                    self.current_file_label.configure(
                        text=f"Current file: {display}"
                    )

                else:
                    self.log(str(msg))

        except queue.Empty:
            pass

        self.after(100, self.process_output_queue)
