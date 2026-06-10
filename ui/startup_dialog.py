"""Startup dialog shown when ClamAV runtime is not detected.

Platform behaviour:
  Windows — offers to download ClamAV portable ZIP from GitHub.
  Linux   — shows distro-specific package manager install command.
"""

import threading
import tkinter as tk

import customtkinter as ctk

from backends import backend


BG_COLOR = ("#F4F7F4", "#0F1411")
SURFACE_COLOR = ("#FFFFFF", "#1B221F")
BORDER_COLOR = ("#CCD8D1", "#313D36")
LOG_COLOR = ("#F8FBF9", "#0F1511")
ACCENT_COLOR = ("#247A59", "#2F8F68")
ACCENT_HOVER = ("#1E684C", "#267A58")
WARNING_COLOR = ("#9C651E", "#D79A3F")
TEXT_SECONDARY = ("#26362D", "#D8E1DC")
TEXT_MUTED = ("#5F7067", "#93A39A")
SECONDARY_HOVER = ("#DCE8E1", "#2A352F")
WHITE_TEXT = "#FFFFFF"


class StartupDownloadDialog(ctk.CTkToplevel):
    """Modal dialog for first-run ClamAV install guidance.

    On Windows: auto-download flow with progress bar.
    On Linux:   shows the correct package manager command for the distro.
    """

    def __init__(self, parent, on_done=None):
        super().__init__(parent)

        self.parent = parent
        self.on_done = on_done
        self._result = False

        self.title("ClamAV Not Found - LibreWard Setup")
        self.transient(parent)
        self.resizable(False, False)
        self.configure(fg_color=BG_COLOR)

        if backend.manages_own_runtime():
            self._build_windows_ui()
        else:
            self._build_linux_ui()

        self.after(100, self._center_and_modal)

    @property
    def result(self) -> bool:
        """True if the dialog successfully installed a ClamAV runtime."""
        return self._result

    # ── Windows UI: download flow ──────────────────────────────────

    def _build_windows_ui(self):
        self.geometry("620x480")

        container = ctk.CTkFrame(self, fg_color=SURFACE_COLOR, corner_radius=8)
        container.pack(fill="both", expand=True, padx=24, pady=24)

        ctk.CTkLabel(
            container,
            text="ClamAV Runtime Required",
            font=ctk.CTkFont(size=22, weight="bold"),
            text_color=WARNING_COLOR,
        ).pack(anchor="w", padx=16, pady=(16, 8))

        ctk.CTkLabel(
            container,
            text=backend.runtime_install_instructions(),
            font=ctk.CTkFont(size=13),
            justify="left",
            wraplength=560,
            text_color=TEXT_MUTED,
        ).pack(fill="x", padx=16, pady=(0, 16))

        self._log_box = ctk.CTkTextbox(
            container,
            wrap="word",
            height=120,
            corner_radius=8,
            border_width=1,
            border_color=BORDER_COLOR,
            fg_color=LOG_COLOR,
            text_color=TEXT_SECONDARY,
        )
        self._log_box.pack(fill="both", expand=True, padx=16, pady=(0, 12))

        self._progress = ctk.CTkProgressBar(
            container,
            mode="determinate",
            progress_color=ACCENT_COLOR,
        )
        self._progress.pack(fill="x", padx=16, pady=(0, 6))
        self._progress.set(0)

        self._progress_label = ctk.CTkLabel(
            container, text="", font=ctk.CTkFont(size=12)
        )
        self._progress_label.pack(pady=(0, 12))

        btn_frame = ctk.CTkFrame(container, fg_color="transparent")
        btn_frame.pack(fill="x", padx=16, pady=(0, 16))

        self._download_btn = ctk.CTkButton(
            btn_frame,
            text="Download ClamAV",
            command=self._start_download,
            height=40,
            corner_radius=8,
            fg_color=ACCENT_COLOR,
            hover_color=ACCENT_HOVER,
            text_color=WHITE_TEXT,
        )
        self._download_btn.pack(side="left", padx=(0, 12))

        self._skip_btn = ctk.CTkButton(
            btn_frame,
            text="Skip",
            fg_color="transparent",
            border_width=1,
            border_color=BORDER_COLOR,
            text_color=TEXT_SECONDARY,
            hover_color=SECONDARY_HOVER,
            command=self._close,
        )
        self._skip_btn.pack(side="left", padx=8)

    def _start_download(self):
        self._download_btn.configure(state="disabled")
        self._skip_btn.configure(state="disabled")

        thread = threading.Thread(target=self._run_windows_update, daemon=True)
        thread.start()

    def _run_windows_update(self):
        from core.updater import fetch_manifest, get_platform_entry, perform_update

        try:
            self._log("Fetching update manifest...\n")
            manifest = fetch_manifest()
            platform_entry = get_platform_entry(manifest)

            if platform_entry is None:
                self._log("ERROR: No ClamAV runtime available for your platform.\n")
                self._log("Please install ClamAV manually from https://www.clamav.net\n")
                self.after(0, self._enable_windows_buttons)
                return

            latest_ver = platform_entry.get("latest_version", "unknown")
            self._log(f"Latest ClamAV version: {latest_ver}\n")
            self._log("Starting download...\n")

            error = perform_update(
                platform_entry,
                log=lambda msg: self.after(0, self._log, msg),
                progress=lambda phase, done, total: self.after(
                    0, self._update_progress, done, total
                ),
            )

            if error:
                self._log(f"\n{error}\n")
                self.after(0, self._enable_windows_buttons)
            else:
                self._log("\nClamAV installed successfully!\n")
                self._progress.set(1.0)
                self._progress_label.configure(text="Done")
                self._result = True
                self.after(500, self._close)

        except Exception as e:
            self._log(f"\nERROR: {e}\n")
            self.after(0, self._enable_windows_buttons)

    def _log(self, text: str) -> None:
        self._log_box.insert("end", text)
        self._log_box.see("end")
        self.update_idletasks()

    def _update_progress(self, done, total):
        if total and total > 0:
            fraction = min(done / total, 1.0)
            self._progress.set(fraction)
            if total > 1_000_000:
                done_mb = done / 1_000_000
                total_mb = total / 1_000_000
                self._progress_label.configure(
                    text=f"Downloading: {done_mb:.1f} / {total_mb:.1f} MB"
                )
            else:
                self._progress_label.configure(
                    text=f"Downloading: {done:,} / {total:,} bytes"
                )
        else:
            self._progress_label.configure(text="Downloading...")

    def _enable_windows_buttons(self):
        self._download_btn.configure(state="normal")
        self._skip_btn.configure(state="normal")

    # ── Linux UI: package manager instructions ─────────────────────

    def _build_linux_ui(self):
        self.geometry("600x440")

        container = ctk.CTkFrame(self, fg_color=SURFACE_COLOR, corner_radius=8)
        container.pack(fill="both", expand=True, padx=24, pady=24)

        ctk.CTkLabel(
            container,
            text="ClamAV Not Installed",
            font=ctk.CTkFont(size=22, weight="bold"),
            text_color=WARNING_COLOR,
        ).pack(anchor="w", padx=16, pady=(16, 10))

        # Distro detection result
        from backends.linux import LinuxBackend
        distro_text = backend.runtime_install_instructions()

        textbox = ctk.CTkTextbox(
            container,
            wrap="word",
            corner_radius=8,
            border_width=1,
            border_color=BORDER_COLOR,
            fg_color=LOG_COLOR,
            text_color=TEXT_SECONDARY,
        )
        textbox.pack(fill="both", expand=True, padx=16, pady=(0, 16))
        textbox.insert("1.0", distro_text)
        textbox.configure(state="disabled")

        ctk.CTkLabel(
            container,
            text="LibreWard uses the system ClamAV installation.\n"
                 "ClamAV updates are handled by your package manager.",
            font=ctk.CTkFont(size=12),
            text_color=TEXT_MUTED,
            justify="left",
        ).pack(fill="x", padx=16, pady=(0, 12))

        ctk.CTkButton(
            container,
            text="OK",
            command=self._close,
            height=36,
            width=140,
            corner_radius=8,
            fg_color=ACCENT_COLOR,
            hover_color=ACCENT_HOVER,
            text_color=WHITE_TEXT,
        ).pack(pady=(0, 16))

    # ── shared helpers ─────────────────────────────────────────────

    def _center_and_modal(self):
        self.update_idletasks()
        try:
            self.parent.update_idletasks()
            w = self.winfo_width()
            h = self.winfo_height()
            px = self.parent.winfo_rootx()
            py = self.parent.winfo_rooty()
            pw = self.parent.winfo_width()
            ph = self.parent.winfo_height()

            x = px + (pw - w) // 2
            y = py + (ph - h) // 2
            x = min(max(x, 0), max(self.winfo_screenwidth() - w, 0))
            y = min(max(y, 0), max(self.winfo_screenheight() - h, 0))
            self.geometry(f"{w}x{h}+{x}+{y}")
        except tk.TclError:
            pass

        try:
            self.lift()
            self.focus_force()
            self.grab_set()
        except tk.TclError:
            pass

    def _close(self):
        try:
            self.grab_release()
        except tk.TclError:
            pass

        if self.on_done:
            self.on_done(self._result)

        self.destroy()
