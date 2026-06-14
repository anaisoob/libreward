"""About window for LibreWard — shows version, licensing, and ClamAV info."""

import tkinter as tk

import customtkinter as ctk

from backends import backend
from core.constants import APP_NAME, APP_VERSION, CLAMAV_HOMEPAGE, CLAMAV_SOURCE


LICENSE_TEXT = (
    f"{APP_NAME} is licensed under the GNU General Public License\n"
    "version 2 or later (GPL-2.0-or-later).\n"
    "\n"
    "ClamAV is an open-source antivirus engine/toolkit\n"
    "licensed separately under the GNU General Public License\n"
    "version 2.\n"
    "ClamAV is developed by Cisco Talos.\n"
    "\n"
    f"{APP_NAME} executes ClamAV command-line tools\n"
    "(clamscan, freshclam) to perform scanning and\n"
    "database updates.\n"
    "\n"
    f"Windows builds of {APP_NAME} may bundle ClamAV\n"
    "command-line binaries as a third-party component.\n"
    f"{APP_NAME} does not claim ownership of ClamAV.\n"
    "\n"
    f"ClamAV homepage:  {CLAMAV_HOMEPAGE}\n"
    f"ClamAV source:    {CLAMAV_SOURCE}"
)


class AboutWindow(ctk.CTkToplevel):
    def __init__(self, parent):
        super().__init__(parent)

        self.parent = parent
        self.title(f"About {APP_NAME}")
        self.transient(parent)
        self.withdraw()
        self.geometry("540x560")
        self.resizable(False, False)

        self.after(100, self._center_and_modal)

        # ── detect ClamAV via backend ────────────────────────────
        runtime = backend.detect_clamav_runtime()

        clamav_version = runtime.version
        clamscan_path = runtime.clamscan
        freshclam_path = runtime.freshclam

        # ── build UI ─────────────────────────────────────────────
        container = ctk.CTkFrame(self)
        container.pack(fill="both", expand=True, padx=20, pady=20)

        # Title
        ctk.CTkLabel(
            container,
            text=f"{APP_NAME} v{APP_VERSION}",
            font=ctk.CTkFont(size=22, weight="bold"),
        ).pack(pady=(0, 4))

        ctk.CTkLabel(
            container,
            text="Open-source security toolkit",
            font=ctk.CTkFont(size=13),
        ).pack(pady=(0, 14))

        # ClamAV detection section
        detect_frame = ctk.CTkFrame(container)
        detect_frame.pack(fill="x", pady=(0, 12), padx=5)

        ctk.CTkLabel(
            detect_frame,
            text="ClamAV Detection",
            font=ctk.CTkFont(size=14, weight="bold"),
        ).pack(anchor="w", padx=12, pady=(10, 6))

        if clamav_version:
            ctk.CTkLabel(
                detect_frame,
                text=f"Version:  {clamav_version}",
                font=ctk.CTkFont(size=12),
                anchor="w",
            ).pack(fill="x", padx=18, pady=(0, 2))
            ctk.CTkLabel(
                detect_frame,
                text=f"Source:   {runtime.source}",
                font=ctk.CTkFont(size=12),
                anchor="w",
            ).pack(fill="x", padx=18, pady=(0, 2))
        else:
            ctk.CTkLabel(
                detect_frame,
                text="Version:  not found (no ClamAV detected)",
                font=ctk.CTkFont(size=12),
                anchor="w",
            ).pack(fill="x", padx=18, pady=(0, 2))

        ctk.CTkLabel(
            detect_frame,
            text=f"clamscan:   {clamscan_path or 'not found'}",
            font=ctk.CTkFont(size=12),
            anchor="w",
        ).pack(fill="x", padx=18, pady=(0, 2))

        ctk.CTkLabel(
            detect_frame,
            text=f"freshclam:  {freshclam_path or 'not found'}",
            font=ctk.CTkFont(size=12),
            anchor="w",
        ).pack(fill="x", padx=18, pady=(0, 2))

        # Platform info
        ctk.CTkLabel(
            detect_frame,
            text=f"Platform:  {backend.platform_arch()}",
            font=ctk.CTkFont(size=12),
            anchor="w",
        ).pack(fill="x", padx=18, pady=(0, 2))

        # Data directories
        ctk.CTkLabel(
            detect_frame,
            text=f"Config:    {backend.config_dir()}",
            font=ctk.CTkFont(size=12),
            anchor="w",
        ).pack(fill="x", padx=18, pady=(0, 2))

        ctk.CTkLabel(
            detect_frame,
            text=f"Database:  {backend.db_dir()}",
            font=ctk.CTkFont(size=12),
            anchor="w",
        ).pack(fill="x", padx=18, pady=(0, 10))

        # License section
        license_frame = ctk.CTkFrame(container)
        license_frame.pack(fill="both", expand=True, pady=(0, 12), padx=5)

        ctk.CTkLabel(
            license_frame,
            text="Licensing",
            font=ctk.CTkFont(size=14, weight="bold"),
        ).pack(anchor="w", padx=12, pady=(10, 6))

        textbox = ctk.CTkTextbox(license_frame, wrap="word")
        textbox.pack(fill="both", expand=True, padx=12, pady=(0, 10))
        textbox.insert("1.0", LICENSE_TEXT)
        textbox.configure(state="disabled")

        # Close button
        ctk.CTkButton(
            container,
            text="Close",
            command=self._close,
        ).pack()

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
            self.deiconify()
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
        self.destroy()
