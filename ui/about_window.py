import shutil
import subprocess
import tkinter as tk

import customtkinter as ctk


LIBREWARD_VERSION = "0.1.0"
CLAMAV_HOMEPAGE = "https://www.clamav.net"
CLAMAV_SOURCE = "https://github.com/Cisco-Talos/clamav"

LICENSE_TEXT = (
    "LibreWard is licensed under the GNU General Public License (GPL).\n"
    "\n"
    "ClamAV is an open-source antivirus engine/toolkit\n"
    "licensed under the GNU General Public License (GPL).\n"
    "ClamAV is developed by Cisco Talos.\n"
    "\n"
    "LibreWard executes ClamAV command-line tools\n"
    "(clamscan, freshclam) to perform scanning and\n"
    "database updates.\n"
    "\n"
    "Windows builds of LibreWard may bundle ClamAV\n"
    "command-line binaries as a third-party component.\n"
    "LibreWard does not claim ownership of ClamAV.\n"
    "\n"
    f"ClamAV homepage:  {CLAMAV_HOMEPAGE}\n"
    f"ClamAV source:    {CLAMAV_SOURCE}"
)


def _run_cmd(*args):
    """Run a command, return stripped stdout or None on failure."""
    try:
        result = subprocess.run(
            list(args), capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    return None


def _find_binary(name):
    """Locate a binary via PATH. Returns path or None."""
    return shutil.which(name)


class AboutWindow(ctk.CTkToplevel):
    def __init__(self, parent):
        super().__init__(parent)

        self.parent = parent
        self.title("About LibreWard")
        self.transient(parent)
        self.geometry("540x540")
        self.resizable(False, False)

        self.after(100, self._center_and_modal)

        clamav_version = _run_cmd("clamscan", "--version")
        clamscan_path = _find_binary("clamscan")
        freshclam_path = _find_binary("freshclam")

        # --- build UI ---
        container = ctk.CTkFrame(self)
        container.pack(fill="both", expand=True, padx=20, pady=20)

        # Title
        ctk.CTkLabel(
            container,
            text=f"LibreWard v{LIBREWARD_VERSION}",
            font=ctk.CTkFont(size=22, weight="bold"),
        ).pack(pady=(0, 4))

        ctk.CTkLabel(
            container,
            text="Open-source security toolkit",
            font=ctk.CTkFont(size=13),
        ).pack(pady=(0, 14))

        # --- ClamAV detection section ---
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
        else:
            ctk.CTkLabel(
                detect_frame,
                text="Version:  not found (clamscan not in PATH)",
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
        ).pack(fill="x", padx=18, pady=(0, 10))

        # --- License section ---
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
