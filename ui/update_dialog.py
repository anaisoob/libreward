"""Reusable modal dialog showing live progress during long operations.

Used by Update ClamAV and Update Database from the Settings page
so the user sees output even when not on the scan page.
"""

import threading
import tkinter as tk

import customtkinter as ctk


BG_COLOR = ("#F4F7F4", "#0F1411")
SURFACE_COLOR = ("#FFFFFF", "#1B221F")
BORDER_COLOR = ("#CCD8D1", "#313D36")
LOG_COLOR = ("#F8FBF9", "#0F1511")
ACCENT_COLOR = ("#247A59", "#2F8F68")
ACCENT_HOVER = ("#1E684C", "#267A58")
TEXT_PRIMARY = ("#17211B", "#F3F7F4")
TEXT_SECONDARY = ("#26362D", "#D8E1DC")
TEXT_MUTED = ("#5F7067", "#93A39A")
WHITE_TEXT = "#FFFFFF"


class UpdateProgressDialog(ctk.CTkToplevel):
    """Modal dialog with live log + activity bar for background operations.

    Usage:
        dialog = UpdateProgressDialog(parent, title="Updating...")
        dialog.run_in_thread(target=my_function, args=(dialog.log,))
        # dialog closes automatically on completion
    """

    def __init__(self, parent, title="Update Progress"):
        super().__init__(parent)

        self.parent = parent
        self.title(title)
        self.transient(parent)
        self.withdraw()
        self.geometry("580x440")
        self.resizable(False, False)
        self.configure(fg_color=BG_COLOR)

        self._running = True

        self._build_ui()
        self.after(100, self._center_and_modal)

    def _build_ui(self):
        container = ctk.CTkFrame(self, fg_color=SURFACE_COLOR, corner_radius=8)
        container.pack(fill="both", expand=True, padx=20, pady=20)

        ctk.CTkLabel(
            container,
            text=self.title(),
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color=TEXT_PRIMARY,
        ).pack(anchor="w", padx=16, pady=(16, 4))

        ctk.CTkLabel(
            container,
            text="Live operation output",
            font=ctk.CTkFont(size=12),
            text_color=TEXT_MUTED,
        ).pack(anchor="w", padx=16, pady=(0, 12))

        # Activity bar
        self._activity = ctk.CTkProgressBar(
            container,
            mode="indeterminate",
            progress_color=ACCENT_COLOR,
        )
        self._activity.pack(fill="x", padx=16, pady=(0, 12))
        self._activity.start()

        self._progress_label = ctk.CTkLabel(
            container,
            text="",
            font=ctk.CTkFont(size=12),
            text_color=TEXT_MUTED,
        )
        self._progress_label.pack(anchor="w", padx=16, pady=(0, 8))

        # Log textbox
        self._log_box = ctk.CTkTextbox(
            container,
            wrap="word",
            corner_radius=8,
            border_width=1,
            border_color=BORDER_COLOR,
            fg_color=LOG_COLOR,
            text_color=TEXT_SECONDARY,
        )
        self._log_box.pack(fill="both", expand=True, padx=16, pady=(0, 14))

        # Close button (disabled until done)
        self._close_btn = ctk.CTkButton(
            container,
            text="Close",
            command=self._close,
            state="disabled",
            height=36,
            corner_radius=8,
            fg_color=ACCENT_COLOR,
            hover_color=ACCENT_HOVER,
            text_color=WHITE_TEXT,
        )
        self._close_btn.pack(pady=(0, 16))

    def log(self, text: str) -> None:
        """Thread-safe: append text to the log box."""
        self.after(0, self._append, text)

    def set_progress(self, done: int, total: int | None) -> None:
        """Thread-safe: switch to determinate download progress."""
        self.after(0, self._set_progress, done, total)

    def _append(self, text: str):
        """Called on the main thread to update the UI."""
        if not self._log_box.winfo_exists():
            return
        self._log_box.insert("end", text)
        self._log_box.see("end")

    def _set_progress(self, done: int, total: int | None) -> None:
        if not self._activity.winfo_exists():
            return
        if total and total > 0:
            self._activity.configure(mode="determinate")
            self._activity.stop()
            self._activity.set(min(done / total, 1.0))
            if total > 1_000_000:
                self._progress_label.configure(
                    text=f"Downloading: {done / 1_000_000:.1f} / {total / 1_000_000:.1f} MB"
                )
            else:
                self._progress_label.configure(
                    text=f"Downloading: {done:,} / {total:,} bytes"
                )
        else:
            self._progress_label.configure(text="Downloading...")

    def done(self):
        """Mark the operation as finished — enables the Close button."""
        self._running = False
        if self._activity.winfo_exists():
            self._activity.stop()
        if self._progress_label.winfo_exists():
            self._progress_label.configure(text="Done")
        if self._close_btn.winfo_exists():
            self._close_btn.configure(state="normal")

    def run_in_thread(self, target, args=()):
        """Run *target* in a background thread.

        *target* receives the dialog's `log` method as its first argument,
        plus any extra *args*. When it returns, `done()` is called.

        Example:
            dialog.run_in_thread(my_func, (extra_arg,))
            # → my_func(dialog.log, extra_arg) is called in a thread
        """

        def wrapper():
            try:
                target(dialog_log=self.log, *args)
            finally:
                self.after(0, self.done)

        thread = threading.Thread(target=wrapper, daemon=True)
        thread.start()

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
        if self._running:
            return  # shouldn't happen — button is disabled
        try:
            self.grab_release()
        except tk.TclError:
            pass
        self.destroy()
