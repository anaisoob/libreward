"""Reusable CustomTkinter information dialog."""

import tkinter as tk

import customtkinter as ctk


BG_COLOR = ("#F4F7F4", "#0F1411")
SURFACE_COLOR = ("#FFFFFF", "#1B221F")
BORDER_COLOR = ("#CCD8D1", "#313D36")
ENTRY_COLOR = ("#F8FBF9", "#101612")
ACCENT_COLOR = ("#247A59", "#2F8F68")
ACCENT_HOVER = ("#1E684C", "#267A58")
SECONDARY_ACTION = ("#2F6FA3", "#4BA3D8")
SECONDARY_ACTION_HOVER = ("#285F8C", "#388FC3")
TEXT_PRIMARY = ("#17211B", "#F3F7F4")
TEXT_SECONDARY = ("#26362D", "#D8E1DC")
TEXT_MUTED = ("#5F7067", "#93A39A")
WHITE_TEXT = "#FFFFFF"


class InfoDialog(ctk.CTkToplevel):
    """Small modal info dialog matching the main LibreWard UI."""

    def __init__(
        self,
        parent,
        title: str,
        message: str,
        *,
        command_text: str | None = None,
    ):
        super().__init__(parent)

        self.parent = parent
        self._command_text = command_text

        self.title(title)
        self.transient(parent)
        self.geometry("560x360" if command_text else "520x260")
        self.minsize(460, 240)
        self.resizable(False, False)
        self.configure(fg_color=BG_COLOR)

        self._build_ui(title, message)
        self.after(100, self._center_and_modal)

    def _build_ui(self, title: str, message: str) -> None:
        container = ctk.CTkFrame(self, fg_color=SURFACE_COLOR, corner_radius=8)
        container.pack(fill="both", expand=True, padx=20, pady=20)

        ctk.CTkLabel(
            container,
            text=title,
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color=TEXT_PRIMARY,
        ).pack(anchor="w", padx=16, pady=(16, 6))

        ctk.CTkLabel(
            container,
            text=message,
            wraplength=480,
            justify="left",
            font=ctk.CTkFont(size=13),
            text_color=TEXT_SECONDARY,
        ).pack(anchor="w", fill="x", padx=16, pady=(0, 14))

        if self._command_text:
            ctk.CTkLabel(
                container,
                text="Terminal command",
                font=ctk.CTkFont(size=12, weight="bold"),
                text_color=TEXT_MUTED,
            ).pack(anchor="w", padx=16, pady=(0, 6))

            command_row = ctk.CTkFrame(container, fg_color="transparent")
            command_row.pack(fill="x", padx=16, pady=(0, 16))

            entry = ctk.CTkEntry(
                command_row,
                height=36,
                corner_radius=8,
                border_width=1,
                border_color=BORDER_COLOR,
                fg_color=ENTRY_COLOR,
                text_color=TEXT_SECONDARY,
            )
            entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
            entry.insert(0, self._command_text)
            entry.configure(state="readonly")

            ctk.CTkButton(
                command_row,
                text="Copy",
                width=84,
                height=36,
                corner_radius=8,
                fg_color=SECONDARY_ACTION,
                hover_color=SECONDARY_ACTION_HOVER,
                text_color=WHITE_TEXT,
                command=lambda: self._copy_command(entry),
            ).pack(side="right")

        ctk.CTkButton(
            container,
            text="Close",
            height=36,
            width=120,
            corner_radius=8,
            fg_color=ACCENT_COLOR,
            hover_color=ACCENT_HOVER,
            text_color=WHITE_TEXT,
            command=self._close,
        ).pack(side="bottom", pady=(0, 16))

    def _copy_command(self, entry: ctk.CTkEntry) -> None:
        self.clipboard_clear()
        self.clipboard_append(entry.get())

    def _center_and_modal(self) -> None:
        self.update_idletasks()
        try:
            self.parent.update_idletasks()
            width = self.winfo_width()
            height = self.winfo_height()
            px = self.parent.winfo_rootx()
            py = self.parent.winfo_rooty()
            pw = self.parent.winfo_width()
            ph = self.parent.winfo_height()

            x = px + (pw - width) // 2
            y = py + (ph - height) // 2
            x = min(max(x, 0), max(self.winfo_screenwidth() - width, 0))
            y = min(max(y, 0), max(self.winfo_screenheight() - height, 0))
            self.geometry(f"{width}x{height}+{x}+{y}")
        except tk.TclError:
            pass

        try:
            self.lift()
            self.focus_force()
            self.grab_set()
        except tk.TclError:
            pass

    def _close(self) -> None:
        try:
            self.grab_release()
        except tk.TclError:
            pass
        self.destroy()
