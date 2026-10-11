import os
import tkinter as tk
from .file_picker import FilePickerDialog

import customtkinter as ctk

from excludes import get_common_excludes


ACCENT_COLOR = ("#247A59", "#2F8F68")
ACCENT_HOVER = ("#1E684C", "#267A58")
DANGER_COLOR = ("#B54444", "#A53A3A")
DANGER_HOVER = ("#973737", "#C04747")
TEXT_SECONDARY = ("#26362D", "#D8E1DC")
WHITE_TEXT = "#FFFFFF"


class ExcludeWindow(ctk.CTkToplevel):
    def __init__(self, parent):
        super().__init__(parent)

        self.parent = parent
        self.title("Exclude list")
        self.transient(parent)
        self.withdraw()
        self.geometry("860x760")
        self.minsize(780, 680)
        self.protocol("WM_DELETE_WINDOW", self.save_and_close)

        self.common_vars = {}
        self.local_user_excludes = list(parent.user_excludes)

        self.create_widgets()
        self.load_state()

        self.after(100, self.center_on_parent)
        self.after(180, self.make_modal)

    def center_on_parent(self):
        self.update_idletasks()

        try:
            self.parent.update_idletasks()

            width = self.winfo_width()
            height = self.winfo_height()

            px = self.parent.winfo_rootx()
            py = self.parent.winfo_rooty()
            pw = self.parent.winfo_width()
            ph = self.parent.winfo_height()

            screen_width = self.winfo_screenwidth()
            screen_height = self.winfo_screenheight()

            x = px + (pw - width) // 2
            y = py + (ph - height) // 2

            x = min(max(x, 0), max(screen_width - width, 0))
            y = min(max(y, 0), max(screen_height - height, 0))

            self.geometry(f"{width}x{height}+{x}+{y}")
            self.deiconify()
        except tk.TclError:
            pass

    def make_modal(self):
        try:
            self.lift()
            self.focus_force()
            self.grab_set()
        except tk.TclError:
            pass

    def create_widgets(self):
        container = ctk.CTkFrame(self)
        container.pack(fill="both", expand=True, padx=15, pady=15)

        title = ctk.CTkLabel(
            container,
            text="Exclude list",
            font=ctk.CTkFont(size=20, weight="bold"),
        )
        title.pack(anchor="w", pady=(0, 10), padx=10)

        common_frame = ctk.CTkFrame(container)
        common_frame.pack(fill="x", pady=(0, 12), padx=5)

        ctk.CTkLabel(
            common_frame,
            text="Common excludes",
            font=ctk.CTkFont(size=16, weight="bold"),
        ).pack(anchor="w", padx=10, pady=(10, 5))

        for label in get_common_excludes():
            var = tk.BooleanVar(value=False)
            self.common_vars[label] = var

            checkbox = ctk.CTkCheckBox(
                common_frame,
                text=label,
                variable=var,
            )
            checkbox.pack(anchor="w", padx=15, pady=4)

        user_frame = ctk.CTkFrame(container)
        user_frame.pack(fill="both", expand=True, pady=(0, 12), padx=5)

        ctk.CTkLabel(
            user_frame,
            text="User-defined excludes",
            font=ctk.CTkFont(size=16, weight="bold"),
        ).pack(anchor="w", padx=10, pady=(10, 5))

        self.user_scroll = ctk.CTkScrollableFrame(user_frame, height=230)
        self.user_scroll.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        user_buttons = ctk.CTkFrame(user_frame)
        user_buttons.pack(fill="x", padx=10, pady=(0, 10))

        ctk.CTkButton(
            user_buttons,
            text="Add folder",
            fg_color=ACCENT_COLOR,
            hover_color=ACCENT_HOVER,
            text_color=WHITE_TEXT,
            command=self.add_folder_from_window,
        ).pack(side="left", padx=(0, 8))

        ctk.CTkButton(
            user_buttons,
            text="Clear user list",
            fg_color=DANGER_COLOR,
            hover_color=DANGER_HOVER,
            text_color=WHITE_TEXT,
            command=self.clear_user_list,
        ).pack(side="left", padx=8)

        bottom = ctk.CTkFrame(container)
        bottom.pack(fill="x", pady=(8, 0))

        ctk.CTkButton(
            bottom,
            text="Save",
            fg_color=ACCENT_COLOR,
            hover_color=ACCENT_HOVER,
            text_color=WHITE_TEXT,
            command=self.save_and_close,
        ).pack(side="right", padx=8, pady=8)

        ctk.CTkButton(
            bottom,
            text="Cancel",
            fg_color="transparent",
            border_width=1,
            text_color=TEXT_SECONDARY,
            command=self.cancel,
        ).pack(side="right", padx=8, pady=8)

    def load_state(self):
        for label, var in self.common_vars.items():
            var.set(label in self.parent.enabled_common_excludes)

        self.refresh_user_rows()

    def refresh_user_rows(self):
        for child in self.user_scroll.winfo_children():
            child.destroy()

        if not self.local_user_excludes:
            empty = ctk.CTkLabel(
                self.user_scroll,
                text="No user-defined excludes.",
                anchor="w",
            )
            empty.pack(fill="x", padx=8, pady=8)
            return

        for path in self.local_user_excludes:
            row = ctk.CTkFrame(self.user_scroll)
            row.pack(fill="x", padx=5, pady=4)

            label = ctk.CTkLabel(row, text=path, anchor="w")
            label.pack(side="left", fill="x", expand=True, padx=8, pady=6)

            remove_button = ctk.CTkButton(
                row,
                text="Remove",
                width=90,
                fg_color=DANGER_COLOR,
                hover_color=DANGER_HOVER,
                text_color=WHITE_TEXT,
                command=lambda p=path: self.remove_path(p),
            )
            remove_button.pack(side="right", padx=8, pady=6)

    def add_folder_from_window(self):
        folder = FilePickerDialog.ask_directory(
            self,
            title="Add exclude folder",
            start_dir=os.path.expanduser("~"),
        )
        if not folder:
            return

        folder = os.path.abspath(folder)

        if folder not in self.local_user_excludes:
            self.local_user_excludes.append(folder)

        self.refresh_user_rows()

    def remove_path(self, path):
        if path in self.local_user_excludes:
            self.local_user_excludes.remove(path)

        self.refresh_user_rows()

    def clear_user_list(self):
        self.local_user_excludes.clear()
        self.refresh_user_rows()

    def save_and_close(self):
        self.parent.enabled_common_excludes.clear()

        for label, var in self.common_vars.items():
            if var.get():
                self.parent.enabled_common_excludes.add(label)

        self.parent.user_excludes = list(self.local_user_excludes)
        self.parent.update_exclude_summary()
        self.parent.save_config()

        try:
            self.grab_release()
        except tk.TclError:
            pass

        self.destroy()

    def cancel(self):
        try:
            self.grab_release()
        except tk.TclError:
            pass

        self.destroy()
