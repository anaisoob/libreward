"""Custom CTk file/directory picker dialog.

Replaces tkinter.filedialog.askdirectory() with a themed, native-feeling
file browser that matches the LibreWard CustomTkinter look.

Usage:
    folder = FilePickerDialog.ask_directory(parent)
    if folder:
        print(f"Selected: {folder}")
"""

from __future__ import annotations

import os
import sys
from typing import Callable

import customtkinter as ctk


# ── helpers ────────────────────────────────────────────────────────────

def _home() -> str:
    return os.path.expanduser("~")


def _is_windows() -> bool:
    return sys.platform == "win32"


def _list_drives() -> list[str]:
    """Return a list of drive roots (Windows) or mount points (Linux)."""
    if _is_windows():
        import string

        drives: list[str] = []
        for letter in string.ascii_uppercase:
            root = f"{letter}:\\"
            if os.path.exists(root):
                drives.append(root)
        return drives

    # Linux – common mount points
    candidates = ["/mnt", "/media", "/run/media"]
    mounts: list[str] = []
    for base in candidates:
        if os.path.isdir(base):
            try:
                for entry in sorted(os.listdir(base)):
                    full = os.path.join(base, entry)
                    if os.path.isdir(full):
                        mounts.append(full)
            except PermissionError:
                pass
    return mounts


# ── icons (emoji fallback – no external icon dependencies) ────────────

FOLDER_ICON = "📁"
FILE_ICON = "📄"
UP_ICON = "⬆"
HOME_ICON = "🏠"
DRIVE_ICON = "💾"
DESKTOP_ICON = "🖥"
DOCUMENTS_ICON = "📋"
DOWNLOADS_ICON = "📥"


# ── dialog ─────────────────────────────────────────────────────────────

class FilePickerDialog(ctk.CTkToplevel):
    """A modal directory picker dialog themed with CustomTkinter.

    Call ``FilePickerDialog.ask_directory(parent)`` to open and block.
    """

    def __init__(
        self,
        parent: ctk.CTk,
        *,
        title: str = "Choose folder",
        start_dir: str | None = None,
        on_pick: Callable[[str | None], None] | None = None,
    ):
        super().__init__(parent)

        self._result: str | None = None
        self._on_pick = on_pick
        self._current_dir = os.path.abspath(start_dir or _home())
        self._history: list[str] = []  # back-stack

        # Window setup
        self.title(title)
        self.transient(parent)
        self.geometry("800x580")
        self.minsize(620, 440)
        self.protocol("WM_DELETE_WINDOW", self._cancel)

        # Build UI
        self._build_sidebar()
        self._build_main_area()
        self._refresh_list()

        # Modal behaviour
        self.after(100, self._center_on_parent)
        self.after(150, self._make_modal)

    # ── static convenience ─────────────────────────────────────────

    @staticmethod
    def ask_directory(
        parent: ctk.CTk,
        *,
        title: str = "Choose folder",
        start_dir: str | None = None,
    ) -> str | None:
        """Open a modal directory picker and return the selected path or None."""
        result_holder: list[str | None] = [None]

        def _on_pick(path: str | None) -> None:
            result_holder[0] = path

        dlg = FilePickerDialog(
            parent, title=title, start_dir=start_dir, on_pick=_on_pick
        )
        dlg.grab_set()
        parent.wait_window(dlg)
        return result_holder[0]

    # ── window positioning ─────────────────────────────────────────

    def _center_on_parent(self) -> None:
        try:
            self.update_idletasks()
            w = self.winfo_width()
            h = self.winfo_height()
            px = self.master.winfo_rootx()
            py = self.master.winfo_rooty()
            pw = self.master.winfo_width()
            ph = self.master.winfo_height()
            sw = self.winfo_screenwidth()
            sh = self.winfo_screenheight()

            x = px + (pw - w) // 2
            y = py + (ph - h) // 2
            x = min(max(x, 0), max(sw - w, 0))
            y = min(max(y, 0), max(sh - h, 0))
            self.geometry(f"{w}x{h}+{x}+{y}")
        except Exception:
            pass

    def _make_modal(self) -> None:
        try:
            self.lift()
            self.focus_force()
            self.grab_set()
        except Exception:
            pass

    # ── sidebar ────────────────────────────────────────────────────

    def _build_sidebar(self) -> None:
        sidebar_w = 190

        sidebar = ctk.CTkFrame(self, width=sidebar_w, corner_radius=0)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)

        # Header
        hdr = ctk.CTkLabel(
            sidebar,
            text="Bookmarks",
            font=ctk.CTkFont(size=14, weight="bold"),
        )
        hdr.pack(anchor="w", padx=16, pady=(18, 10))

        # Separator
        sep = ctk.CTkFrame(sidebar, height=1, fg_color=("gray80", "gray25"))
        sep.pack(fill="x", padx=12, pady=(0, 8))

        # Bookmark buttons
        home_dir = _home()
        bookmarks: list[tuple[str, str, str]] = [
            (f"{HOME_ICON}  Home", home_dir, home_dir),
            (f"{DESKTOP_ICON}  Desktop", os.path.join(home_dir, "Desktop"), "Desktop"),
            (f"{DOCUMENTS_ICON}  Documents", os.path.join(home_dir, "Documents"), "Documents"),
            (f"{DOWNLOADS_ICON}  Downloads", os.path.join(home_dir, "Downloads"), "Downloads"),
            (f"{DRIVE_ICON}  Root", "/" if not _is_windows() else "C:\\", "Root"),
        ]

        for label, path, _name in bookmarks:
            if os.path.isdir(path):
                btn = ctk.CTkButton(
                    sidebar,
                    text=label,
                    anchor="w",
                    height=36,
                    corner_radius=6,
                    fg_color="transparent",
                    text_color=("gray10", "gray90"),
                    hover_color=("gray75", "gray28"),
                    font=ctk.CTkFont(size=12),
                    command=lambda p=path: self._navigate_to(p),
                )
                btn.pack(fill="x", padx=10, pady=2)

        # Drives section (Windows) or mount points (Linux)
        drives = _list_drives()
        if drives:
            # spacer
            ctk.CTkLabel(sidebar, text="").pack(pady=(8, 0))

            drives_hdr = ctk.CTkLabel(
                sidebar,
                text="Drives" if _is_windows() else "Mounts",
                font=ctk.CTkFont(size=12, weight="bold"),
            )
            drives_hdr.pack(anchor="w", padx=16, pady=(4, 4))

            for d in drives:
                display = d.rstrip(os.sep)
                if len(display) > 24:
                    display = "..." + display[-21:]
                btn = ctk.CTkButton(
                    sidebar,
                    text=f"  {DRIVE_ICON}  {display}",
                    anchor="w",
                    height=32,
                    corner_radius=6,
                    fg_color="transparent",
                    text_color=("gray10", "gray90"),
                    hover_color=("gray75", "gray28"),
                    font=ctk.CTkFont(size=12),
                    command=lambda p=d: self._navigate_to(p),
                )
                btn.pack(fill="x", padx=10, pady=1)

        # Spacer for bottom
        ctk.CTkLabel(sidebar, text="").pack(expand=True, pady=(6, 0))

    # ── main area ──────────────────────────────────────────────────

    def _build_main_area(self) -> None:
        main = ctk.CTkFrame(self)
        main.pack(side="left", fill="both", expand=True)

        # ── Path bar ──────────────────────────────────────────────
        path_frame = ctk.CTkFrame(main, fg_color="transparent")
        path_frame.pack(fill="x", padx=12, pady=(14, 4))

        # Up / back button
        self._up_btn = ctk.CTkButton(
            path_frame,
            text=f"{UP_ICON}  Up",
            width=60,
            height=32,
            corner_radius=6,
            command=self._go_up,
        )
        self._up_btn.pack(side="left", padx=(0, 6))

        # Back button
        self._back_btn = ctk.CTkButton(
            path_frame,
            text="← Back",
            width=60,
            height=32,
            corner_radius=6,
            command=self._go_back,
            state="disabled",
        )
        self._back_btn.pack(side="left", padx=(0, 8))

        # Path entry
        self._path_var = ctk.StringVar(value=self._current_dir)
        self._path_entry = ctk.CTkEntry(
            path_frame,
            textvariable=self._path_var,
            height=32,
        )
        self._path_entry.pack(side="left", fill="x", expand=True, padx=(0, 6))
        self._path_entry.bind("<Return>", lambda _e: self._on_path_entered())

        # Go button
        go_btn = ctk.CTkButton(
            path_frame,
            text="Go",
            width=46,
            height=32,
            corner_radius=6,
            command=self._on_path_entered,
        )
        go_btn.pack(side="left")

        # ── Separator ─────────────────────────────────────────────
        sep = ctk.CTkFrame(main, height=1, fg_color=("gray80", "gray25"))
        sep.pack(fill="x", padx=12, pady=(6, 2))

        # ── Header row (Name / Size) ──────────────────────────────
        header_row = ctk.CTkFrame(main, fg_color="transparent")
        header_row.pack(fill="x", padx=16, pady=(4, 2))

        ctk.CTkLabel(
            header_row,
            text="Name",
            font=ctk.CTkFont(size=11, weight="bold"),
            width=360,
            anchor="w",
        ).pack(side="left")

        ctk.CTkLabel(
            header_row,
            text="Type",
            font=ctk.CTkFont(size=11, weight="bold"),
            width=120,
            anchor="w",
        ).pack(side="left", padx=(20, 0))

        # ── File list ─────────────────────────────────────────────
        self._list_frame = ctk.CTkScrollableFrame(main)
        self._list_frame.pack(fill="both", expand=True, padx=8, pady=(0, 2))

        # Status label (current directory item count)
        self._status_label = ctk.CTkLabel(
            main,
            text="",
            font=ctk.CTkFont(size=11),
            anchor="w",
        )
        self._status_label.pack(fill="x", padx=16, pady=(2, 2))

        # ── Bottom action row (inside main area) ──────────────────
        action_row = ctk.CTkFrame(main, fg_color="transparent")
        action_row.pack(fill="x", padx=12, pady=(2, 10))

        # Selected path display
        self._selected_label = ctk.CTkLabel(
            action_row,
            text="",
            font=ctk.CTkFont(size=11),
            text_color=("gray40", "gray60"),
            anchor="w",
        )
        self._selected_label.pack(side="left", fill="x", expand=True, padx=(4, 12))

        ctk.CTkButton(
            action_row,
            text="Select this folder",
            command=self._select_current,
            height=34,
        ).pack(side="right", padx=4)

        ctk.CTkButton(
            action_row,
            text="Cancel",
            command=self._cancel,
            height=34,
            fg_color="transparent",
            border_width=1,
            text_color=("gray10", "gray90"),
        ).pack(side="right", padx=4)

    # ── navigation ─────────────────────────────────────────────────

    def _navigate_to(self, path: str) -> None:
        """Navigate to *path*, pushing current dir onto back-stack."""
        path = os.path.abspath(path)
        if not os.path.isdir(path):
            return

        # Only push history if actually changing
        if self._current_dir != path:
            self._history.append(self._current_dir)
            self._current_dir = path

        self._path_var.set(path)
        self._refresh_list()
        self._update_nav_buttons()

    def _go_up(self) -> None:
        parent = os.path.dirname(self._current_dir)
        if parent and parent != self._current_dir and os.path.isdir(parent):
            self._history.append(self._current_dir)  # save current before going up
            self._current_dir = parent
            self._path_var.set(parent)
            self._refresh_list()
            self._update_nav_buttons()

    def _go_back(self) -> None:
        if not self._history:
            return
        prev = self._history.pop()
        self._current_dir = prev
        self._path_var.set(prev)
        self._refresh_list()
        self._update_nav_buttons()

    def _on_path_entered(self) -> None:
        raw = self._path_var.get().strip()
        path = os.path.abspath(os.path.expanduser(raw)) if raw else self._current_dir
        self._navigate_to(path)

    def _update_nav_buttons(self) -> None:
        if self._history:
            self._back_btn.configure(state="normal")
        else:
            self._back_btn.configure(state="disabled")

        # Disable "Up" if at filesystem root
        parent = os.path.dirname(self._current_dir)
        if not parent or parent == self._current_dir:
            self._up_btn.configure(state="disabled")
        else:
            self._up_btn.configure(state="normal")

    # ── listing ────────────────────────────────────────────────────

    def _refresh_list(self) -> None:
        """Re-populate the scrollable file list from *_current_dir*."""
        # Clear existing
        for child in self._list_frame.winfo_children():
            child.destroy()

        # Collect entries
        try:
            entries = sorted(os.listdir(self._current_dir))
        except PermissionError:
            err = ctk.CTkLabel(
                self._list_frame,
                text="Permission denied.",
                text_color=("gray50", "gray50"),
            )
            err.pack(anchor="w", padx=16, pady=20)
            self._status_label.configure(text="Cannot access this directory")
            return
        except FileNotFoundError:
            err = ctk.CTkLabel(
                self._list_frame,
                text="Directory not found.",
                text_color=("gray50", "gray50"),
            )
            err.pack(anchor="w", padx=16, pady=20)
            self._status_label.configure(text="Directory does not exist")
            return

        # Split into dirs and files
        dirs: list[str] = []
        files: list[str] = []
        for name in entries:
            full = os.path.join(self._current_dir, name)
            try:
                if os.path.isdir(full):
                    dirs.append(name)
                else:
                    files.append(name)
            except OSError:
                pass

        dirs.sort(key=str.lower)
        files.sort(key=str.lower)
        ordered = dirs + files
        dirs_set = frozenset(dirs)

        if not ordered:
            empty = ctk.CTkLabel(
                self._list_frame,
                text="(empty directory)",
                text_color=("gray50", "gray50"),
            )
            empty.pack(anchor="w", padx=16, pady=20)

        # Render rows
        for name in ordered:
            full = os.path.join(self._current_dir, name)
            is_dir = name in dirs_set
            self._render_row(name, full, is_dir)

        # Status
        dir_count = len(dirs)
        file_count = len(files)
        self._status_label.configure(
            text=f"{dir_count} folder{'s' if dir_count != 1 else ''}, "
            f"{file_count} file{'s' if file_count != 1 else ''}"
        )

    def _render_row(self, name: str, full_path: str, is_dir: bool) -> None:
        """Render one row in the file list."""
        row = ctk.CTkFrame(self._list_frame, fg_color="transparent")
        row.pack(fill="x", padx=2, pady=1)

        # Icon + name button
        icon = FOLDER_ICON if is_dir else FILE_ICON
        display = f"  {icon}  {name}"
        if len(display) > 72:
            display = display[:69] + "..."

        # Use a label-like button that fills the row
        btn = ctk.CTkButton(
            row,
            text=display,
            anchor="w",
            fg_color="transparent",
            text_color=("gray10", "gray90"),
            hover_color=("gray75", "gray28"),
            font=ctk.CTkFont(size=12),
            command=lambda p=full_path, d=is_dir: self._on_row_click(p, d),
        )
        btn.pack(side="left", fill="x", expand=True)

        # Type label
        type_text = "Folder" if is_dir else "File"
        ctk.CTkLabel(
            row,
            text=type_text,
            font=ctk.CTkFont(size=11),
            text_color=("gray50", "gray55"),
            width=80,
            anchor="w",
        ).pack(side="left", padx=(12, 8))

    def _on_row_click(self, path: str, is_dir: bool) -> None:
        """Handle click on a row: navigate into dirs, ignore files."""
        self._selected_label.configure(text=path)
        if is_dir:
            self._navigate_to(path)

    # ── actions ────────────────────────────────────────────────────

    def _select_current(self) -> None:
        self._result = self._current_dir
        self._finish()

    def _cancel(self) -> None:
        self._result = None
        self._finish()

    def _finish(self) -> None:
        try:
            self.grab_release()
        except Exception:
            pass
        if self._on_pick:
            self._on_pick(self._result)
        self.destroy()
