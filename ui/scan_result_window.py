"""Scan result popup — outcome, stats, infected list with actions, and summary."""

import tkinter as tk
from tkinter import messagebox

import customtkinter as ctk

from core.quarantine import quarantine_file, delete_file, open_file_location


ACCENT_COLOR = ("#247A59", "#2F8F68")
ACCENT_HOVER = ("#1E684C", "#267A58")
DANGER_COLOR = ("#B54444", "#A53A3A")
DANGER_HOVER = ("#973737", "#C04747")
WARNING_COLOR = ("#9C651E", "#D79A3F")
SUCCESS_COLOR = ("#247A59", "#2F8F68")
TEXT_SECONDARY = ("#26362D", "#D8E1DC")
WHITE_TEXT = "#FFFFFF"


class ScanResultWindow(ctk.CTkToplevel):
    """Modal popup shown after a scan completes.

    For infected files, offers per-file Quarantine / Delete / Open-location
    buttons, plus batch Quarantine All / Delete All.
    """

    def __init__(self, parent, result):
        super().__init__(parent)

        self.parent = parent
        self.title("Scan Result")
        self.transient(parent)
        self.withdraw()
        self.geometry("760x620")
        self.minsize(600, 460)

        self._row_widgets: list[dict] = []  # per-row button refs
        self._processed: set[int] = set()   # indices of handled files

        infected = result.get("infected", [])
        total = result.get("total", 0)
        scanned = result.get("scanned", 0)
        stopped = result.get("stopped", False)
        errors = result.get("errors", False)
        warnings = result.get("warnings", False)
        admin_hint = result.get("admin_hint", False)
        summary_lines = result.get("summary_lines", [])

        # ── Outcome ─────────────────────────────────────────────────
        if stopped:
            outcome = "Scan stopped by user"
            outcome_color = WARNING_COLOR
        elif infected:
            outcome = "Infected files found!"
            outcome_color = DANGER_COLOR
        elif errors:
            outcome = "Scan failed"
            outcome_color = DANGER_COLOR
        elif warnings:
            outcome = "Scan completed with warnings"
            outcome_color = WARNING_COLOR
        else:
            outcome = "No threats found"
            outcome_color = SUCCESS_COLOR

        # ── Build UI ────────────────────────────────────────────────
        container = ctk.CTkFrame(self)
        container.pack(fill="both", expand=True, padx=20, pady=20)

        # Outcome header
        ctk.CTkLabel(
            container,
            text=outcome,
            font=ctk.CTkFont(size=22, weight="bold"),
            text_color=outcome_color,
        ).pack(pady=(0, 14))

        # Stats
        scanned_str = f"{scanned} / {total}" if total else "0"
        ctk.CTkLabel(
            container,
            text=f"Files scanned: {scanned_str}",
            font=ctk.CTkFont(size=14),
        ).pack(pady=(0, 12))

        if warnings:
            warning_text = (
                "Some files could not be opened because they were locked, "
                "changed during scanning, or access was denied."
            )
            if admin_hint:
                warning_text += (
                    "\n\nFor deeper scans of protected Windows locations, "
                    "restart LibreWard as Administrator and scan again."
                )
            ctk.CTkLabel(
                container,
                text=warning_text,
                wraplength=660,
                justify="left",
                font=ctk.CTkFont(size=12),
                text_color=TEXT_SECONDARY,
            ).pack(fill="x", padx=8, pady=(0, 12))

        # ── Infected list (with actions) ────────────────────────────
        if infected:
            # Header row: title + batch buttons
            header_row = ctk.CTkFrame(container, fg_color="transparent")
            header_row.pack(fill="x", pady=(0, 4))

            ctk.CTkLabel(
                header_row,
                text=f"Infected files ({len(infected)}):",
                font=ctk.CTkFont(size=14, weight="bold"),
            ).pack(side="left", padx=(0, 12))

            ctk.CTkButton(
                header_row,
                text="Quarantine All",
                command=lambda: self._quarantine_all(infected),
                width=130,
                height=30,
                fg_color=WARNING_COLOR,
                hover_color=ACCENT_HOVER,
                text_color=WHITE_TEXT,
            ).pack(side="right", padx=4)

            ctk.CTkButton(
                header_row,
                text="Delete All",
                command=lambda: self._delete_all(infected),
                width=100,
                height=30,
                fg_color=DANGER_COLOR,
                hover_color=DANGER_HOVER,
                text_color=WHITE_TEXT,
            ).pack(side="right", padx=4)

            # Scrollable list
            scroll = ctk.CTkScrollableFrame(container, height=160)
            scroll.pack(fill="x", padx=0, pady=(0, 10))

            for idx, (path, status) in enumerate(infected):
                row = ctk.CTkFrame(scroll, fg_color="transparent")
                row.pack(fill="x", padx=2, pady=2)

                # Path label
                path_label = ctk.CTkLabel(
                    row,
                    text=path,
                    anchor="w",
                    font=ctk.CTkFont(size=12),
                )
                path_label.pack(side="left", fill="x", expand=True,
                                padx=(8, 4), pady=4)

                # Threat name
                threat_label = ctk.CTkLabel(
                    row,
                    text=status,
                    font=ctk.CTkFont(size=12, weight="bold"),
                    text_color=DANGER_COLOR,
                )
                threat_label.pack(side="left", padx=(4, 12), pady=4)

                # Action buttons (compact, packed right)
                qbtn = ctk.CTkButton(
                    row,
                    text="Quarantine",
                    command=lambda p=path, s=status, i=idx: self._quarantine_one(p, s, i),
                    width=90,
                    height=26,
                    font=ctk.CTkFont(size=11),
                    fg_color=ACCENT_COLOR,
                    hover_color=ACCENT_HOVER,
                    text_color=WHITE_TEXT,
                )
                qbtn.pack(side="right", padx=2, pady=4)

                dbtn = ctk.CTkButton(
                    row,
                    text="Delete",
                    command=lambda p=path, i=idx: self._delete_one(p, i),
                    width=60,
                    height=26,
                    font=ctk.CTkFont(size=11),
                    fg_color=DANGER_COLOR,
                    hover_color=DANGER_HOVER,
                    text_color=WHITE_TEXT,
                )
                dbtn.pack(side="right", padx=2, pady=4)

                obtn = ctk.CTkButton(
                    row,
                    text="📂",
                    command=lambda p=path: open_file_location(p),
                    width=36,
                    height=26,
                    font=ctk.CTkFont(size=13),
                    fg_color="transparent",
                    border_width=1,
                    text_color=TEXT_SECONDARY,
                )
                obtn.pack(side="right", padx=2, pady=4)

                self._row_widgets.append({
                    "qbtn": qbtn,
                    "dbtn": dbtn,
                    "obtn": obtn,
                    "path_label": path_label,
                    "threat_label": threat_label,
                })

        # ── Scan summary ────────────────────────────────────────────
        if summary_lines:
            summary_frame = ctk.CTkFrame(container)
            summary_frame.pack(fill="both", expand=True, pady=(0, 12))

            ctk.CTkLabel(
                summary_frame,
                text="Scan Summary",
                font=ctk.CTkFont(size=14, weight="bold"),
            ).pack(anchor="w", padx=12, pady=(10, 6))

            summary_text = ctk.CTkTextbox(summary_frame, wrap="word")
            summary_text.pack(fill="both", expand=True, padx=10, pady=(0, 10))
            summary_text.insert("1.0", "".join(summary_lines))
            summary_text.configure(state="disabled")

        # ── Status line ─────────────────────────────────────────────
        self._status = ctk.CTkLabel(
            container,
            text="",
            font=ctk.CTkFont(size=11),
            text_color=("gray40", "gray60"),
            anchor="w",
        )
        self._status.pack(fill="x", padx=4, pady=(4, 8))

        # ── Close ───────────────────────────────────────────────────
        ctk.CTkButton(
            container,
            text="Close",
            command=self._close,
        ).pack()

        # Modal behaviour
        self.after(100, self._center_and_modal)

    # ── per-file actions ────────────────────────────────────────────

    def _quarantine_one(self, path: str, threat: str, idx: int) -> None:
        if idx in self._processed:
            return
        msg = quarantine_file(path, threat)
        self._processed.add(idx)
        self._mark_done(idx, msg, success="Quarantined" in msg)
        self._notify_quarantine_changed()

    def _delete_one(self, path: str, idx: int) -> None:
        if idx in self._processed:
            return
        ok = messagebox.askyesno(
            "Confirm Delete",
            f"Permanently delete this file?\n\n{path}\n\nThis cannot be undone.",
            parent=self,
        )
        if not ok:
            return
        msg = delete_file(path)
        self._processed.add(idx)
        self._mark_done(idx, msg, success="Deleted" in msg)

    def _mark_done(self, idx: int, msg: str, *, success: bool) -> None:
        """Update row buttons and status after an action."""
        if idx < len(self._row_widgets):
            w = self._row_widgets[idx]
            color = SUCCESS_COLOR if success else DANGER_COLOR
            short = "Done ✓" if success else "Failed ✗"
            w["qbtn"].configure(text=short, fg_color=color, state="disabled")
            w["dbtn"].configure(state="disabled")
            w["obtn"].configure(state="disabled")
        self._status.configure(text=msg)

    # ── batch actions ───────────────────────────────────────────────

    def _quarantine_all(self, infected: list[tuple[str, str]]) -> None:
        count = 0
        for idx, (path, threat) in enumerate(infected):
            if idx not in self._processed:
                msg = quarantine_file(path, threat)
                self._processed.add(idx)
                self._mark_done(idx, msg, success="Quarantined" in msg)
                count += 1
        self._status.configure(
            text=f"Quarantined {count} file{'s' if count != 1 else ''}."
        )
        self._notify_quarantine_changed()

    def _delete_all(self, infected: list[tuple[str, str]]) -> None:
        remaining = [i for i in range(len(infected)) if i not in self._processed]
        if not remaining:
            return
        ok = messagebox.askyesno(
            "Confirm Delete All",
            f"Permanently delete {len(remaining)} infected file(s)?\n\n"
            "This cannot be undone.",
            parent=self,
        )
        if not ok:
            return
        count = 0
        for idx in remaining:
            path, _threat = infected[idx]
            msg = delete_file(path)
            self._processed.add(idx)
            self._mark_done(idx, msg, success="Deleted" in msg)
            count += 1
        self._status.configure(
            text=f"Deleted {count} file{'s' if count != 1 else ''}."
        )

    def _notify_quarantine_changed(self) -> None:
        callback = getattr(self.parent, "on_quarantine_changed", None)
        if callable(callback):
            callback()

    # ── window boilerplate ──────────────────────────────────────────

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
