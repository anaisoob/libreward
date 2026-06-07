import tkinter as tk

import customtkinter as ctk


class ScanResultWindow(ctk.CTkToplevel):
    """Modal popup shown after a scan completes, summarizing the outcome."""

    def __init__(self, parent, result):
        """
        *result* is a dict with keys:
            infected  – list of (path, status) tuples
            total     – total files counted
            scanned   – files actually scanned
            stopped   – bool, True if user aborted
            errors    – bool, True if clamscan reported errors
        """
        super().__init__(parent)

        self.parent = parent
        self.title("Scan Result")
        self.transient(parent)
        self.geometry("620x480")
        self.minsize(500, 380)

        self.after(100, self._center_and_modal)

        infected = result.get("infected", [])
        total = result.get("total", 0)
        scanned = result.get("scanned", 0)
        stopped = result.get("stopped", False)
        errors = result.get("errors", False)

        # Determine outcome
        if stopped:
            outcome = "Scan stopped by user"
            outcome_color = "#CC8800"
        elif infected:
            outcome = "Infected files found!"
            outcome_color = "#CC3333"
        elif errors:
            outcome = "Scan finished with errors"
            outcome_color = "#CC8800"
        else:
            outcome = "No threats found"
            outcome_color = "#33AA33"

        # --- build UI ---
        container = ctk.CTkFrame(self)
        container.pack(fill="both", expand=True, padx=20, pady=20)

        # Outcome header
        ctk.CTkLabel(
            container,
            text=outcome,
            font=ctk.CTkFont(size=22, weight="bold"),
            text_color=outcome_color,
        ).pack(pady=(0, 14))

        # Stats line
        scanned_str = f"{scanned} / {total}" if total else "0"
        ctk.CTkLabel(
            container,
            text=f"Files scanned: {scanned_str}",
            font=ctk.CTkFont(size=14),
        ).pack(pady=(0, 12))

        # Infected list
        if infected:
            list_frame = ctk.CTkFrame(container)
            list_frame.pack(fill="both", expand=True, pady=(0, 12))

            ctk.CTkLabel(
                list_frame,
                text=f"Infected files ({len(infected)}):",
                font=ctk.CTkFont(size=14, weight="bold"),
            ).pack(anchor="w", padx=12, pady=(10, 6))

            scroll = ctk.CTkScrollableFrame(list_frame)
            scroll.pack(fill="both", expand=True, padx=10, pady=(0, 10))

            for path, status in infected:
                row = ctk.CTkFrame(scroll)
                row.pack(fill="x", padx=4, pady=3)

                path_label = ctk.CTkLabel(
                    row,
                    text=path,
                    anchor="w",
                    font=ctk.CTkFont(size=12),
                )
                path_label.pack(side="left", fill="x", expand=True, padx=(8, 4), pady=4)

                status_label = ctk.CTkLabel(
                    row,
                    text=status,
                    font=ctk.CTkFont(size=12, weight="bold"),
                    text_color="#CC3333",
                )
                status_label.pack(side="right", padx=(4, 8), pady=4)

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
