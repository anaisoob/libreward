"""Main application window — ClamAV GUI."""

import os
import subprocess
import threading
import queue
from .file_picker import FilePickerDialog
from tkinter import messagebox

import customtkinter as ctk

from config import load_config as config_load, save_config as config_save
from backends import backend
from excludes import get_common_excludes, get_active_exclude_patterns
from scanner import (
    collect_files,
    build_clamscan_command,
    parse_clamscan_result_line,
    should_log_line,
)
from core.constants import APP_NAME, APP_VERSION
from core.runtime import check_startup, StartupStatus
from .about_window import AboutWindow
from .exclude_window import ExcludeWindow
from .scan_result_window import ScanResultWindow
from .startup_dialog import StartupDownloadDialog


BG_COLOR = ("#F4F7F4", "#0F1411")
SIDEBAR_COLOR = ("#E3EAE5", "#151B18")
SURFACE_COLOR = ("#FFFFFF", "#1B221F")
SURFACE_ALT_COLOR = ("#EDF3EF", "#202923")
BORDER_COLOR = ("#CCD8D1", "#313D36")
ENTRY_COLOR = ("#F8FBF9", "#101612")
LOG_COLOR = ("#F8FBF9", "#0F1511")
ACCENT_COLOR = ("#247A59", "#2F8F68")
ACCENT_HOVER = ("#1E684C", "#267A58")
SECONDARY_ACTION = ("#2F6FA3", "#4BA3D8")
SECONDARY_ACTION_HOVER = ("#285F8C", "#388FC3")
DANGER_COLOR = ("#B54444", "#A53A3A")
DANGER_HOVER = ("#973737", "#C04747")
TEXT_PRIMARY = ("#17211B", "#F3F7F4")
TEXT_SECONDARY = ("#26362D", "#D8E1DC")
TEXT_MUTED = ("#5F7067", "#93A39A")
TEXT_SUBTLE = ("#7A8A82", "#6F7E76")
SECONDARY_HOVER = ("#DCE8E1", "#2A352F")
WHITE_TEXT = "#FFFFFF"


class ClamAVGui(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title(APP_NAME)
        self.geometry("1080x760")
        self.minsize(920, 640)
        self.configure(fg_color=BG_COLOR)

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("green")

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

        # Startup status (set after health check)
        self._startup_status: StartupStatus | None = None

        self.load_config()
        self.create_widgets()
        self.update_exclude_summary()  # reflect loaded excludes in UI

        # Run startup check after UI is visible.
        self.after(200, self._startup_check)
        self.after(100, self.process_output_queue)

    # ── config ──────────────────────────────────────────────────────

    def load_config(self):
        try:
            data = config_load()
            if data is None:
                return

            self.scan_path.set(data.get("scan_path", os.path.expanduser("~")))

            common = data.get("enabled_common_excludes", [])
            common_keys = set(get_common_excludes().keys())
            self.enabled_common_excludes = {
                item for item in common if item in common_keys
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

    # ── startup health check ────────────────────────────────────────

    def _startup_check(self):
        """Run ClamAV health check without blocking the Tk event loop."""

        thread = threading.Thread(target=self._run_startup_check, daemon=True)
        thread.start()

    def _run_startup_check(self):
        """Worker body for startup health check."""

        def _log(msg):
            self.output_queue.put(msg)

        _log(f"=== {APP_NAME} v{APP_VERSION} ===\n")
        _log(f"Platform: {backend.platform_arch()}\n\n")

        status = check_startup(log=_log)
        self._startup_status = status
        self.output_queue.put(("__STARTUP_DONE__", None))

        _log("\n")

        if status.is_first_run:
            # No ClamAV at all — offer download
            self.output_queue.put(("__NO_CLAMAV__", None))
        elif not status.db_found:
            _log(
                "Virus database not found.\n"
                "Please update the database before scanning.\n\n"
            )
            self.output_queue.put(("__NO_DATABASE__", None))

        _log("Ready.\n\n")

    def _show_startup_dialog(self):
        """Show the first-run ClamAV download dialog."""
        self.after(100, self._open_download_dialog)

    def _open_download_dialog(self):
        StartupDownloadDialog(self, on_done=self._on_download_done)

    def _on_download_done(self, success: bool):
        if success:
            self.log("\nRe-checking ClamAV runtime after install...\n")

            def _log(msg):
                self.output_queue.put(msg)

            status = check_startup(log=_log)
            self._startup_status = status

            if status.runtime_ok:
                self.log("ClamAV is now available.\n")
                if not status.db_found:
                    self.log(
                        "Virus database not found.\n"
                        "Update the database before scanning.\n"
                    )
                    self._offer_database_update(
                        "ClamAV is installed, but the virus database is missing.\n\n"
                        "Update the database now?"
                    )
            else:
                self.log(
                    "WARNING: ClamAV still not detected after install.\n"
                )
                self._startup_status = None

    def _offer_database_update(self, message: str) -> None:
        """Ask the user to run freshclam when scanning is not ready."""
        if self._startup_status is None or not self._startup_status.can_update_db:
            self._show_info_dialog(
                "Virus Database Missing",
                "Virus database not found.\n\n"
                "freshclam is not available, so LibreWard cannot update it automatically.",
            )
            return

        answer = messagebox.askyesno("Virus Database Missing", message)
        if answer:
            self.after(100, self._settings_update_database)

    # ── action: update ClamAV runtime ───────────────────────────────

    def _check_for_updates(self):
        """Check for ClamAV runtime updates in a background thread."""
        from core.updater import check_for_updates, perform_update

        self.log("Checking for ClamAV updates...\n")

        def _run():
            try:
                def _log(msg):
                    self.output_queue.put(msg)

                platform_entry = check_for_updates(log=_log)

                if platform_entry is None:
                    self.output_queue.put(
                        "No update available or update not applicable.\n\n"
                    )
                    return

                # Ask user before updating
                latest = platform_entry.get("latest_version", "?")
                self.output_queue.put(
                    f"ClamAV {latest} is available. "
                    "Click 'Update ClamAV' to install.\n"
                )
                self.output_queue.put(("__UPDATE_AVAILABLE__", platform_entry))

            except Exception as e:
                self.output_queue.put(f"Update check failed: {e}\n\n")

        thread = threading.Thread(target=_run, daemon=True)
        thread.start()

    def _start_clamav_update(self, platform_entry):
        """Actually perform the ClamAV runtime update."""
        from core.updater import perform_update

        self.log("Starting ClamAV update...\n")
        self.start_activity("Activity: updating ClamAV...")

        def _run():
            def _log(msg):
                self.output_queue.put(msg)

            def _progress(phase, done, total):
                if phase == "download" and total:
                    pct = min(done / total, 1.0)
                    self.output_queue.put(
                        ("__UPDATE_PROGRESS__", pct)
                    )

            error = perform_update(
                platform_entry, log=_log, progress=_progress
            )

            if error:
                self.output_queue.put(f"\nERROR: {error}\n")
                self.output_queue.put(("__UPDATE_DONE__", False))
            else:
                self.output_queue.put("\nClamAV runtime updated successfully!\n")
                self.output_queue.put(
                    "Use 'Update Database' to download the latest virus definitions.\n\n"
                )
                self.output_queue.put(("__UPDATE_DONE__", True))

        thread = threading.Thread(target=_run, daemon=True)
        thread.start()

    # ── action: update database ─────────────────────────────────────

    def _update_database(self):
        """Run freshclam to update the virus database."""
        if self._startup_status is None or not self._startup_status.can_update_db:
            self.log("ERROR: freshclam not available. Update ClamAV first.\n")
            return

        from core.db_manager import run_freshclam_update

        self.log("Updating virus database...\n")
        self.start_activity("Activity: updating virus database...")

        freshclam_path = self._startup_status.runtime.freshclam

        def _run():
            def _log(msg):
                self.output_queue.put(msg)

            # Let run_freshclam_update handle platform-specific behaviour
            # (custom conf on Windows, pkexec/sudo on Linux, etc.)
            success, output = run_freshclam_update(
                freshclam_path, conf_path=None, log_callback=_log
            )

            if success:
                self.output_queue.put("\nDatabase update completed.\n")

                # Re-check database status
                status = check_startup()
                self._startup_status = status
                if status.db_found:
                    self.output_queue.put("Virus database is now ready.\n\n")
                else:
                    self.output_queue.put(
                        "WARNING: Database still not detected. Check logs.\n\n"
                    )
            else:
                self.output_queue.put(
                    f"\nDatabase update failed. See output above.\n"
                )

            self.output_queue.put(("__DB_UPDATE_DONE__", success))

        thread = threading.Thread(target=_run, daemon=True)
        thread.start()

    # ── UI construction ─────────────────────────────────────────────

    def create_widgets(self):
        # Sidebar (fixed left panel)
        SIDEBAR_W = 240
        sidebar = ctk.CTkFrame(
            self,
            width=SIDEBAR_W,
            corner_radius=0,
            fg_color=SIDEBAR_COLOR,
        )
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)

        # ── Sidebar header ─────────────────────────────────────────
        header = ctk.CTkFrame(sidebar, fg_color="transparent")
        header.pack(fill="x", padx=16, pady=(24, 6))

        logo = ctk.CTkFrame(
            header,
            width=42,
            height=42,
            corner_radius=8,
            fg_color=ACCENT_COLOR,
        )
        logo.pack(side="left", padx=(0, 12))
        logo.pack_propagate(False)

        ctk.CTkLabel(
            logo,
            text="LW",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=WHITE_TEXT,
        ).pack(expand=True)

        ctk.CTkLabel(
            header,
            text=APP_NAME,
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color=TEXT_PRIMARY,
        ).pack(side="left", anchor="center")

        # Subtle separator
        sep = ctk.CTkFrame(sidebar, height=1, fg_color=BORDER_COLOR)
        sep.pack(fill="x", padx=18, pady=(10, 14))

        # ── Navigation ─────────────────────────────────────────────
        self._nav_buttons: dict[str, ctk.CTkButton] = {}

        nav_items = [
            ("scan", "Scan"),
            ("firewall", "Firewall"),
            ("internet", "Internet Watcher"),
            ("settings", "Settings"),
        ]

        for key, label in nav_items:
            btn = ctk.CTkButton(
                sidebar,
                text=label,
                anchor="w",
                height=42,
                corner_radius=8,
                fg_color="transparent",
                text_color=TEXT_SECONDARY,
                hover_color=SURFACE_ALT_COLOR,
                font=ctk.CTkFont(size=13, weight="bold"),
                command=lambda k=key: self._switch_page(k),
            )
            btn.pack(fill="x", padx=12, pady=4)
            self._nav_buttons[key] = btn

        self._quarantine_nav_index = len(nav_items)
        self._nav_buttons["quarantine"] = None

        # ── Bottom section ────────────────────────────────────────
        # Push About + version to the bottom
        ctk.CTkLabel(sidebar, text="").pack(pady=(6, 0), expand=True)

        sep2 = ctk.CTkFrame(sidebar, height=1, fg_color=BORDER_COLOR)
        sep2.pack(fill="x", padx=18, pady=(6, 10))

        about_btn = ctk.CTkButton(
            sidebar,
            text="    ℹ   About",
            anchor="w",
            height=36,
            corner_radius=8,
            fg_color="transparent",
            text_color=TEXT_SECONDARY,
            hover_color=SURFACE_ALT_COLOR,
            font=ctk.CTkFont(size=12),
            command=self.open_about_window,
        )
        about_btn.pack(fill="x", padx=10, pady=2)

        ctk.CTkLabel(
            sidebar,
            text=f"v{APP_VERSION}",
            font=ctk.CTkFont(size=10),
            text_color=TEXT_SUBTLE,
        ).pack(pady=(4, 16))

        # ── Content area ───────────────────────────────────────────
        self._content = ctk.CTkFrame(self, fg_color=BG_COLOR, corner_radius=0)
        self._content.pack(side="left", fill="both", expand=True)

        # Build pages
        self._pages: dict[str, ctk.CTkFrame] = {}
        self._pages["scan"] = self._build_scan_page()
        self._pages["firewall"] = self._build_placeholder_page(
            "🔥  Firewall", "Firewall management is coming soon."
        )
        self._pages["internet"] = self._build_placeholder_page(
            "🌐  Internet Watcher", "Internet traffic monitoring is coming soon."
        )
        self._pages["quarantine"] = self._build_quarantine_page()
        self._pages["settings"] = self._build_settings_page()

        # Default page
        self._refresh_quarantine_nav()
        self._switch_page("scan")

    def _button_kwargs(self, variant: str = "primary") -> dict:
        """Return consistent button styles with good light/dark contrast."""
        base = {
            "corner_radius": 8,
            "font": ctk.CTkFont(size=13, weight="bold"),
        }
        if variant == "primary":
            return {
                **base,
                "fg_color": ACCENT_COLOR,
                "hover_color": ACCENT_HOVER,
                "text_color": WHITE_TEXT,
            }
        if variant == "danger":
            return {
                **base,
                "fg_color": DANGER_COLOR,
                "hover_color": DANGER_HOVER,
                "text_color": WHITE_TEXT,
            }
        if variant == "outline":
            return {
                **base,
                "fg_color": SECONDARY_ACTION,
                "hover_color": SECONDARY_ACTION_HOVER,
                "text_color": WHITE_TEXT,
            }
        return {
            **base,
            "fg_color": SURFACE_ALT_COLOR,
            "hover_color": SECONDARY_HOVER,
            "text_color": TEXT_SECONDARY,
        }

    def _build_scan_page(self) -> ctk.CTkFrame:
        """Build and return the virus scan page frame."""
        page = ctk.CTkFrame(self._content, fg_color=BG_COLOR, corner_radius=0)

        header = ctk.CTkFrame(page, fg_color="transparent")
        header.pack(fill="x", padx=26, pady=(24, 10))

        title_block = ctk.CTkFrame(header, fg_color="transparent")
        title_block.pack(side="left", fill="x", expand=True)

        ctk.CTkLabel(
            title_block,
            text="Virus Scan",
            anchor="w",
            font=ctk.CTkFont(size=26, weight="bold"),
            text_color=TEXT_PRIMARY,
        ).pack(fill="x")

        ctk.CTkLabel(
            title_block,
            text="Run ClamAV scans, monitor progress, and review detected files.",
            anchor="w",
            font=ctk.CTkFont(size=13),
            text_color=TEXT_MUTED,
        ).pack(fill="x", pady=(4, 0))

        # Path row
        path_frame = ctk.CTkFrame(page, fg_color=SURFACE_COLOR, corner_radius=8)
        path_frame.pack(fill="x", padx=26, pady=(10, 10))

        ctk.CTkLabel(
            path_frame,
            text="Scan folder",
            width=110,
            anchor="w",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=TEXT_PRIMARY,
        ).pack(side="left", padx=(16, 8))

        self.path_entry = ctk.CTkEntry(
            path_frame,
            textvariable=self.scan_path,
            height=38,
            corner_radius=8,
            border_width=1,
            border_color=BORDER_COLOR,
            fg_color=ENTRY_COLOR,
        )
        self.path_entry.pack(side="left", fill="x", expand=True, padx=8, pady=14)

        ctk.CTkButton(
            path_frame,
            text="Choose",
            height=38,
            width=92,
            **self._button_kwargs("primary"),
            command=self.choose_scan_folder,
        ).pack(side="left", padx=(4, 8))

        ctk.CTkButton(
            path_frame,
            text="Excludes",
            height=38,
            width=94,
            **self._button_kwargs("outline"),
            command=self.open_exclude_window,
        ).pack(side="left", padx=(0, 16))

        # Exclude summary
        self.exclude_summary_label = ctk.CTkLabel(
            page,
            text="Excludes: none",
            anchor="w",
            text_color=TEXT_MUTED,
            font=ctk.CTkFont(size=12),
        )
        self.exclude_summary_label.pack(fill="x", padx=30, pady=(0, 12))

        # Scan buttons
        button_frame = ctk.CTkFrame(page, fg_color="transparent")
        button_frame.pack(fill="x", padx=26, pady=(0, 14))

        self.start_button = ctk.CTkButton(
            button_frame,
            text="Start scan",
            height=40,
            width=126,
            **self._button_kwargs("primary"),
            command=self.start_scan,
        )
        self.start_button.pack(side="left", padx=(0, 8))

        self.quick_scan_button = ctk.CTkButton(
            button_frame,
            text="Quick System Scan",
            height=40,
            width=156,
            **self._button_kwargs("outline"),
            command=self.start_quick_scan,
        )
        self.quick_scan_button.pack(side="left", padx=8)

        self.stop_button = ctk.CTkButton(
            button_frame,
            text="Stop",
            height=40,
            width=94,
            **self._button_kwargs("danger"),
            command=self.stop_scan,
            state="disabled",
        )
        self.stop_button.pack(side="left", padx=8)

        self.clear_button = ctk.CTkButton(
            button_frame,
            text="Clear log",
            height=40,
            width=104,
            **self._button_kwargs("secondary"),
            command=self.clear_log,
        )
        self.clear_button.pack(side="left", padx=8)

        status_grid = ctk.CTkFrame(page, fg_color="transparent")
        status_grid.pack(fill="x", padx=26, pady=(0, 14))
        status_grid.grid_columnconfigure(0, weight=1, uniform="status")
        status_grid.grid_columnconfigure(1, weight=2, uniform="status")

        status_card = ctk.CTkFrame(status_grid, fg_color=SURFACE_COLOR, corner_radius=8)
        status_card.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        current_card = ctk.CTkFrame(status_grid, fg_color=SURFACE_COLOR, corner_radius=8)
        current_card.grid(row=0, column=1, sticky="nsew", padx=(8, 0))

        ctk.CTkLabel(
            status_card,
            text="Status",
            anchor="w",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=TEXT_SUBTLE,
        ).pack(fill="x", padx=14, pady=(12, 2))

        self.status_label = ctk.CTkLabel(
            status_card,
            text="ready",
            anchor="w",
            font=ctk.CTkFont(size=15, weight="bold"),
            text_color=TEXT_PRIMARY,
        )
        self.status_label.pack(fill="x", padx=14, pady=(0, 12))

        ctk.CTkLabel(
            current_card,
            text="Current file",
            anchor="w",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=TEXT_SUBTLE,
        ).pack(fill="x", padx=14, pady=(12, 2))

        self.current_file_label = ctk.CTkLabel(
            current_card,
            text="-",
            anchor="w",
            font=ctk.CTkFont(size=13),
            text_color=TEXT_SECONDARY,
        )
        self.current_file_label.pack(fill="x", padx=14, pady=(0, 12))

        # Progress bar
        progress_frame = ctk.CTkFrame(page, fg_color=SURFACE_COLOR, corner_radius=8)
        progress_frame.pack(fill="x", padx=26, pady=(0, 12))

        progress_header = ctk.CTkFrame(progress_frame, fg_color="transparent")
        progress_header.pack(fill="x", padx=14, pady=(12, 6))

        ctk.CTkLabel(
            progress_header,
            text="Progress",
            anchor="w",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=TEXT_MUTED,
        ).pack(side="left")

        self.percent_label = ctk.CTkLabel(
            progress_header,
            text="0%",
            anchor="e",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=TEXT_PRIMARY,
        )
        self.percent_label.pack(side="right")

        self.progress = ctk.CTkProgressBar(
            progress_frame,
            mode="determinate",
            progress_color=ACCENT_COLOR,
        )
        self.progress.pack(fill="x", padx=14, pady=(0, 14))
        self.progress.set(0)

        # Activity indicator (shared — positioned relative to last element)
        self.activity_label = ctk.CTkLabel(
            page,
            text="Activity: idle",
            anchor="w",
            text_color=TEXT_MUTED,
            font=ctk.CTkFont(size=12),
        )
        self.activity_bar = ctk.CTkProgressBar(
            page,
            mode="indeterminate",
            progress_color=ACCENT_COLOR,
        )
        self.activity_bar.stop()

        # Log area
        self.log_frame = ctk.CTkFrame(page, fg_color=SURFACE_COLOR, corner_radius=8)
        self.log_frame.pack(fill="both", expand=True, padx=26, pady=(0, 24))

        ctk.CTkLabel(
            self.log_frame,
            text="Event log",
            anchor="w",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=TEXT_MUTED,
        ).pack(fill="x", padx=14, pady=(12, 6))

        self.log_box = ctk.CTkTextbox(
            self.log_frame,
            wrap="word",
            corner_radius=8,
            border_width=1,
            border_color=BORDER_COLOR,
            fg_color=LOG_COLOR,
            text_color=TEXT_SECONDARY,
        )
        self.log_box.pack(fill="both", expand=True, padx=14, pady=(0, 14))

        return page

    def _build_placeholder_page(self, title: str, subtitle: str) -> ctk.CTkFrame:
        """Build a placeholder 'coming soon' page."""
        page = ctk.CTkFrame(self._content, fg_color=BG_COLOR, corner_radius=0)

        inner = ctk.CTkFrame(page, fg_color=SURFACE_COLOR, corner_radius=8)
        inner.place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(
            inner,
            text=title,
            font=ctk.CTkFont(size=24, weight="bold"),
            text_color=TEXT_PRIMARY,
        ).pack(padx=42, pady=(34, 8))

        ctk.CTkLabel(
            inner,
            text=subtitle,
            font=ctk.CTkFont(size=14),
            text_color=TEXT_MUTED,
        ).pack(padx=42, pady=(0, 34))

        return page

    def _build_quarantine_page(self) -> ctk.CTkFrame:
        """Build and return the quarantine management page."""
        page = ctk.CTkFrame(self._content, fg_color=BG_COLOR, corner_radius=0)

        header = ctk.CTkFrame(page, fg_color="transparent")
        header.pack(fill="x", padx=28, pady=(24, 16))

        title_block = ctk.CTkFrame(header, fg_color="transparent")
        title_block.pack(side="left", fill="x", expand=True)

        ctk.CTkLabel(
            title_block,
            text="Quarantine",
            anchor="w",
            font=ctk.CTkFont(size=26, weight="bold"),
            text_color=TEXT_PRIMARY,
        ).pack(fill="x")

        self._quarantine_subtitle = ctk.CTkLabel(
            title_block,
            text="Review isolated files and choose whether to restore or delete them.",
            anchor="w",
            font=ctk.CTkFont(size=13),
            text_color=TEXT_MUTED,
        )
        self._quarantine_subtitle.pack(fill="x", pady=(4, 0))

        ctk.CTkButton(
            header,
            text="Refresh",
            height=38,
            width=100,
            **self._button_kwargs("outline"),
            command=self._refresh_quarantine_page,
        ).pack(side="right", padx=(12, 0))

        self._quarantine_list = ctk.CTkScrollableFrame(
            page,
            fg_color=SURFACE_COLOR,
            corner_radius=8,
        )
        self._quarantine_list.pack(fill="both", expand=True, padx=28, pady=(0, 24))

        self._refresh_quarantine_page()
        return page

    def _quarantine_items(self) -> list[dict]:
        from core.quarantine import list_quarantined_files

        return list_quarantined_files()

    def _refresh_quarantine_nav(self):
        """Show the Quarantine nav item only when quarantined files exist."""
        count = len(self._quarantine_items())
        btn = self._nav_buttons.get("quarantine")

        if count and btn is None:
            btn = ctk.CTkButton(
                self._nav_buttons["scan"].master,
                text=f"Quarantine ({count})",
                anchor="w",
                height=42,
                corner_radius=8,
                fg_color="transparent",
                text_color=TEXT_SECONDARY,
                hover_color=SURFACE_ALT_COLOR,
                font=ctk.CTkFont(size=13, weight="bold"),
                command=lambda: self._switch_page("quarantine"),
            )
            btn.pack(fill="x", padx=12, pady=4, after=self._nav_buttons["internet"])
            self._nav_buttons["quarantine"] = btn
        elif count and btn is not None:
            btn.configure(text=f"Quarantine ({count})")
            if not btn.winfo_ismapped():
                btn.pack(fill="x", padx=12, pady=4, after=self._nav_buttons["internet"])
        elif not count and btn is not None:
            btn.pack_forget()
            if getattr(self, "_current_page", None) == "quarantine":
                self._switch_page("scan")

    def _refresh_quarantine_page(self):
        """Refresh quarantine rows from on-disk metadata."""
        if not hasattr(self, "_quarantine_list"):
            return

        for child in self._quarantine_list.winfo_children():
            child.destroy()

        items = self._quarantine_items()
        self._refresh_quarantine_nav()

        if hasattr(self, "_quarantine_subtitle"):
            noun = "file" if len(items) == 1 else "files"
            self._quarantine_subtitle.configure(
                text=f"{len(items)} isolated {noun}. Restore false positives or permanently delete confirmed threats."
            )

        if not items:
            empty = ctk.CTkFrame(
                self._quarantine_list,
                fg_color="transparent",
            )
            empty.pack(fill="both", expand=True, padx=16, pady=28)
            ctk.CTkLabel(
                empty,
                text="No quarantined files",
                font=ctk.CTkFont(size=18, weight="bold"),
                text_color=TEXT_PRIMARY,
            ).pack(anchor="w")
            ctk.CTkLabel(
                empty,
                text="Files you quarantine after a scan will appear here.",
                font=ctk.CTkFont(size=13),
                text_color=TEXT_MUTED,
            ).pack(anchor="w", pady=(6, 0))
            return

        for item in items:
            self._add_quarantine_row(item)

    def _add_quarantine_row(self, item: dict):
        row = ctk.CTkFrame(
            self._quarantine_list,
            fg_color=SURFACE_ALT_COLOR,
            corner_radius=8,
        )
        row.pack(fill="x", padx=12, pady=8)

        info = ctk.CTkFrame(row, fg_color="transparent")
        info.pack(side="left", fill="x", expand=True, padx=14, pady=12)

        original_path = str(item.get("original_path") or "unknown original path")
        threat_name = str(item.get("threat_name") or "unknown threat")
        quarantined_at = str(item.get("quarantined_at") or "unknown time")
        size = item.get("original_size")
        size_label = self._format_size(size) if isinstance(size, int) else "unknown size"

        ctk.CTkLabel(
            info,
            text=original_path,
            anchor="w",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=TEXT_PRIMARY,
        ).pack(fill="x")

        ctk.CTkLabel(
            info,
            text=f"{threat_name}  |  {size_label}  |  {quarantined_at}",
            anchor="w",
            font=ctk.CTkFont(size=12),
            text_color=TEXT_MUTED,
        ).pack(fill="x", pady=(4, 0))

        actions = ctk.CTkFrame(row, fg_color="transparent")
        actions.pack(side="right", padx=14, pady=12)

        qname = str(item.get("quarantine_name"))

        ctk.CTkButton(
            actions,
            text="Restore",
            height=34,
            width=92,
            **self._button_kwargs("primary"),
            command=lambda name=qname: self._restore_quarantined(name),
        ).pack(side="left", padx=(0, 8))

        ctk.CTkButton(
            actions,
            text="Delete",
            height=34,
            width=82,
            **self._button_kwargs("danger"),
            command=lambda name=qname: self._delete_quarantined(name),
        ).pack(side="left")

    def _restore_quarantined(self, quarantine_name: str):
        from core.quarantine import restore_file

        msg = restore_file(quarantine_name)
        if msg.startswith("Original file already exists:"):
            original = msg.partition(": ")[2]
            answer = messagebox.askyesno(
                "Restore Quarantined File",
                f"A file already exists at the original location:\n\n"
                f"{original}\n\n"
                "Overwrite it with the quarantined file?",
            )
            if answer:
                msg = restore_file(quarantine_name, overwrite=True)
        self.log(msg + "\n")
        self._refresh_quarantine_page()

    def _delete_quarantined(self, quarantine_name: str):
        from core.quarantine import delete_quarantined_file

        answer = messagebox.askyesno(
            "Delete Quarantined File",
            "Permanently delete this quarantined file?\n\nThis cannot be undone.",
        )
        if not answer:
            return

        msg = delete_quarantined_file(quarantine_name)
        self.log(msg + "\n")
        self._refresh_quarantine_page()

    @staticmethod
    def _format_size(size: int) -> str:
        if size >= 1_000_000:
            return f"{size / 1_000_000:.1f} MB"
        if size >= 1_000:
            return f"{size / 1_000:.1f} KB"
        return f"{size} B"

    def _build_settings_page(self) -> ctk.CTkFrame:
        """Build and return the Settings page."""
        page = ctk.CTkFrame(self._content, fg_color=BG_COLOR, corner_radius=0)

        # Title
        ctk.CTkLabel(
            page,
            text="Settings",
            font=ctk.CTkFont(size=26, weight="bold"),
            text_color=TEXT_PRIMARY,
        ).pack(anchor="w", padx=28, pady=(24, 4))

        ctk.CTkLabel(
            page,
            text="Manage engine updates, database status, and appearance.",
            font=ctk.CTkFont(size=13),
            text_color=TEXT_MUTED,
        ).pack(anchor="w", padx=28, pady=(0, 20))

        # ── ClamAV section ──────────────────────────────────────
        clamav_frame = ctk.CTkFrame(page, fg_color=SURFACE_COLOR, corner_radius=8)
        clamav_frame.pack(fill="x", padx=28, pady=(0, 16))

        ctk.CTkLabel(
            clamav_frame,
            text="ClamAV Engine",
            font=ctk.CTkFont(size=15, weight="bold"),
            text_color=TEXT_PRIMARY,
        ).pack(anchor="w", padx=16, pady=(14, 8))

        btn_row = ctk.CTkFrame(clamav_frame, fg_color="transparent")
        btn_row.pack(fill="x", padx=12, pady=(4, 14))

        ctk.CTkButton(
            btn_row,
            text="Update ClamAV",
            command=self._settings_update_runtime,
            height=36,
            **self._button_kwargs("primary"),
        ).pack(side="left", padx=6)

        ctk.CTkButton(
            btn_row,
            text="Update Database",
            command=self._settings_update_database,
            height=36,
            **self._button_kwargs("outline"),
        ).pack(side="left", padx=6)

        status_info = ctk.CTkTextbox(
            clamav_frame,
            wrap="word",
            height=124,
            corner_radius=8,
            border_width=1,
            border_color=BORDER_COLOR,
            fg_color=LOG_COLOR,
            text_color=TEXT_SECONDARY,
        )
        status_info.pack(fill="x", padx=16, pady=(0, 14))
        status_info.insert("1.0", self._runtime_status_summary())
        status_info.configure(state="disabled")
        self._settings_status_info = status_info

        # ── Database info ───────────────────────────────────────
        from core.db_manager import database_summary

        db_text = database_summary()

        db_frame = ctk.CTkFrame(page, fg_color=SURFACE_COLOR, corner_radius=8)
        db_frame.pack(fill="x", padx=28, pady=(0, 16))

        ctk.CTkLabel(
            db_frame,
            text="Virus Database",
            font=ctk.CTkFont(size=15, weight="bold"),
            text_color=TEXT_PRIMARY,
        ).pack(anchor="w", padx=16, pady=(14, 8))

        db_info = ctk.CTkTextbox(
            db_frame,
            wrap="word",
            height=108,
            corner_radius=8,
            border_width=1,
            border_color=BORDER_COLOR,
            fg_color=LOG_COLOR,
            text_color=TEXT_SECONDARY,
        )
        db_info.pack(fill="x", padx=16, pady=(0, 14))
        db_info.insert("1.0", db_text)
        db_info.configure(state="disabled")

        # Store reference so we can refresh it after DB update
        self._settings_db_info = db_info

        # ── Appearance ──────────────────────────────────────────
        appearance_frame = ctk.CTkFrame(page, fg_color=SURFACE_COLOR, corner_radius=8)
        appearance_frame.pack(fill="x", padx=28, pady=(0, 16))

        ctk.CTkLabel(
            appearance_frame,
            text="Appearance",
            font=ctk.CTkFont(size=15, weight="bold"),
            text_color=TEXT_PRIMARY,
        ).pack(anchor="w", padx=16, pady=(14, 8))

        mode_var = ctk.StringVar(value=ctk.get_appearance_mode().lower())
        mode_row = ctk.CTkFrame(appearance_frame, fg_color="transparent")
        mode_row.pack(fill="x", padx=12, pady=(4, 14))

        ctk.CTkLabel(
            mode_row,
            text="Color mode:",
            font=ctk.CTkFont(size=13),
            text_color=TEXT_MUTED,
        ).pack(side="left", padx=(4, 12))

        ctk.CTkOptionMenu(
            mode_row,
            values=["dark", "light"],
            variable=mode_var,
            command=lambda v: ctk.set_appearance_mode(v),
            width=120,
            fg_color=SURFACE_ALT_COLOR,
            button_color=ACCENT_COLOR,
            button_hover_color=ACCENT_HOVER,
            text_color=TEXT_SECONDARY,
        ).pack(side="left")

        return page

    def _refresh_settings_db_info(self):
        """Refresh the database summary on the Settings page (if visible)."""
        if hasattr(self, "_settings_db_info") and self._settings_db_info.winfo_exists():
            from core.db_manager import database_summary
            self._settings_db_info.configure(state="normal")
            self._settings_db_info.delete("1.0", "end")
            self._settings_db_info.insert("1.0", database_summary())
            self._settings_db_info.configure(state="disabled")

    def _refresh_settings_status_info(self):
        """Refresh the ClamAV runtime summary on the Settings page."""
        if (
            hasattr(self, "_settings_status_info")
            and self._settings_status_info.winfo_exists()
        ):
            self._settings_status_info.configure(state="normal")
            self._settings_status_info.delete("1.0", "end")
            self._settings_status_info.insert("1.0", self._runtime_status_summary())
            self._settings_status_info.configure(state="disabled")

    def _runtime_status_summary(self) -> str:
        """Return a compact runtime/database summary for Settings."""
        status = self._startup_status
        if status is None:
            runtime = backend.detect_clamav_runtime()
            status_label = "pending startup check"
            db_label = "pending startup check"
            freshclam_label = "pending startup check"
        else:
            runtime = status.runtime
            status_label = "ready" if status.runtime_ok else "not ready"
            db_label = "ready" if status.db_found else "missing"
            freshclam_label = "available" if status.freshclam_ok else "not available"

        lines = [
            f"Runtime: {status_label}",
            f"Source: {runtime.source or 'not found'}",
            f"Version: {runtime.version or 'unknown'}",
            f"clamscan: {runtime.clamscan or 'not found'}",
            f"freshclam: {runtime.freshclam or 'not found'} ({freshclam_label})",
            f"Database: {db_label}",
        ]
        return "\n".join(lines)

    # ── Settings page: dialog-based update actions ──────────────────

    def _settings_update_runtime(self):
        """Update ClamAV with a modal progress dialog."""
        from core.updater import check_for_updates, perform_update
        from ui.update_dialog import UpdateProgressDialog

        if not backend.manages_own_runtime():
            distro = backend.distro_info()
            if distro.get("unknown") == "true":
                msg = (
                    "ClamAV updates are handled by your Linux package manager.\n\n"
                    "Update ClamAV using your distribution's normal software update tools."
                )
                command_text = None
            else:
                command_text = distro.get("update_cmd", "")
                msg = (
                    f"ClamAV updates are handled by {distro.get('pkg_manager', 'your package manager')}.\n\n"
                    "Run the command below in a terminal to update system packages, "
                    "including ClamAV."
                )
            self._show_info_dialog(
                "ClamAV Update",
                msg,
                command_text=command_text or None,
            )
            return

        dialog = UpdateProgressDialog(self, title="Update ClamAV")

        def _do_update(dialog_log):
            dialog_log("Checking for updates...\n")
            platform_entry = check_for_updates(log=dialog_log)

            if platform_entry is None:
                dialog_log("No update available.\n")
                return

            dialog_log(f"Downloading ClamAV {platform_entry.get('latest_version', '?')}...\n")
            error = perform_update(
                platform_entry,
                log=dialog_log,
                progress=None,  # could add progress bar later
            )

            if error:
                dialog_log(f"\nERROR: {error}\n")
            else:
                dialog_log("\nClamAV updated successfully!\n")
                dialog_log("Use 'Update Database' to get the latest virus definitions.\n")

        dialog.run_in_thread(_do_update)

    def _settings_update_database(self):
        """Update virus database with a modal progress dialog."""
        from core.db_manager import run_freshclam_update
        from ui.update_dialog import UpdateProgressDialog

        if self._startup_status is None or not self._startup_status.can_update_db:
            self._show_info_dialog(
                "Database Update",
                "freshclam not available.\nPlease install ClamAV first."
            )
            return

        freshclam_path = self._startup_status.runtime.freshclam
        dialog = UpdateProgressDialog(self, title="Update Virus Database")

        def _do_update(dialog_log):
            dialog_log("Running freshclam...\n")
            success, output = run_freshclam_update(
                freshclam_path, conf_path=None, log_callback=dialog_log
            )

            if success:
                dialog_log("\nDatabase update completed.\n")
                # Re-check status
                status = check_startup()
                self._startup_status = status
                if status.db_found:
                    dialog_log("Virus database is now ready.\n")
                self.after(100, self._refresh_settings_status_info)
                self.after(100, self._refresh_settings_db_info)
            else:
                dialog_log("\nDatabase update failed. See output above.\n")

        dialog.run_in_thread(_do_update)

    def _show_info_dialog(
        self,
        title: str,
        message: str,
        *,
        command_text: str | None = None,
    ):
        """Show a styled info dialog."""
        from ui.info_dialog import InfoDialog

        InfoDialog(self, title, message, command_text=command_text)

    def _switch_page(self, key: str):
        """Show the page identified by *key* and hide all others."""
        self._current_page = key

        if key == "quarantine":
            self._refresh_quarantine_page()

        # Update nav button highlighting
        for k, btn in self._nav_buttons.items():
            if btn is None:
                continue
            if k == key:
                btn.configure(
                    fg_color=ACCENT_COLOR,
                    text_color=WHITE_TEXT,
                )
            else:
                btn.configure(
                    fg_color="transparent",
                    text_color=TEXT_SECONDARY,
                )

        # Show only the selected page
        for k, page in self._pages.items():
            if k == key:
                page.pack(fill="both", expand=True)
            else:
                page.pack_forget()

    def on_quarantine_changed(self):
        """Called by child windows after quarantine contents change."""
        self._refresh_quarantine_nav()
        if hasattr(self, "_quarantine_list"):
            self._refresh_quarantine_page()

    # ── update runtime button (check + confirm + install) ───────────

    def update_runtime(self):
        """Handle 'Update ClamAV' button.

        Windows: check manifest, download, install.
        Linux:   tell the user their package manager handles ClamAV updates.
        """
        if not backend.manages_own_runtime():
            # Linux — system package manager handles it
            distro = backend.distro_info()
            if distro.get("unknown") == "true":
                self.log(
                    "ClamAV updates are handled by your system's package manager.\n"
                    "Use your package manager to update all installed packages.\n\n"
                )
            else:
                self.log(
                    f"ClamAV updates are handled by {distro.get('pkg_manager', 'your package manager')}.\n"
                    f"To update ClamAV, run this command in a terminal:\n\n"
                    f"  {distro.get('update_cmd', '')}\n\n"
                )
            return

        # Windows — check for updates, download, install
        # If update is already staged (from background check), install directly
        if hasattr(self, "_pending_update_entry") and self._pending_update_entry:
            entry = self._pending_update_entry
            self._pending_update_entry = None
            self._start_clamav_update(entry)
            return

        # Otherwise, check first then install
        self.log("Checking for ClamAV updates...\n")

        from core.updater import check_for_updates, perform_update

        def _run():
            try:
                def _log(msg):
                    self.output_queue.put(msg)

                platform_entry = check_for_updates(log=_log)

                if platform_entry is None:
                    self.output_queue.put(
                        "ClamAV runtime is up to date.\n\n"
                    )
                    return

                latest = platform_entry.get("latest_version", "?")
                self.output_queue.put(
                    f"\nClamAV {latest} is available.\n"
                )
                self.output_queue.put(("__UPDATE_AVAILABLE__", platform_entry))

            except Exception as e:
                self.output_queue.put(
                    f"\nUpdate check failed: {e}\n"
                )

        thread = threading.Thread(target=_run, daemon=True)
        thread.start()

    # ── folder / exclude / about / log ──────────────────────────────

    def choose_scan_folder(self):
        folder = FilePickerDialog.ask_directory(
            self,
            title="Choose scan folder",
            start_dir=self.scan_path.get().strip(),
        )
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

    # ── activity indicator ──────────────────────────────────────────

    def start_activity(self, text="Activity: running"):
        self.activity_label.configure(text=text)

        if not self.activity_label.winfo_ismapped():
            self.activity_label.pack(
                fill="x", padx=26, pady=(0, 3), before=self.log_frame
            )

        if not self.activity_bar.winfo_ismapped():
            self.activity_bar.pack(
                fill="x", padx=26, pady=(0, 10), before=self.log_frame
            )

        self.activity_bar.start()

    def stop_activity(self, text="Activity: idle"):
        self.activity_bar.stop()
        self.activity_bar.pack_forget()
        self.activity_label.configure(text=text)
        self.activity_label.pack_forget()

    # ── scan flow ───────────────────────────────────────────────────

    def start_scan(self):
        """Start a scan of the user-selected folder."""
        path = self.scan_path.get().strip()

        if not path or not os.path.exists(path):
            self.log("ERROR: Scan folder does not exist.\n")
            return

        self._start_scan_flow(path, "Starting scan")

    def start_quick_scan(self):
        """Start a Quick System Scan of common malware locations."""
        paths = backend.quick_scan_paths()

        if not paths:
            self.log(
                "ERROR: No quick scan paths available on this system.\n"
            )
            return

        self._start_scan_flow(paths, "Quick System Scan")

    def _start_scan_flow(self, scan_roots, scan_label: str):
        """Common scan setup: validate, reset state, log, start thread.

        *scan_roots* may be a single path string or a list of path strings.
        """
        # Validate ClamAV is available
        runtime = backend.detect_clamav_runtime()
        if not runtime.found:
            self.log("ERROR: ClamAV not found. Please install ClamAV first.\n")
            self._show_startup_dialog()
            return

        if self._startup_status is not None and not self._startup_status.db_found:
            self._offer_database_update(
                "Virus database not found.\n\n"
                "LibreWard will not start a scan until the database is ready.\n\n"
                "Update the database now?"
            )
            self.log(
                "Scan cancelled because the virus database is missing. "
                "Update the database first.\n"
            )
            return

        self.save_config()

        self.stop_requested = False
        self.summary_started = False
        self.total_files = 0
        self.scanned_files = 0
        self.counted_files = set()

        self.progress.set(0)
        self.percent_label.configure(text="0%")
        self.status_label.configure(text="preparing")
        self.current_file_label.configure(text="-")
        self.start_activity("Activity: preparing scan...")

        self.start_button.configure(state="disabled")
        self.quick_scan_button.configure(state="disabled")
        self.stop_button.configure(state="normal")

        active_excludes = get_active_exclude_patterns(
            self.enabled_common_excludes, self.user_excludes
        )

        self.log("\n========================================\n")
        self.log(f"{scan_label}\n")

        if isinstance(scan_roots, str):
            self.log(f"Scan folder: {scan_roots}\n")
        else:
            self.log(f"Scan folders ({len(scan_roots)}):\n")
            for p in scan_roots:
                self.log(f"  - {p}\n")

        if active_excludes:
            self.log("Active excludes:\n")
            for item in active_excludes:
                self.log(f"  - {item}\n")
        else:
            self.log("Active excludes: none\n")

        self.log(f"ClamAV: {runtime.clamscan}\n")
        self.log(f"Version: {runtime.version or 'unknown'}\n")
        self.log("Mode: one clamscan process, progress parsed from --verbose output\n")
        self.log("========================================\n\n")

        thread = threading.Thread(
            target=self.run_scan,
            args=(scan_roots, active_excludes, runtime.clamscan),
            daemon=True,
        )
        thread.start()

    def run_scan(self, scan_root, exclude_patterns, clamscan_path):
        infected_found = False
        errors_found = False
        infected = []
        total = 0
        scan_summary_lines: list[str] = []

        try:
            self.output_queue.put("Counting files before scan...\n")
            self.output_queue.put(("__STATUS__", "counting files"))
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

            cmd = build_clamscan_command(
                scan_root, exclude_patterns, clamscan_path=clamscan_path
            )

            self.output_queue.put(
                "Command: clamscan with selected scan roots and active excludes\n\n"
            )

            self.output_queue.put(("__STATUS__", "scanning"))
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

                    file_path, status = parse_clamscan_result_line(
                        line, known_files
                    )

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
                        if self.summary_started:
                            scan_summary_lines.append(line)

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
            self.output_queue.put(
                "ERROR: clamscan not found. Please install ClamAV first.\n"
            )
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
                "summary_lines": scan_summary_lines,
            }
            self.output_queue.put(("__SCAN_DONE__", result))

    def stop_scan(self):
        self.stop_requested = True
        self.log("\nStopping scan...\n")
        self.status_label.configure(text="stopping")

        if self.activity_label.winfo_ismapped():
            self.activity_label.configure(text="Activity: stopping...")

        if self.process and self.process.poll() is None:
            try:
                backend.stop_process(self.process)
            except Exception as e:
                self.log(f"ERROR while stopping scan: {e}\n")

    # ── queue processing ────────────────────────────────────────────

    def process_output_queue(self):
        try:
            while True:
                msg = self.output_queue.get_nowait()

                # --- Scan lifecycle ---
                if isinstance(msg, tuple) and msg[0] == "__SCAN_DONE__":
                    self.start_button.configure(state="normal")
                    self.quick_scan_button.configure(state="normal")
                    self.stop_button.configure(state="disabled")

                    if self.stop_requested:
                        self.status_label.configure(text="stopped")
                        self.stop_activity("Activity: stopped")
                    else:
                        self.status_label.configure(text="finished")
                        self.stop_activity("Activity: finished")

                    self.current_file_label.configure(text="-")
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
                        text=f"found {self.total_files} files"
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
                            text=f"scanning {current} / {total}"
                        )

                elif isinstance(msg, tuple) and msg[0] == "__CURRENT_FILE__":
                    path = msg[1]
                    display = path
                    if len(display) > 125:
                        display = "..." + display[-122:]
                    self.current_file_label.configure(
                        text=display
                    )

                # --- Startup / lifecycle ---
                elif isinstance(msg, tuple) and msg[0] == "__NO_CLAMAV__":
                    self._refresh_settings_status_info()
                    self._show_startup_dialog()

                elif isinstance(msg, tuple) and msg[0] == "__NO_DATABASE__":
                    self._refresh_settings_status_info()

                elif isinstance(msg, tuple) and msg[0] == "__STARTUP_DONE__":
                    self._refresh_settings_status_info()
                    self._refresh_settings_db_info()

                # --- Update flow ---
                elif isinstance(msg, tuple) and msg[0] == "__UPDATE_AVAILABLE__":
                    platform_entry = msg[1]
                    latest = platform_entry.get("latest_version", "?")
                    answer = messagebox.askyesno(
                        "ClamAV Update Available",
                        f"ClamAV {latest} is available.\n\n"
                        "Do you want to download and install it now?",
                    )
                    if answer:
                        self._pending_update_entry = None
                        self._start_clamav_update(platform_entry)
                    else:
                        # Save for later if user clicks "Update ClamAV"
                        self._pending_update_entry = platform_entry

                elif isinstance(msg, tuple) and msg[0] == "__UPDATE_PROGRESS__":
                    # Progress bar during update download (re-use scan progress bar)
                    self.progress.set(msg[1])
                    pct = int(msg[1] * 100)
                    self.status_label.configure(
                        text=f"downloading update... {pct}%"
                    )

                elif isinstance(msg, tuple) and msg[0] == "__UPDATE_DONE__":
                    success = msg[1]
                    self.progress.set(0)
                    self.stop_activity("Activity: idle")
                    if success:
                        # Re-check status
                        status = check_startup()
                        self._startup_status = status
                        self._refresh_settings_status_info()
                        self._refresh_settings_db_info()
                        self.status_label.configure(
                            text="ClamAV updated"
                        )
                        if not status.db_found:
                            self._offer_database_update(
                                "ClamAV is updated, but the virus database is missing.\n\n"
                                "Update the database now?"
                            )
                    else:
                        self.status_label.configure(
                            text="update failed"
                        )

                elif isinstance(msg, tuple) and msg[0] == "__DB_UPDATE_DONE__":
                    success = msg[1]
                    self.stop_activity("Activity: idle")
                    if success:
                        self.status_label.configure(
                            text="database updated"
                        )
                        # Refresh settings DB info if the widget exists
                        self._refresh_settings_status_info()
                        self._refresh_settings_db_info()
                    else:
                        self.status_label.configure(
                            text="database update failed"
                        )

                else:
                    self.log(str(msg))

        except queue.Empty:
            pass

        self.after(100, self.process_output_queue)
