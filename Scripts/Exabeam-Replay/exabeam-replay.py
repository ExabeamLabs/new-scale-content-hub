"""Exabeam Replay desktop application — raw collector replay edition."""
from __future__ import annotations

import json
import os
import queue
import sys
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any, Callable

from credential_store import CredentialEncryptionError, decrypt_secret, encrypt_secret
from replay_core import APP_VERSION, ConfigurationError, ReplayEngine, make_transport, prepare_source

APP_TITLE = "Exabeam Replay"

# Dark palette based on Exabeam's public green/blue brand guidance.
APP_BG = "#0B1018"
SURFACE = "#121A25"
SURFACE_ALT = "#172230"
NAV_BG = "#05080D"
NAV_SURFACE = "#101824"
NAV_TEXT = "#F7F9FC"
NAV_MUTED = "#8F9DB0"
BORDER = "#263446"
BORDER_STRONG = "#34465D"
TEXT = "#F4F7FB"
TEXT_SECONDARY = "#CAD4E0"
TEXT_MUTED = "#91A0B3"
BLUE = "#006BFF"
BLUE_DARK = "#0054CC"
BLUE_SOFT = "#102A4F"
GREEN = "#009D00"
GREEN_BRIGHT = "#4CDB00"
GREEN_SOFT = "#12351A"
PURPLE = "#8D00FF"
WARNING = "#F5B544"
WARNING_SOFT = "#352810"
DANGER = "#FF6B61"
DANGER_SOFT = "#3A191B"
SUCCESS = "#4CDB00"
CODE_BG = "#070B12"
CODE_TEXT = "#D7E2F0"
CODE_MUTED = "#7F8EA3"

SANS = ("Segoe UI", 10)
SANS_SM = ("Segoe UI", 9)
SANS_XS = ("Segoe UI", 8)
SANS_MD = ("Segoe UI", 11)
SANS_BOLD = ("Segoe UI", 10, "bold")
TITLE = ("Segoe UI", 23, "bold")
SECTION_TITLE = ("Segoe UI", 14, "bold")
MONO = ("Consolas", 9)
MONO_MD = ("Consolas", 10)
PREVIEW_LIMIT = 2 * 1024 * 1024


def resource_path(*parts: str) -> Path:
    """Resolve bundled assets both from source and PyInstaller one-file builds."""
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
    return base.joinpath(*parts)


def format_bytes(value: int) -> str:
    number = float(value)
    for suffix in ("B", "KB", "MB", "GB", "TB"):
        if number < 1024 or suffix == "TB":
            return f"{int(number)} B" if suffix == "B" else f"{number:.1f} {suffix}"
        number /= 1024
    return f"{number:.1f} TB"


def shorten_digest(value: str, width: int = 18) -> str:
    if not value:
        return "Not validated"
    return value if len(value) <= width else f"{value[:width]}…"


class AutoHideText(tk.Frame):
    """Text widget whose scrollbars appear only when content overflows."""

    def __init__(self, parent: tk.Widget, **text_options: Any) -> None:
        background = str(text_options.get("bg", CODE_BG))
        super().__init__(parent, bg=background, bd=0, highlightthickness=0)
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        self._vertical = ttk.Scrollbar(self, orient="vertical", style="Dark.Vertical.TScrollbar")
        self._horizontal = ttk.Scrollbar(self, orient="horizontal", style="Dark.Horizontal.TScrollbar")
        self._text = tk.Text(
            self,
            yscrollcommand=self._on_vertical_scroll,
            xscrollcommand=self._on_horizontal_scroll,
            **text_options,
        )
        self._text.grid(row=0, column=0, sticky="nsew")
        self._vertical.configure(command=self._text.yview)
        self._horizontal.configure(command=self._text.xview)

        # Re-check after layout changes, text edits, and wrap-mode changes.
        self._text.bind("<Configure>", lambda _event: self.after_idle(self._refresh_scrollbars), add="+")
        self._text.bind("<<Modified>>", lambda _event: self.after_idle(self._refresh_scrollbars), add="+")
        self.after_idle(self._refresh_scrollbars)

    def _on_vertical_scroll(self, first: str, last: str) -> None:
        self._vertical.set(first, last)
        if float(first) <= 0.0 and float(last) >= 1.0:
            self._vertical.grid_remove()
        else:
            self._vertical.grid(row=0, column=1, sticky="ns")

    def _on_horizontal_scroll(self, first: str, last: str) -> None:
        self._horizontal.set(first, last)
        if float(first) <= 0.0 and float(last) >= 1.0:
            self._horizontal.grid_remove()
        else:
            self._horizontal.grid(row=1, column=0, sticky="ew")

    def _refresh_scrollbars(self) -> None:
        if self.winfo_exists():
            self._text.yview_moveto(self._text.yview()[0])
            self._text.xview_moveto(self._text.xview()[0])

    # Delegate the Text methods used by the application while keeping geometry
    # management on this outer frame.
    def configure(self, cnf: Any = None, **kwargs: Any) -> Any:
        result = self._text.configure(cnf, **kwargs)
        self.after_idle(self._refresh_scrollbars)
        return result

    config = configure

    def get(self, *args: Any) -> str:
        return self._text.get(*args)

    def insert(self, *args: Any) -> None:
        self._text.insert(*args)
        self.after_idle(self._refresh_scrollbars)

    def delete(self, *args: Any) -> None:
        self._text.delete(*args)
        self.after_idle(self._refresh_scrollbars)

    def bind(self, sequence: str | None = None, func: Callable[..., Any] | None = None, add: str | bool | None = None) -> str:
        return self._text.bind(sequence, func, add)

    def edit_modified(self, arg: bool | None = None) -> bool:
        if arg is None:
            return bool(self._text.edit_modified())
        self._text.edit_modified(arg)
        return bool(arg)

    def focus_set(self) -> None:
        self._text.focus_set()

    def tag_config(self, *args: Any, **kwargs: Any) -> Any:
        return self._text.tag_config(*args, **kwargs)

    tag_configure = tag_config

    def see(self, *args: Any) -> None:
        self._text.see(*args)
        self.after_idle(self._refresh_scrollbars)


class ScrollablePage(tk.Frame):
    """A simple vertical scroll container for configuration pages."""

    def __init__(self, parent: tk.Widget) -> None:
        super().__init__(parent, bg=APP_BG)
        self.canvas = tk.Canvas(self, bg=APP_BG, highlightthickness=0, bd=0)
        scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview, style="Dark.Vertical.TScrollbar")
        self.content = tk.Frame(self.canvas, bg=APP_BG)
        self.window_id = self.canvas.create_window((0, 0), window=self.content, anchor="nw")
        self.canvas.configure(yscrollcommand=scrollbar.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        self.content.bind("<Configure>", self._sync_region)
        self.canvas.bind("<Configure>", self._sync_width)
        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel, add="+")
        self.canvas.bind_all("<Button-4>", self._on_linux_scroll, add="+")
        self.canvas.bind_all("<Button-5>", self._on_linux_scroll, add="+")

    def _sync_region(self, _event: tk.Event) -> None:
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def _sync_width(self, event: tk.Event) -> None:
        self.canvas.itemconfigure(self.window_id, width=event.width)

    def _contains_pointer(self, event: tk.Event) -> bool:
        widget = self.winfo_containing(event.x_root, event.y_root)
        while widget is not None:
            if widget in (self, self.canvas, self.content):
                return True
            widget = getattr(widget, "master", None)
        return False

    def _on_mousewheel(self, event: tk.Event) -> None:
        if self._contains_pointer(event):
            self.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

    def _on_linux_scroll(self, event: tk.Event) -> None:
        if self._contains_pointer(event):
            self.canvas.yview_scroll(-1 if event.num == 4 else 1, "units")


class App(tk.Tk):
    PAGE_META = {
        "source": ("Source", ""),
        "destination": ("Destination", ""),
        "replay": ("Control", ""),
    }

    def __init__(self) -> None:
        # Windows must receive the application identity before Tk creates its
        # top-level window; otherwise the taskbar may retain the Python icon.
        if sys.platform == "win32":
            try:
                import ctypes

                ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("Exabeam.Replay")
            except (AttributeError, OSError):
                pass
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1320x850")
        self.minsize(1120, 720)
        self.configure(bg=APP_BG)
        try:
            self._app_icon = tk.PhotoImage(file=str(resource_path("assets", "exabeam-icon.png")))
            self.iconphoto(True, self._app_icon)
            if sys.platform == "win32":
                self.iconbitmap(default=str(resource_path("assets", "exabeam-icon.ico")))
                self.after_idle(self._set_windows_taskbar_icon)
        except tk.TclError:
            self._app_icon = None
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        self._queue: queue.Queue = queue.Queue()
        self._engine: ReplayEngine | None = None
        self._active_run_id: str | None = None
        self._selected_file: Path | None = None
        self._paused = False
        self._start_mono: float | None = None
        self._total = 0
        self._selected_page = "source"
        self._source_digest = ""
        self._source_count: int | None = None
        self._source_size: int | None = None
        self._typed_source_digest = ""
        self._typed_source_count: int | None = None
        self._typed_source_size = 0
        self._nav_items: dict[str, tuple[tk.Frame, tk.Label, tk.Label]] = {}
        self._pages: dict[str, ScrollablePage] = {}
        self._last_destination: str | None = None
        self._connection_states: dict[str, dict[str, Any]] = {}
        self._connection_test_id = 0

        self._styles()
        self._variables()
        self._load_destination_settings()
        self._build()
        self._bindings()
        self._refresh_destination()
        self._show_page("source")
        self._update_summary()
        self.after(100, self._poll_queue)

    def _set_windows_taskbar_icon(self) -> None:
        """Apply the bundled Exabeam icon to the native Windows top-level window."""
        if sys.platform != "win32":
            return
        try:
            import ctypes
            from ctypes import wintypes

            icon_path = str(resource_path("assets", "exabeam-icon.ico"))
            user32 = ctypes.windll.user32
            user32.LoadImageW.argtypes = [
                wintypes.HINSTANCE, wintypes.LPCWSTR, wintypes.UINT,
                ctypes.c_int, ctypes.c_int, wintypes.UINT,
            ]
            user32.LoadImageW.restype = wintypes.HANDLE
            user32.GetParent.argtypes = [wintypes.HWND]
            user32.GetParent.restype = wintypes.HWND
            user32.SendMessageW.argtypes = [
                wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM
            ]
            user32.SendMessageW.restype = ctypes.c_ssize_t
            image_icon = 1
            load_from_file = 0x0010
            load_default_size = 0x0040
            wm_seticon = 0x0080
            icon_small = 0
            icon_big = 1
            handle = user32.LoadImageW(
                None, icon_path, image_icon, 0, 0, load_from_file | load_default_size
            )
            if not handle:
                return
            native_window = user32.GetParent(self.winfo_id()) or self.winfo_id()
            user32.SendMessageW(native_window, wm_seticon, icon_big, handle)
            user32.SendMessageW(native_window, wm_seticon, icon_small, handle)
            self._native_icon_handle = handle
        except (AttributeError, OSError, tk.TclError):
            return

    def _styles(self) -> None:
        style = ttk.Style(self)
        style.theme_use("clam")
        self.option_add("*TCombobox*Listbox.background", SURFACE_ALT)
        self.option_add("*TCombobox*Listbox.foreground", TEXT)
        self.option_add("*TCombobox*Listbox.selectBackground", BLUE)
        self.option_add("*TCombobox*Listbox.selectForeground", "#FFFFFF")
        style.configure(
            "Modern.TCombobox",
            background=SURFACE,
            fieldbackground=SURFACE,
            foreground=TEXT,
            arrowcolor=TEXT_SECONDARY,
            bordercolor=BORDER_STRONG,
            lightcolor=BORDER_STRONG,
            darkcolor=BORDER_STRONG,
            padding=8,
            font=SANS,
        )
        style.map(
            "Modern.TCombobox",
            fieldbackground=[("readonly", SURFACE)],
            foreground=[("readonly", TEXT)],
            selectbackground=[("readonly", SURFACE)],
            selectforeground=[("readonly", TEXT)],
            bordercolor=[("focus", BLUE)],
        )
        style.configure(
            "Replay.Horizontal.TProgressbar",
            troughcolor="#1B2736",
            background=BLUE,
            bordercolor="#1B2736",
            lightcolor=BLUE,
            darkcolor=BLUE,
            thickness=8,
        )
        for scrollbar_style in ("Dark.Vertical.TScrollbar", "Dark.Horizontal.TScrollbar"):
            style.configure(
                scrollbar_style,
                gripcount=0,
                background="#2B3A4E",
                troughcolor=CODE_BG,
                bordercolor=CODE_BG,
                lightcolor="#2B3A4E",
                darkcolor="#2B3A4E",
                arrowcolor=TEXT_MUTED,
                relief="flat",
            )
            style.map(
                scrollbar_style,
                background=[("active", "#3A4C63"), ("pressed", "#465B75")],
                arrowcolor=[("active", TEXT_SECONDARY)],
            )

    def _variables(self) -> None:
        self.file_var = tk.StringVar()
        self.source_mode_var = tk.StringVar(value="text")
        self.destination_var = tk.StringVar(value="Webhook Collector")
        self.host_var = tk.StringVar(value="127.0.0.1")
        self.port_var = tk.IntVar(value=514)
        self.webhook_url_var = tk.StringVar()
        self.webhook_token_var = tk.StringVar()
        self.show_token_var = tk.BooleanVar(value=False)
        self.save_destination_var = tk.BooleanVar(value=False)
        self.file_wrap_var = tk.BooleanVar(value=True)
        self.paste_wrap_var = tk.BooleanVar(value=True)
        self.verify_tls_var = tk.BooleanVar(value=True)
        self.ca_file_var = tk.StringVar()
        self.loop_count_var = tk.IntVar(value=1)
        self.pass_interval_var = tk.IntVar(value=0)
        self.save_reports_var = tk.BooleanVar(value=False)

        for variable in (self.source_mode_var, self.destination_var, self.host_var, self.port_var, self.webhook_url_var):
            variable.trace_add("write", lambda *_args: self._update_summary())
        for variable in (self.destination_var, self.host_var, self.port_var, self.webhook_url_var, self.webhook_token_var, self.verify_tls_var, self.ca_file_var):
            variable.trace_add("write", lambda *_args: self._maybe_save_destination())
        for variable in (self.destination_var, self.host_var, self.port_var, self.webhook_url_var, self.verify_tls_var, self.ca_file_var):
            variable.trace_add("write", lambda *_args: self._show_connection_status())

    def _bindings(self) -> None:
        self.bind_all("<Control-o>", lambda _event: self._browse())
        self.bind_all("<Control-r>", lambda _event: self._start())
        self.bind_all("<Control-1>", lambda _event: self._show_page("source"))
        self.bind_all("<Control-2>", lambda _event: self._show_page("destination"))
        self.bind_all("<Control-3>", lambda _event: self._show_page("replay"))

    def _build(self) -> None:
        shell = tk.Frame(self, bg=APP_BG)
        shell.pack(fill="both", expand=True)
        shell.grid_rowconfigure(0, weight=1)
        shell.grid_columnconfigure(1, weight=1)

        self._build_navigation(shell)
        workspace = tk.Frame(shell, bg=APP_BG)
        workspace.grid(row=0, column=1, sticky="nsew")
        workspace.grid_rowconfigure(1, weight=1)
        workspace.grid_columnconfigure(0, weight=1)
        self._build_workspace_header(workspace)
        self._build_workspace_body(workspace)

    # ---------- Navigation ----------
    def _build_navigation(self, parent: tk.Widget) -> None:
        nav = tk.Frame(parent, bg=NAV_BG, width=222)
        nav.grid(row=0, column=0, sticky="nsw")
        nav.grid_propagate(False)

        # Media Kit-inspired accent line across the top of the sidebar.
        tk.Frame(nav, bg=GREEN, height=4).pack(fill="x", side="top")

        brand = tk.Frame(nav, bg=NAV_BG)
        brand.pack(fill="x", padx=22, pady=(22, 28))
        brand_row = tk.Frame(brand, bg=NAV_BG)
        brand_row.pack(anchor="w")
        try:
            self._brand_icon = tk.PhotoImage(file=str(resource_path("assets", "exabeam-icon.png")))
            tk.Label(brand_row, image=self._brand_icon, bg=NAV_BG, bd=0).pack(side="left", anchor="n", padx=(0, 9), pady=(5, 0))
        except tk.TclError:
            self._brand_icon = None
        wordmark = tk.Frame(brand_row, bg=NAV_BG)
        wordmark.pack(side="left", anchor="n")
        tk.Label(wordmark, text="exabeam", bg=NAV_BG, fg=NAV_TEXT, font=("Segoe UI", 16, "bold")).pack(anchor="w")
        tk.Label(wordmark, text="Replay", bg=NAV_BG, fg=NAV_TEXT, font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(3, 0))

        tk.Label(nav, text="WORKFLOW", bg=NAV_BG, fg="#617087", font=("Segoe UI", 8, "bold")).pack(anchor="w", padx=24, pady=(0, 8))
        self._nav_item(nav, "source", "Source", "Log sample")
        self._nav_item(nav, "destination", "Destination", "Collector endpoint")
        self._nav_item(nav, "replay", "Control", "Replay settings")

        spacer = tk.Frame(nav, bg=NAV_BG)
        spacer.pack(fill="both", expand=True)

        footer = tk.Frame(nav, bg=NAV_BG)
        footer.pack(fill="x", padx=20, pady=(0, 18))
        tk.Label(footer, text=f"Version {APP_VERSION}", bg=NAV_BG, fg=NAV_MUTED, font=SANS_XS).pack(anchor="w")
        tk.Label(footer, text="Community project · not official", bg=NAV_BG, fg="#617087", font=SANS_XS).pack(anchor="w", pady=(2, 0))

    def _nav_item(self, parent: tk.Widget, key: str, title: str, subtitle: str) -> None:
        holder = tk.Frame(parent, bg=NAV_BG, cursor="hand2")
        holder.pack(fill="x", padx=12, pady=3)
        indicator = tk.Frame(holder, bg=NAV_BG, width=3)
        indicator.pack(side="left", fill="y")
        body = tk.Frame(holder, bg=NAV_BG)
        body.pack(side="left", fill="x", expand=True, padx=(10, 6), pady=9)
        title_label = tk.Label(body, text=title, bg=NAV_BG, fg=NAV_TEXT, font=("Segoe UI", 10, "bold"))
        title_label.pack(anchor="w")
        subtitle_label = tk.Label(body, text=subtitle, bg=NAV_BG, fg=NAV_MUTED, font=SANS_XS)
        subtitle_label.pack(anchor="w", pady=(2, 0))
        self._nav_items[key] = (indicator, title_label, subtitle_label)
        for widget in (holder, indicator, body, title_label, subtitle_label):
            widget.bind("<Button-1>", lambda _event, page=key: self._show_page(page))

    # ---------- Workspace ----------
    def _build_workspace_header(self, parent: tk.Widget) -> None:
        header = tk.Frame(parent, bg=APP_BG)
        header.grid(row=0, column=0, sticky="ew", padx=30, pady=(24, 12))
        header.grid_columnconfigure(0, weight=1)
        heading = tk.Frame(header, bg=APP_BG)
        heading.grid(row=0, column=0, sticky="w")
        self.page_title = tk.Label(heading, text="Source", bg=APP_BG, fg=TEXT, font=TITLE)
        self.page_title.pack(anchor="w")
        self.page_subtitle = tk.Label(heading, text="", bg=APP_BG, fg=TEXT_MUTED, font=SANS_MD)

        self.status_chip = tk.Label(header, text="●  IDLE", bg=SURFACE, fg=TEXT_MUTED, font=("Segoe UI", 9, "bold"), padx=13, pady=7, highlightbackground=BORDER, highlightthickness=1)
        self.status_chip.grid(row=0, column=1, sticky="e")

    def _build_workspace_body(self, parent: tk.Widget) -> None:
        body = tk.Frame(parent, bg=APP_BG)
        body.grid(row=1, column=0, sticky="nsew", padx=30, pady=(0, 28))
        body.grid_rowconfigure(0, weight=1)
        body.grid_columnconfigure(0, weight=1)
        body.grid_columnconfigure(1, weight=0, minsize=430)

        self.page_host = tk.Frame(body, bg=APP_BG)
        self.page_host.grid(row=0, column=0, sticky="nsew", padx=(0, 18))
        self.page_host.grid_rowconfigure(0, weight=1)
        self.page_host.grid_columnconfigure(0, weight=1)

        for key in ("source", "destination", "replay"):
            page = ScrollablePage(self.page_host)
            page.grid(row=0, column=0, sticky="nsew")
            self._pages[key] = page
        self._build_source_page(self._pages["source"].content)
        self._build_destination_page(self._pages["destination"].content)
        self._build_replay_page(self._pages["replay"].content)

        console = tk.Frame(body, bg=SURFACE, width=430, highlightbackground=BORDER, highlightthickness=1)
        console.grid(row=0, column=1, sticky="nsew")
        console.grid_propagate(False)
        console.grid_rowconfigure(5, weight=1)
        console.grid_columnconfigure(0, weight=1)
        self._build_console(console)

    # ---------- Page primitives ----------
    def _section(self, parent: tk.Widget, title: str, subtitle: str = "") -> tk.Frame:
        card = tk.Frame(parent, bg=SURFACE, highlightbackground=BORDER, highlightthickness=1)
        card.pack(fill="x", pady=(0, 14), padx=(0, 2))
        header = tk.Frame(card, bg=SURFACE)
        header.pack(fill="x", padx=20, pady=(18, 13))
        tk.Label(header, text=title, bg=SURFACE, fg=TEXT, font=SECTION_TITLE).pack(anchor="w")
        if subtitle:
            tk.Label(header, text=subtitle, bg=SURFACE, fg=TEXT_MUTED, font=SANS_SM, wraplength=330, justify="left").pack(anchor="w", pady=(4, 0))
        body = tk.Frame(card, bg=SURFACE)
        body.pack(fill="x", padx=20, pady=(0, 20))
        return body

    def _field_label(self, parent: tk.Widget, text: str, required: bool = False) -> None:
        row = tk.Frame(parent, bg=SURFACE)
        row.pack(fill="x", pady=(11, 5))
        tk.Label(row, text=text, bg=SURFACE, fg=TEXT_SECONDARY, font=SANS_BOLD).pack(side="left")
        if required:
            tk.Label(row, text="Required", bg=SURFACE, fg=BLUE, font=SANS_XS).pack(side="right")

    def _entry(self, parent: tk.Widget, variable: tk.Variable, mono: bool = False, readonly: bool = False, show: str | None = None) -> tk.Entry:
        kwargs: dict[str, Any] = {
            "textvariable": variable,
            "bg": SURFACE_ALT,
            "fg": TEXT,
            "insertbackground": TEXT,
            "relief": "flat",
            "highlightbackground": BORDER_STRONG,
            "highlightcolor": BLUE,
            "highlightthickness": 1,
            "font": MONO_MD if mono else SANS,
            "bd": 0,
        }
        if readonly:
            kwargs.update(state="readonly", readonlybackground=SURFACE_ALT)
        if show is not None:
            kwargs["show"] = show
        entry = tk.Entry(parent, **kwargs)
        entry.pack(fill="x", ipady=9)
        return entry

    def _spin(self, parent: tk.Widget, variable: tk.Variable, low: float, high: float, increment: float = 1) -> tk.Spinbox:
        spin = tk.Spinbox(
            parent,
            from_=low,
            to=high,
            increment=increment,
            textvariable=variable,
            bg=SURFACE_ALT,
            fg=TEXT,
            insertbackground=TEXT,
            buttonbackground=SURFACE_ALT,
            relief="flat",
            highlightbackground=BORDER_STRONG,
            highlightcolor=BLUE,
            highlightthickness=1,
            font=MONO_MD,
            bd=0,
        )
        spin.pack(fill="x", ipady=8)
        return spin

    def _check(self, parent: tk.Widget, text: str, variable: tk.BooleanVar, command: Callable[[], None] | None = None) -> tk.Checkbutton:
        check = tk.Checkbutton(
            parent,
            text=text,
            variable=variable,
            command=command,
            bg=SURFACE,
            fg=TEXT_SECONDARY,
            activebackground=SURFACE,
            activeforeground=TEXT,
            selectcolor=SURFACE_ALT,
            font=SANS,
            bd=0,
            highlightthickness=0,
            cursor="hand2",
        )
        check.pack(anchor="w", pady=4)
        return check

    def _button(
        self,
        parent: tk.Widget,
        text: str,
        command: Callable[[], None],
        variant: str = "secondary",
        compact: bool = False,
    ) -> tk.Button:
        styles = {
            "primary": (BLUE, "#FFFFFF", BLUE_DARK),
            "success": (GREEN, "#FFFFFF", SUCCESS),
            "secondary": (SURFACE, TEXT_SECONDARY, BLUE_SOFT),
            "soft": (BLUE_SOFT, "#8EC5FF", "#173A67"),
            "danger": (DANGER_SOFT, DANGER, "#4B2023"),
            "dark": (NAV_BG, NAV_TEXT, NAV_SURFACE),
        }
        bg, fg, active = styles[variant]
        return tk.Button(
            parent,
            text=text,
            command=command,
            bg=bg,
            fg=fg,
            activebackground=active,
            activeforeground=fg,
            disabledforeground="#627086",
            relief="flat",
            bd=0,
            highlightthickness=1 if variant == "secondary" else 0,
            highlightbackground=BORDER_STRONG,
            cursor="hand2",
            font=("Segoe UI", 9 if compact else 10, "bold"),
            padx=12 if compact else 17,
            pady=6 if compact else 9,
        )

    def _info_banner(self, parent: tk.Widget, title: str, text: str, tone: str = "blue") -> None:
        palette = {
            "blue": (BLUE_SOFT, BLUE, BLUE_DARK),
            "green": (GREEN_SOFT, GREEN, SUCCESS),
            "warning": (WARNING_SOFT, WARNING, WARNING),
        }
        bg, accent, fg = palette[tone]
        box = tk.Frame(parent, bg=bg, highlightbackground=accent, highlightthickness=1)
        box.pack(fill="x", pady=(10, 0))
        marker = tk.Frame(box, bg=accent, width=4)
        marker.pack(side="left", fill="y")
        content = tk.Frame(box, bg=bg)
        content.pack(side="left", fill="x", expand=True, padx=13, pady=11)
        tk.Label(content, text=title, bg=bg, fg=fg, font=SANS_BOLD).pack(anchor="w")
        tk.Label(content, text=text, bg=bg, fg=TEXT_SECONDARY, font=SANS_SM, wraplength=320, justify="left").pack(anchor="w", pady=(3, 0))

    # ---------- Source page ----------
    def _build_source_page(self, parent: tk.Widget) -> None:
        select = self._section(parent, "Log sample")

        tabs = tk.Frame(select, bg=SURFACE_ALT, highlightbackground=BORDER_STRONG, highlightthickness=1)
        tabs.pack(fill="x", pady=(0, 14))
        tabs.grid_columnconfigure((0, 1), weight=1)
        self.source_tab_buttons: dict[str, tk.Button] = {}
        for column, (key, label) in enumerate((("text", "Paste logs"), ("file", "Upload sample"))):
            button = tk.Button(
                tabs,
                text=label,
                command=lambda selected=key: self._set_source_mode(selected),
                bg=SURFACE_ALT,
                fg=TEXT_SECONDARY,
                activebackground=BLUE_SOFT,
                activeforeground="#FFFFFF",
                relief="flat",
                bd=0,
                font=SANS_BOLD,
                cursor="hand2",
                padx=12,
                pady=10,
            )
            button.grid(row=0, column=column, sticky="ew")
            self.source_tab_buttons[key] = button

        self.source_panel_host = tk.Frame(select, bg=SURFACE)
        self.source_panel_host.pack(fill="both", expand=True)
        self.source_panel_host.grid_columnconfigure(0, weight=1)

        # File source tab.
        self.source_file_panel = tk.Frame(self.source_panel_host, bg=SURFACE)
        self.source_file_panel.grid(row=0, column=0, sticky="nsew")
        dropzone = tk.Frame(self.source_file_panel, bg=SURFACE_ALT, highlightbackground=BORDER_STRONG, highlightthickness=1)
        dropzone.pack(fill="x")
        icon = tk.Canvas(dropzone, width=52, height=52, bg=SURFACE_ALT, highlightthickness=0)
        icon.pack(pady=(20, 7))
        icon.create_rectangle(13, 9, 39, 43, outline=BLUE, width=2)
        icon.create_line(19, 20, 33, 20, fill=BLUE, width=2)
        icon.create_line(19, 27, 33, 27, fill=BLUE, width=2)
        icon.create_line(19, 34, 29, 34, fill=BLUE, width=2)
        tk.Label(dropzone, text="Select a source log file", bg=SURFACE_ALT, fg=TEXT, font=("Segoe UI", 12, "bold")).pack()
        tk.Frame(dropzone, bg=SURFACE_ALT, height=8).pack()
        browse = self._button(dropzone, "Choose file", self._browse, "primary")
        browse.pack(pady=(0, 20))

        selected = tk.Frame(self.source_file_panel, bg=SURFACE)
        selected.pack(fill="x", pady=(16, 0))
        self.file_name_label = tk.Label(selected, text="No file selected", bg=SURFACE, fg=TEXT, font=SANS_BOLD)
        self.file_name_label.pack(anchor="w")
        self.file_meta_label = tk.Label(selected, text="Select a file to preview and replay.", bg=SURFACE, fg=TEXT_MUTED, font=SANS_SM)
        self.file_meta_label.pack(anchor="w", pady=(3, 0))
        file_path_row = tk.Frame(selected, bg=SURFACE)
        file_path_row.pack(fill="x", pady=(9, 0))
        file_entry = self._entry(file_path_row, self.file_var, mono=True, readonly=True)
        file_entry.pack_forget()
        file_entry.pack(side="left", fill="x", expand=True, ipady=9)
        change = self._button(file_path_row, "Change", self._browse, "secondary", compact=True)
        change.pack(side="left", padx=(8, 0))

        preview_shell = tk.Frame(self.source_file_panel, bg=CODE_BG, highlightbackground="#27374B", highlightthickness=1)
        preview_shell.pack(fill="both", expand=True, pady=(16, 0))
        preview_bar = tk.Frame(preview_shell, bg="#0E1622")
        preview_bar.pack(fill="x")
        tk.Label(preview_bar, text="SOURCE PREVIEW", bg="#0E1622", fg=CODE_MUTED, font=("Segoe UI", 8, "bold")).pack(side="left", padx=12, pady=8)
        self.preview_badge = tk.Label(preview_bar, text="NO FILE", bg="#1A2A3E", fg=CODE_MUTED, font=SANS_XS, padx=8, pady=3)
        self.preview_badge.pack(side="right", padx=9, pady=5)
        tk.Checkbutton(
            preview_bar,
            text="Word wrap",
            variable=self.file_wrap_var,
            command=lambda: self._apply_word_wrap(self.source_text, self.file_wrap_var),
            bg="#0E1622",
            fg="#AFC0D5",
            activebackground="#0E1622",
            activeforeground="#FFFFFF",
            selectcolor="#1A2A3E",
            font=SANS_XS,
            bd=0,
            highlightthickness=0,
            cursor="hand2",
        ).pack(side="right", padx=(0, 3), pady=5)
        self.source_text = AutoHideText(
            preview_shell,
            height=10,
            bg=CODE_BG,
            fg=CODE_TEXT,
            insertbackground=CODE_TEXT,
            relief="flat",
            font=MONO_MD,
            wrap="word",
            state="disabled",
            bd=0,
            padx=12,
            pady=10,
        )
        self.source_text.pack(fill="both", expand=True)

        # Typed source tab. Tk adds a display-only terminal newline at "end";
        # replay reads through "end-1c" so only operator-entered text is sent.
        self.source_text_panel = tk.Frame(self.source_panel_host, bg=SURFACE)
        self.source_text_panel.grid(row=0, column=0, sticky="nsew")
        typed_shell = tk.Frame(self.source_text_panel, bg=CODE_BG, highlightbackground="#27374B", highlightthickness=1)
        typed_shell.pack(fill="both", expand=True)
        typed_bar = tk.Frame(typed_shell, bg="#0E1622")
        typed_bar.pack(fill="x")
        tk.Label(typed_bar, text="PASTE LOGS", bg="#0E1622", fg=CODE_MUTED, font=("Segoe UI", 8, "bold")).pack(side="left", padx=12, pady=8)
        tk.Label(typed_bar, text="UTF-8", bg="#1A2A3E", fg="#B8D6FF", font=SANS_XS, padx=8, pady=3).pack(side="right", padx=9, pady=5)
        tk.Checkbutton(
            typed_bar,
            text="Word wrap",
            variable=self.paste_wrap_var,
            command=lambda: self._apply_word_wrap(self.typed_source_text, self.paste_wrap_var),
            bg="#0E1622",
            fg="#AFC0D5",
            activebackground="#0E1622",
            activeforeground="#FFFFFF",
            selectcolor="#1A2A3E",
            font=SANS_XS,
            bd=0,
            highlightthickness=0,
            cursor="hand2",
        ).pack(side="right", padx=(0, 3), pady=5)
        self.typed_source_text = AutoHideText(
            typed_shell,
            height=20,
            bg=CODE_BG,
            fg=CODE_TEXT,
            insertbackground=CODE_TEXT,
            relief="flat",
            font=MONO_MD,
            wrap="word",
            undo=True,
            bd=0,
            padx=12,
            pady=10,
        )
        self.typed_source_text.pack(fill="both", expand=True)
        self.typed_source_text.bind("<<Modified>>", self._typed_source_changed)
        self.typed_source_text.edit_modified(False)
        tk.Label(
            self.source_text_panel,
            text="Replays the UTF-8 bytes exactly as entered.",
            bg=SURFACE,
            fg=TEXT_MUTED,
            font=SANS_SM,
        ).pack(anchor="w", pady=(8, 0))

        # Ensure Paste logs is visibly selected on first launch.
        self._set_source_mode("text")

    # ---------- Destination page ----------
    def _build_destination_page(self, parent: tk.Widget) -> None:
        transport = self._section(parent, "Transport")
        self._field_label(transport, "Destination type", required=True)
        combo = ttk.Combobox(
            transport,
            textvariable=self.destination_var,
            state="readonly",
            values=["Webhook Collector", "Syslog UDP", "Syslog TCP", "Syslog TLS"],
            style="Modern.TCombobox",
        )
        combo.pack(fill="x")
        combo.bind("<<ComboboxSelected>>", self._on_destination_selected)

        self.destination_fields = self._section(parent, "Collector endpoint")

        saved = self._section(parent, "Save destination")
        self._check(
            saved,
            "Save destination for future sessions",
            self.save_destination_var,
            self._toggle_save_destination,
        )
        tk.Label(
            saved,
            text="Webhook tokens are encrypted before they are written to disk.",
            bg=SURFACE,
            fg=TEXT_MUTED,
            font=SANS_XS,
        ).pack(anchor="w", pady=(1, 0))

        verify = self._section(parent, "Connection test")
        actions = tk.Frame(verify, bg=SURFACE)
        actions.pack(fill="x")
        self.test_button = self._button(actions, "Test destination", self._test_destination, "soft")
        self.test_button.pack(side="left")
        tk.Label(verify, text="No sample data is sent.", bg=SURFACE, fg=TEXT_MUTED, font=SANS_SM).pack(anchor="w", pady=(10, 0))

        self.connection_status_bar = tk.Frame(
            verify,
            bg=GREEN_SOFT,
            highlightbackground=GREEN,
            highlightthickness=1,
        )
        self.connection_status_label = tk.Label(
            self.connection_status_bar,
            text="",
            bg=GREEN_SOFT,
            fg=TEXT,
            font=SANS_BOLD,
            anchor="w",
            justify="left",
            wraplength=520,
        )
        self.connection_status_label.pack(fill="x", padx=12, pady=10)
        self._show_connection_status()

    def _connection_fingerprint(self, destination: str | None = None) -> tuple[Any, ...]:
        destination = destination or self.destination_var.get()
        if destination == "Webhook Collector":
            return (destination, self.webhook_url_var.get().strip())
        try:
            port = int(self.port_var.get())
        except (tk.TclError, ValueError):
            port = 0
        if destination == "Syslog TLS":
            return (
                destination,
                self.host_var.get().strip(),
                port,
                bool(self.verify_tls_var.get()),
                self.ca_file_var.get().strip(),
            )
        return (destination, self.host_var.get().strip(), port)

    def _show_connection_status(self) -> None:
        if not hasattr(self, "connection_status_bar"):
            return
        destination = self.destination_var.get()
        state = self._connection_states.get(destination)
        if not state or state.get("fingerprint") != self._connection_fingerprint(destination):
            self.connection_status_bar.pack_forget()
            return

        status = state.get("status")
        if status == "success":
            bg, border, fg, prefix = GREEN_SOFT, GREEN, SUCCESS, "SUCCESS"
        elif status == "failed":
            bg, border, fg, prefix = DANGER_SOFT, DANGER, DANGER, "FAILED"
        else:
            bg, border, fg, prefix = BLUE_SOFT, BLUE, "#8EC5FF", "TESTING"
        self.connection_status_bar.config(bg=bg, highlightbackground=border)
        self.connection_status_label.config(
            text=f"{prefix} · {state.get('message', destination)}",
            bg=bg,
            fg=fg,
        )
        if not self.connection_status_bar.winfo_manager():
            self.connection_status_bar.pack(fill="x", pady=(12, 0))

    def _settings_path(self) -> Path:
        if sys.platform == "win32" and os.getenv("APPDATA"):
            base = Path(os.environ["APPDATA"])
        elif sys.platform == "darwin":
            base = Path.home() / "Library" / "Application Support"
        else:
            base = Path(os.getenv("XDG_CONFIG_HOME", Path.home() / ".config"))
        return base / "exabeam-replay" / "destination.json"

    def _load_destination_settings(self) -> None:
        path = self._settings_path()
        if not path.is_file():
            return
        try:
            saved = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(saved, dict) or saved.get("schema_version") != 2:
                return
            destination = saved.get("destination_type")
            if destination in {"Webhook Collector", "Syslog UDP", "Syslog TCP", "Syslog TLS"}:
                self.destination_var.set(destination)
                self._last_destination = destination
            self.host_var.set(str(saved.get("host", self.host_var.get())))
            self.port_var.set(int(saved.get("port", self.port_var.get())))
            self.webhook_url_var.set(str(saved.get("webhook_url", "")))
            self.verify_tls_var.set(bool(saved.get("verify_tls", True)))
            self.ca_file_var.set(str(saved.get("ca_file", "")))
            self.webhook_token_var.set(decrypt_secret(saved.get("encrypted_webhook_token")))
            self.save_destination_var.set(True)
        except (
            OSError,
            ValueError,
            TypeError,
            json.JSONDecodeError,
            CredentialEncryptionError,
        ):
            # Invalid or machine-incompatible saved settings must never prevent startup.
            self.webhook_token_var.set("")
            return

    def _save_destination_settings(self) -> bool:
        if not self.save_destination_var.get():
            return False
        path = self._settings_path()
        try:
            encrypted_token = encrypt_secret(self.webhook_token_var.get())
            payload = {
                "schema_version": 2,
                "destination_type": self.destination_var.get(),
                "host": self.host_var.get().strip(),
                "port": int(self.port_var.get()),
                "webhook_url": self.webhook_url_var.get().strip(),
                "encrypted_webhook_token": encrypted_token,
                "verify_tls": bool(self.verify_tls_var.get()),
                "ca_file": self.ca_file_var.get().strip(),
            }
            path.parent.mkdir(parents=True, exist_ok=True)
            temporary = path.with_suffix(".tmp")
            temporary.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            try:
                temporary.chmod(0o600)
            except OSError:
                pass
            temporary.replace(path)
            try:
                path.chmod(0o600)
            except OSError:
                pass
            return True
        except (OSError, ValueError, tk.TclError, CredentialEncryptionError):
            return False

    def _maybe_save_destination(self) -> None:
        if getattr(self, "save_destination_var", None) is not None and self.save_destination_var.get():
            self._save_destination_settings()

    def _toggle_save_destination(self) -> None:
        path = self._settings_path()
        if self.save_destination_var.get():
            if self._save_destination_settings():
                self._log("ok", "Destination settings and encrypted credentials will be restored in future sessions.")
            else:
                self.save_destination_var.set(False)
                self._log("err", "Destination settings could not be saved securely.")
                messagebox.showerror("Save destination", "Destination settings could not be saved securely.")
        else:
            try:
                path.unlink(missing_ok=True)
                path.with_suffix(".tmp").unlink(missing_ok=True)
            except OSError as exc:
                self._log("err", f"Could not delete saved destination settings: {exc}")
                return
            self._log("info", "Saved destination settings file was deleted.")

    @staticmethod
    def _apply_word_wrap(widget: tk.Text, variable: tk.BooleanVar) -> None:
        widget.configure(wrap="word" if variable.get() else "none")

    def _toggle_token(self) -> None:
        if hasattr(self, "webhook_token_entry"):
            self.webhook_token_entry.config(show="" if self.show_token_var.get() else "•")

    def _add_ca_controls(self) -> None:
        self._check(self.destination_fields, "Verify TLS certificate", self.verify_tls_var, self._update_summary)
        self._field_label(self.destination_fields, "Optional CA certificate file")
        ca_row = tk.Frame(self.destination_fields, bg=SURFACE)
        ca_row.pack(fill="x")
        ca_entry = self._entry(ca_row, self.ca_file_var, mono=True)
        ca_entry.pack_forget()
        ca_entry.pack(side="left", fill="x", expand=True, ipady=9)
        choose_ca = self._button(ca_row, "Browse", self._browse_ca, "secondary", compact=True)
        choose_ca.pack(side="left", padx=(8, 0))

    def _on_destination_selected(self, _event: tk.Event | None = None) -> None:
        """Apply the transport's standard port when the user selects it."""
        destination = self.destination_var.get()
        default_ports = {"Syslog UDP": 514, "Syslog TCP": 514, "Syslog TLS": 6514}
        if destination in default_ports:
            self.port_var.set(default_ports[destination])
        self._last_destination = destination
        self._refresh_destination()

    def _refresh_destination(self) -> None:
        if not hasattr(self, "destination_fields"):
            return
        for child in self.destination_fields.winfo_children():
            child.destroy()

        destination = self.destination_var.get()
        self._last_destination = destination
        if destination == "Webhook Collector":
            self._field_label(self.destination_fields, "Webhook URL", required=True)
            self._entry(self.destination_fields, self.webhook_url_var, mono=True)

            self._field_label(self.destination_fields, "Bearer token", required=True)
            token_row = tk.Frame(self.destination_fields, bg=SURFACE)
            token_row.pack(fill="x")
            self.webhook_token_entry = self._entry(token_row, self.webhook_token_var, mono=True, show="•")
            self.webhook_token_entry.pack_forget()
            self.webhook_token_entry.pack(side="left", fill="x", expand=True, ipady=9)
            show = tk.Checkbutton(
                token_row, text="Show", variable=self.show_token_var, command=self._toggle_token,
                bg=SURFACE, fg=TEXT_SECONDARY, activebackground=SURFACE, activeforeground=TEXT,
                selectcolor=SURFACE_ALT, font=SANS_SM, bd=0, highlightthickness=0, cursor="hand2",
            )
            show.pack(side="left", padx=(10, 0))

            tk.Label(self.destination_fields, text="Maximum request size: 32 MB", bg=SURFACE, fg=TEXT_MUTED, font=SANS_SM).pack(anchor="w", pady=(12, 0))
        else:
            row = tk.Frame(self.destination_fields, bg=SURFACE)
            row.pack(fill="x")
            row.grid_columnconfigure(0, weight=3)
            row.grid_columnconfigure(1, weight=1)

            host = tk.Frame(row, bg=SURFACE)
            host.grid(row=0, column=0, sticky="ew", padx=(0, 8))
            self._field_label(host, "Collector host", required=True)
            self._entry(host, self.host_var, mono=True)

            port = tk.Frame(row, bg=SURFACE)
            port.grid(row=0, column=1, sticky="ew", padx=(8, 0))
            self._field_label(port, "Port", required=True)
            self._spin(port, self.port_var, 1, 65535)

            if destination == "Syslog TLS":
                self._add_ca_controls()

        self._update_summary()
        self._show_connection_status()

    # ---------- Replay page ----------
    def _build_replay_page(self, parent: tk.Widget) -> None:
        looping = self._section(parent, "Repeat")
        row = tk.Frame(looping, bg=SURFACE)
        row.pack(fill="x")
        row.grid_columnconfigure((0, 1), weight=1)

        passes = tk.Frame(row, bg=SURFACE)
        passes.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        self._field_label(passes, "Number of passes")
        self._spin(passes, self.loop_count_var, 1, 1_000_000)

        interval = tk.Frame(row, bg=SURFACE)
        interval.grid(row=0, column=1, sticky="ew", padx=(8, 0))
        self._field_label(interval, "Interval between passes (seconds)")
        self._spin(interval, self.pass_interval_var, 0, 86_400)

        evidence = self._section(parent, "Evidence")
        self._check(evidence, "Save run reports to the reports folder", self.save_reports_var)

    # ---------- Console ----------
    def _build_console(self, parent: tk.Widget) -> None:
        heading = tk.Frame(parent, bg=SURFACE)
        heading.grid(row=0, column=0, sticky="ew", padx=20, pady=(20, 12))
        heading.grid_columnconfigure(0, weight=1)
        tk.Label(heading, text="Run console", bg=SURFACE, fg=TEXT, font=SECTION_TITLE).grid(row=0, column=0, sticky="w")
        # Intentionally no secondary heading: keep the console compact.

        actions = tk.Frame(parent, bg=SURFACE)
        actions.grid(row=1, column=0, sticky="ew", padx=20)
        self.start_button = self._button(actions, "Start replay", self._start, "primary")
        self.start_button.pack(side="left", fill="x", expand=True)
        self.pause_button = self._button(actions, "Pause", self._pause, "secondary", compact=True)
        self.pause_button.pack(side="left", padx=(8, 0))
        self.stop_button = self._button(actions, "Stop", self._stop, "danger", compact=True)
        self.stop_button.pack(side="left", padx=(8, 0))
        self.pause_button.config(state="disabled")
        self.stop_button.config(state="disabled")

        overview = tk.Frame(parent, bg=SURFACE_ALT, highlightbackground=BORDER, highlightthickness=1)
        overview.grid(row=2, column=0, sticky="ew", padx=20, pady=(16, 0))
        tk.Label(overview, text="RUN OVERVIEW", bg=SURFACE_ALT, fg=TEXT_MUTED, font=("Segoe UI", 8, "bold")).pack(anchor="w", padx=13, pady=(12, 7))
        self.summary_source = self._summary_row(overview, "Source", "Not selected")
        self.summary_destination = self._summary_row(
            overview,
            "Destination",
            "Webhook · URL not set",
            wraplength=260,
        )
        tk.Frame(overview, bg=SURFACE_ALT, height=8).pack()

        metrics = tk.Frame(parent, bg=SURFACE)
        metrics.grid(row=3, column=0, sticky="ew", padx=20, pady=(16, 0))
        metrics.grid_columnconfigure((0, 1, 2), weight=1)
        self.sent_label = self._metric(metrics, 0, "Sent", "0", SUCCESS)
        self.eps_label = self._metric(metrics, 1, "EPS", "0", BLUE)
        self.error_label = self._metric(metrics, 2, "Failed", "0", DANGER)

        progress_box = tk.Frame(parent, bg=SURFACE)
        progress_box.grid(row=4, column=0, sticky="ew", padx=20, pady=(16, 12))
        row = tk.Frame(progress_box, bg=SURFACE)
        row.pack(fill="x")
        tk.Label(row, text="Current pass", bg=SURFACE, fg=TEXT_SECONDARY, font=SANS_BOLD).pack(side="left")
        self.percent_label = tk.Label(row, text="0%", bg=SURFACE, fg=TEXT_MUTED, font=SANS_SM)
        self.percent_label.pack(side="right")
        self.progress = ttk.Progressbar(progress_box, style="Replay.Horizontal.TProgressbar", mode="determinate")
        self.progress.pack(fill="x", pady=(7, 6))
        times = tk.Frame(progress_box, bg=SURFACE)
        times.pack(fill="x")
        self.elapsed_label = tk.Label(times, text="Elapsed 0s", bg=SURFACE, fg=TEXT_MUTED, font=SANS_XS)
        self.elapsed_label.pack(side="left")
        self.eta_label = tk.Label(times, text="ETA —", bg=SURFACE, fg=TEXT_MUTED, font=SANS_XS)
        self.eta_label.pack(side="right")

        activity_shell = tk.Frame(parent, bg=CODE_BG, highlightbackground="#27374B", highlightthickness=1)
        activity_shell.grid(row=5, column=0, sticky="nsew", padx=20, pady=(0, 16))
        activity_shell.grid_rowconfigure(1, weight=1)
        activity_shell.grid_columnconfigure(0, weight=1)
        activity_header = tk.Frame(activity_shell, bg="#0E1622")
        activity_header.grid(row=0, column=0, sticky="ew")
        tk.Label(activity_header, text="ACTIVITY", bg="#0E1622", fg=CODE_MUTED, font=("Segoe UI", 8, "bold")).pack(side="left", padx=12, pady=8)
        clear = tk.Button(activity_header, text="Clear", command=self._clear_activity, bg="#0E1622", fg="#9FB0C6", activebackground="#1B2A3D", activeforeground="#FFFFFF", relief="flat", bd=0, cursor="hand2", font=SANS_XS)
        clear.pack(side="right", padx=5)
        export = tk.Button(activity_header, text="Export", command=self._export_activity, bg="#0E1622", fg="#9FB0C6", activebackground="#1B2A3D", activeforeground="#FFFFFF", relief="flat", bd=0, cursor="hand2", font=SANS_XS)
        export.pack(side="right", padx=5)
        self.activity = AutoHideText(
            activity_shell,
            bg=CODE_BG,
            fg=CODE_TEXT,
            insertbackground=CODE_TEXT,
            relief="flat",
            font=MONO,
            wrap="word",
            state="disabled",
            bd=0,
            padx=11,
            pady=9,
        )
        self.activity.grid(row=1, column=0, sticky="nsew")
        for name, color in (("info", "#8EC5FF"), ("ok", "#72E06A"), ("warn", "#F2C66D"), ("err", "#FF8B84"), ("dim", "#B7C4D4"), ("time", "#66758A")):
            self.activity.tag_config(name, foreground=color)

        footer = tk.Frame(parent, bg=SURFACE)
        footer.grid(row=6, column=0, sticky="ew", padx=20, pady=(0, 17))
        self.total_label = tk.Label(footer, text="Records/pass —", bg=SURFACE, fg=TEXT_MUTED, font=SANS_XS)
        self.total_label.pack(side="left")
        self.loops_label = tk.Label(footer, text="Passes 0", bg=SURFACE, fg=TEXT_MUTED, font=SANS_XS)
        self.loops_label.pack(side="right")

        self._log("info", "Ready. Choose Webhook Collector or syslog. TCP and TLS use RFC 6587 octet-counting framing.")

    def _summary_row(
        self,
        parent: tk.Widget,
        title: str,
        value: str,
        *,
        wraplength: int | None = None,
    ) -> tk.Label:
        row = tk.Frame(parent, bg=SURFACE_ALT)
        row.pack(fill="x", padx=13, pady=3)
        tk.Label(row, text=title, bg=SURFACE_ALT, fg=TEXT_MUTED, font=SANS_SM, width=11, anchor="w").pack(side="left")
        label = tk.Label(
            row,
            text=value,
            bg=SURFACE_ALT,
            fg=TEXT,
            font=SANS_BOLD,
            anchor="e",
            justify="right",
            wraplength=wraplength or 0,
        )
        label.pack(side="right", fill="x", expand=True)
        return label

    def _metric(self, parent: tk.Widget, column: int, title: str, value: str, color: str) -> tk.Label:
        frame = tk.Frame(parent, bg=SURFACE_ALT, highlightbackground=BORDER, highlightthickness=1)
        frame.grid(row=0, column=column, sticky="ew", padx=(0 if column == 0 else 5, 0 if column == 2 else 5))
        tk.Label(frame, text=title, bg=SURFACE_ALT, fg=TEXT_MUTED, font=SANS_XS).pack(anchor="w", padx=10, pady=(9, 1))
        label = tk.Label(frame, text=value, bg=SURFACE_ALT, fg=color, font=("Segoe UI", 18, "bold"))
        label.pack(anchor="w", padx=10, pady=(0, 9))
        return label

    # ---------- Page switching ----------
    def _show_page(self, key: str) -> None:
        if key not in self._pages:
            return
        self._selected_page = key
        self._pages[key].tkraise()
        title, subtitle = self.PAGE_META[key]
        self.page_title.config(text=title)
        self.page_subtitle.config(text=subtitle)
        for item_key, (indicator, title_label, subtitle_label) in self._nav_items.items():
            active = item_key == key
            indicator.config(bg=BLUE if active else NAV_BG)
            title_label.config(fg="#FFFFFF" if active else NAV_TEXT)
            subtitle_label.config(fg="#C3D0E1" if active else NAV_MUTED)

    # ---------- Source actions ----------
    def _typed_payload(self) -> bytes:
        if not hasattr(self, "typed_source_text"):
            return b""
        return self.typed_source_text.get("1.0", "end-1c").encode("utf-8")

    def _set_source_mode(self, mode: str) -> None:
        if mode not in {"file", "text"} or not hasattr(self, "source_file_panel"):
            return
        self.source_mode_var.set(mode)
        if mode == "file":
            self.source_file_panel.tkraise()
        else:
            self.source_text_panel.tkraise()
        for key, button in self.source_tab_buttons.items():
            active = key == mode
            button.config(
                bg=BLUE_SOFT if active else SURFACE_ALT,
                fg="#FFFFFF" if active else TEXT_SECONDARY,
                activebackground=BLUE_SOFT if active else SURFACE_ALT,
            )
        self._refresh_source_metrics()
        self._update_summary()

    def _typed_source_changed(self, _event: tk.Event | None = None) -> None:
        if not hasattr(self, "typed_source_text") or not self.typed_source_text.edit_modified():
            return
        self.typed_source_text.edit_modified(False)
        self._typed_source_digest = ""
        self._typed_source_count = None
        self._typed_source_size = len(self._typed_payload())
        if self.source_mode_var.get() == "text":
            self._refresh_source_metrics()
            self._update_summary()

    def _refresh_source_metrics(self) -> None:
        """Refresh internal source metadata; no integrity panel is shown in the UI."""
        if self.source_mode_var.get() == "text":
            self._typed_source_size = len(self._typed_payload())


    def _set_preview(self, raw: bytes, truncated: bool) -> None:
        text = raw.decode("utf-8", errors="backslashreplace")
        if truncated:
            text += "\n\n[Preview truncated at 2 MB. The complete file will be replayed.]"
        self.source_text.config(state="normal")
        self.source_text.delete("1.0", "end")
        self.source_text.insert("1.0", text)
        self.source_text.config(state="disabled")
        self.preview_badge.config(text="TRUNCATED" if truncated else "READ ONLY", bg="#1B3555", fg="#B8D6FF")

    def _browse(self) -> None:
        self._set_source_mode("file")
        selected = filedialog.askopenfilename(
            title="Select log file",
            filetypes=[("Log files", "*.log *.txt *.json *.ndjson *.csv *.syslog"), ("All files", "*.*")],
        )
        if not selected:
            return
        path = Path(selected)
        try:
            size = path.stat().st_size
            with path.open("rb") as handle:
                preview = handle.read(PREVIEW_LIMIT)
                truncated = bool(handle.read(1))
        except OSError as exc:
            messagebox.showerror("Cannot open source", str(exc))
            return
        self._selected_file = path
        self._source_size = size
        self._source_digest = ""
        self._source_count = None
        self.file_var.set(str(path))
        self.file_name_label.config(text=path.name)
        self.file_meta_label.config(text=f"{format_bytes(size)}" + (" · preview limited to 2 MB" if truncated else " · complete preview"))
        self._set_preview(preview, truncated)
        self._update_summary()
        self._log("info", f"Selected {path.name} ({format_bytes(size)}); replay source remains binary and immutable.")

    def _browse_ca(self) -> None:
        selected = filedialog.askopenfilename(title="Select CA certificate", filetypes=[("Certificates", "*.pem *.crt *.cer"), ("All files", "*.*")])
        if selected:
            self.ca_file_var.set(selected)

    def _destination_key(self) -> str:
        return {
            "Webhook Collector": "webhook",
            "Syslog UDP": "syslog_udp",
            "Syslog TCP": "syslog_tcp",
            "Syslog TLS": "syslog_tls",
        }[self.destination_var.get()]

    def _base_config(self, include_source: bool = True) -> dict[str, Any]:
        config: dict[str, Any] = {
            "exact_passthrough": True,
            "format": "exact-bytes",
            "boundary": "physical-line",
            "destination": self._destination_key(),
            "dry_run": False,
            "save_reports": bool(self.save_reports_var.get()),
            "host": self.host_var.get().strip(),
            "port": int(self.port_var.get()),
            "webhook_url": self.webhook_url_var.get().strip(),
            "webhook_token": self.webhook_token_var.get().strip(),
            "webhook_content_type": "application/octet-stream",
            "framing": "none",
            "verify_tls": True if self._destination_key() == "webhook" else bool(self.verify_tls_var.get()),
            "ca_file": "" if self._destination_key() == "webhook" else self.ca_file_var.get().strip(),
            "batch_size": 1,
            "speed": 1.0,
            "eps_cap": 0,
            "ts_rewrite": False,
            "loop": int(self.loop_count_var.get()) > 1,
            "loop_max": int(self.loop_count_var.get()),
            "loop_interval": int(self.pass_interval_var.get()),
            "timeout": 15,
            "retries": 0,
            "retry_backoff": 1.0,
            "stop_on_failure": True,
            "report_dir": "reports",
        }
        if include_source:
            if self.source_mode_var.get() == "file" and self._selected_file:
                config["source_path"] = str(self._selected_file)
            elif self.source_mode_var.get() == "text":
                config["source_bytes"] = self._typed_payload()
        return config


    # ---------- Destination actions ----------
    def _test_destination(self) -> None:
        destination = self.destination_var.get()
        fingerprint = self._connection_fingerprint(destination)
        self._connection_test_id += 1
        test_id = self._connection_test_id
        try:
            # Tk variables must only be read on the GUI thread. Capture the
            # complete immutable test configuration before starting the worker.
            config = self._base_config(include_source=False)
            config["dry_run"] = False
        except (ConfigurationError, ValueError, OSError, tk.TclError) as exc:
            self._connection_states[destination] = {
                "status": "failed",
                "message": str(exc),
                "fingerprint": fingerprint,
                "test_id": test_id,
            }
            self._show_connection_status()
            self._log("err", f"{destination}: {exc}")
            return

        self._connection_states[destination] = {
            "status": "testing",
            "message": f"Testing {destination}…",
            "fingerprint": fingerprint,
            "test_id": test_id,
        }
        self._show_connection_status()
        self.test_button.config(state="disabled")
        self._log("info", f"Testing {destination} connectivity…")

        def worker() -> None:
            try:
                transport = make_transport(config)
                result = transport.test()
                transport.close()
                self._queue.put({
                    "run_id": None,
                    "kind": "connection_test",
                    "result": result,
                    "destination": destination,
                    "fingerprint": fingerprint,
                    "test_id": test_id,
                })
            except (ConfigurationError, ValueError, OSError) as exc:
                self._queue.put({
                    "run_id": None,
                    "kind": "connection_test_error",
                    "message": str(exc),
                    "destination": destination,
                    "fingerprint": fingerprint,
                    "test_id": test_id,
                })

        threading.Thread(target=worker, daemon=True).start()

    # ---------- Run actions ----------
    def _start(self) -> None:
        if self._engine and self._engine.alive:
            return
        try:
            if self.source_mode_var.get() == "file":
                if not self._selected_file or not self._selected_file.is_file():
                    raise ConfigurationError("Select a source file first.")
            elif not self._typed_payload():
                raise ConfigurationError("Paste or type at least one character to replay.")
            config = self._base_config()
            if config["destination"] == "webhook":
                if not config["webhook_url"]:
                    raise ConfigurationError("Enter the Webhook Collector URL.")
                if not config["webhook_token"]:
                    raise ConfigurationError("Enter the Webhook Collector bearer token.")
            elif not config["host"]:
                raise ConfigurationError("Enter a syslog collector host.")
        except (ConfigurationError, ValueError, OSError) as exc:
            messagebox.showerror("Cannot start replay", str(exc))
            self._log("err", str(exc))
            has_source = bool(self._selected_file) if self.source_mode_var.get() == "file" else bool(self._typed_payload())
            self._show_page("source" if not has_source else "destination")
            return

        self._reset_stats()
        self._engine = ReplayEngine(config, self._queue)
        self._active_run_id = self._engine.run_id
        self._start_mono = time.monotonic()
        self._paused = False
        self.start_button.config(state="disabled", text="Running…")
        self.pause_button.config(state="normal", text="Pause")
        self.stop_button.config(state="normal")
        self._set_status("running")
        self._engine.start()

    def _pause(self) -> None:
        if not self._engine or not self._engine.alive:
            return
        if self._paused:
            self._engine.resume()
            self._paused = False
            self.pause_button.config(text="Pause")
            self._set_status("running")
            self._log("info", "Replay resumed.")
        else:
            self._engine.pause()
            self._paused = True
            self.pause_button.config(text="Resume")
            self._set_status("paused")
            self._log("warn", "Replay paused.")

    def _stop(self) -> None:
        if self._engine and self._engine.alive:
            self._engine.stop()
            self.stop_button.config(state="disabled")
            self.pause_button.config(state="disabled")
            self._set_status("stopping")
            self._log("warn", "Stop requested; waiting for the active operation to exit.")

    def _reset_stats(self) -> None:
        self._total = 0
        self.sent_label.config(text="0")
        self.eps_label.config(text="0")
        self.error_label.config(text="0")
        self.total_label.config(text="Records/pass —")
        self.loops_label.config(text="Passes 0")
        self.progress["value"] = 0
        self.percent_label.config(text="0%")
        self.elapsed_label.config(text="Elapsed 0s")
        self.eta_label.config(text="ETA —")

    def _set_status(self, status: str) -> None:
        mapping = {
            "idle": ("●  IDLE", SURFACE, TEXT_MUTED, BORDER),
            "running": ("●  RUNNING", GREEN_SOFT, SUCCESS, "#275D32"),
            "paused": ("●  PAUSED", WARNING_SOFT, WARNING, "#6A5224"),
            "stopping": ("●  STOPPING", WARNING_SOFT, WARNING, "#6A5224"),
            "completed": ("✓  COMPLETE", GREEN_SOFT, SUCCESS, "#275D32"),
            "stopped": ("■  STOPPED", WARNING_SOFT, WARNING, "#6A5224"),
            "failed": ("✕  FAILED", DANGER_SOFT, DANGER, "#713237"),
        }
        text, bg, fg, border = mapping.get(status, (status.upper(), SURFACE, TEXT_MUTED, BORDER))
        self.status_chip.config(text=text, bg=bg, fg=fg, highlightbackground=border)

    def _update_summary(self) -> None:
        if not hasattr(self, "summary_source"):
            return
        if self.source_mode_var.get() == "text":
            typed_size = len(self._typed_payload())
            source_text = f"Pasted logs · {format_bytes(typed_size)}" if typed_size else "Pasted logs · empty"
        else:
            source_text = self._selected_file.name if self._selected_file else "Not selected"
        try:
            if self.destination_var.get() == "Webhook Collector":
                destination = f"Webhook · {self.webhook_url_var.get() or 'URL not set'}"
            else:
                destination = f"{self.destination_var.get()} · {self.host_var.get() or '—'}:{int(self.port_var.get())}"
        except (tk.TclError, ValueError):
            destination = f"{self.destination_var.get()} · incomplete"
        self.summary_source.config(text=source_text)
        self.summary_destination.config(text=destination)

    def _poll_queue(self) -> None:
        try:
            while True:
                message = self._queue.get_nowait()
                kind = message.get("kind")
                if kind in {"connection_test", "connection_test_error"}:
                    self.test_button.config(state="normal")
                    destination = message.get("destination", self.destination_var.get())
                    fingerprint = message.get("fingerprint")
                    current = self._connection_states.get(destination, {})
                    if current.get("test_id") != message.get("test_id"):
                        continue
                    if kind == "connection_test":
                        result = message["result"]
                        self._connection_states[destination] = {
                            "status": "success" if result.ok else "failed",
                            "message": result.message,
                            "fingerprint": fingerprint,
                            "test_id": message.get("test_id"),
                        }
                        self._log("ok" if result.ok else "err", f"{destination}: {result.message}")
                    else:
                        error_message = message["message"]
                        self._connection_states[destination] = {
                            "status": "failed",
                            "message": error_message,
                            "fingerprint": fingerprint,
                            "test_id": message.get("test_id"),
                        }
                        self._log("err", f"{destination}: {error_message}")
                    self._show_connection_status()
                    continue
                if message.get("run_id") != self._active_run_id:
                    continue
                if kind == "log":
                    self._log(message["level"], message["msg"])
                elif kind == "total":
                    self._total = message["count"]
                    self.total_label.config(text=f"Records/pass {self._total:,}")
                elif kind == "progress":
                    pct = int(message["progress"] * 100)
                    self.progress["value"] = pct
                    self.percent_label.config(text=f"{pct}%")
                    self.sent_label.config(text=f"{message['sent']:,}")
                    self.error_label.config(text=f"{message['errors']:,}")
                    self.loops_label.config(text=f"Passes {message['loops']:,}")
                    if self._start_mono:
                        elapsed = max(time.monotonic() - self._start_mono, 0.001)
                        self.elapsed_label.config(text=f"Elapsed {int(elapsed)}s")
                        completed = message["current_index"]
                        remaining = max(message["total"] - completed, 0)
                        rate = completed / elapsed
                        self.eta_label.config(text=f"ETA {int(remaining / rate)}s" if rate > 0 and remaining else "ETA —")
                elif kind == "eps":
                    self.eps_label.config(text=f"{message['value']:,}")
                elif kind == "done":
                    summary = message["summary"]
                    self._set_status(summary["status"])
                    self.start_button.config(state="normal", text="Start replay")
                    self.pause_button.config(state="disabled", text="Pause")
                    self.stop_button.config(state="disabled")
                    self.sent_label.config(text=f"{summary['records_sent']:,}")
                    self.error_label.config(text=f"{summary['records_failed']:,}")
                    self.loops_label.config(text=f"Passes {summary['loops_completed']:,}")
                    level = "ok" if summary["status"] == "completed" and summary["records_failed"] == 0 else "warn" if summary["status"] == "stopped" else "err"
                    self._log(level, f"Run {summary['status']}: {summary['records_sent']:,} sent, {summary['records_failed']:,} failed, average {summary['average_eps']} records/s.")
                    if summary.get("report_file"):
                        self._log("info", f"Report: {summary['report_file']}")
                    if summary.get("failed_records_file"):
                        self._log("warn", f"Failed raw bytes: {summary['failed_records_file']}")
                    self._engine = None
        except queue.Empty:
            pass
        self.after(100, self._poll_queue)

    # ---------- Activity ----------
    def _log(self, level: str, text: str) -> None:
        timestamp = time.strftime("%H:%M:%S")
        labels = {"info": "INFO", "ok": " OK ", "warn": "WARN", "err": "ERR ", "dim": "...."}
        self.activity.config(state="normal")
        self.activity.insert("end", f"{timestamp} ", "time")
        self.activity.insert("end", f"[{labels.get(level, 'INFO')}] ", level if level in labels else "info")
        self.activity.insert("end", text + "\n", "dim" if level == "dim" else "")
        self.activity.config(state="disabled")
        self.activity.see("end")

    def _clear_activity(self) -> None:
        self.activity.config(state="normal")
        self.activity.delete("1.0", "end")
        self.activity.config(state="disabled")

    def _export_activity(self) -> None:
        selected = filedialog.asksaveasfilename(title="Export activity", defaultextension=".txt", initialfile="replay-activity.txt", filetypes=[("Text", "*.txt"), ("All files", "*.*")])
        if selected:
            Path(selected).write_text(self.activity.get("1.0", "end-1c"), encoding="utf-8")
            self._log("ok", f"Exported activity to {selected}.")

    def _on_close(self) -> None:
        self._maybe_save_destination()
        if self._engine and self._engine.alive:
            if not messagebox.askyesno("Replay running", "Stop the active replay and exit?"):
                return
            self._engine.stop()
        self.destroy()


def main() -> None:
    App().mainloop()


if __name__ == "__main__":
    main()
