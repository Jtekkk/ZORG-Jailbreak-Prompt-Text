#!/usr/bin/env python3
"""
WinDiag Pro — Windows 10/11 Diagnostic & Repair Tool
"""

import customtkinter as ctk
import threading
import queue
import json
import os
import sys
import datetime
import platform
from pathlib import Path
from typing import List, Optional, Dict, Any

from scanner import DiagnosticScanner, Issue, Severity, ScanCategory
from fixer   import DiagnosticFixer, FixResult, FixMeta, ALL_FIXES, FIX_MAP, is_admin, request_elevation

# -----------------------------------------------------------------------
# Theme & palette
# -----------------------------------------------------------------------

ACCENT      = '#0078D4'
ACCENT_H    = '#1A8FE3'
ACCENT_DARK = '#005A9E'
BG          = '#1C1C1C'
PANEL       = '#252525'
CARD        = '#2E2E2E'
BORDER      = '#3A3A3A'
SEP         = '#3E3E3E'
TXT         = '#FFFFFF'
TXT2        = '#ADADAD'
TXT3        = '#707070'
RED         = '#E74856'
YELLOW      = '#FCB900'
BLUE_INFO   = '#60CDFF'
GREEN       = '#13A10E'
GREEN_L     = '#4EC94E'

SEV_COLORS  = {
    Severity.CRITICAL: RED,
    Severity.WARNING:  YELLOW,
    Severity.INFO:     BLUE_INFO,
}

FONT_TITLE  = ('Segoe UI', 22, 'bold')
FONT_HEAD   = ('Segoe UI', 14, 'bold')
FONT_SUBH   = ('Segoe UI', 12, 'bold')
FONT_BODY   = ('Segoe UI', 12)
FONT_SMALL  = ('Segoe UI', 10)
FONT_MONO   = ('Consolas', 11)

SETTINGS_PATH = Path(os.environ.get('APPDATA', Path.home())) / 'WinDiagPro' / 'settings.json'

DEFAULT_SETTINGS = {
    'days_back':          7,
    'log_names':          ['System', 'Application'],
    'scan_categories':    [c.value for c in ScanCategory],
    'theme':              'dark',
    'auto_scan_on_start': False,
    'show_info_issues':   True,
}


def load_settings() -> Dict:
    try:
        if SETTINGS_PATH.exists():
            with open(SETTINGS_PATH) as f:
                data = json.load(f)
                merged = {**DEFAULT_SETTINGS, **data}
                return merged
    except Exception:
        pass
    return dict(DEFAULT_SETTINGS)


def save_settings(settings: Dict):
    try:
        SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(SETTINGS_PATH, 'w') as f:
            json.dump(settings, f, indent=2)
    except Exception:
        pass


# -----------------------------------------------------------------------
# Helper widgets
# -----------------------------------------------------------------------

def make_frame(parent, **kw) -> ctk.CTkFrame:
    kw.setdefault('fg_color', CARD)
    kw.setdefault('corner_radius', 8)
    return ctk.CTkFrame(parent, **kw)


def make_label(parent, text='', size=12, bold=False, color=TXT, **kw) -> ctk.CTkLabel:
    weight = 'bold' if bold else 'normal'
    return ctk.CTkLabel(parent, text=text,
                        font=('Segoe UI', size, weight),
                        text_color=color, **kw)


def make_button(parent, text, command=None, width=120, height=34,
                color=ACCENT, hover=ACCENT_H, txt_color=TXT, **kw) -> ctk.CTkButton:
    return ctk.CTkButton(parent, text=text, command=command,
                         width=width, height=height,
                         fg_color=color, hover_color=hover,
                         text_color=txt_color,
                         font=('Segoe UI', 12, 'bold'),
                         corner_radius=6, **kw)


def sev_icon(sev: Severity) -> str:
    return {Severity.CRITICAL: '●', Severity.WARNING: '▲', Severity.INFO: '◆'}.get(sev, '●')


# -----------------------------------------------------------------------
# Health score ring canvas
# -----------------------------------------------------------------------

class HealthRing(ctk.CTkCanvas):
    def __init__(self, parent, size=160, **kw):
        kw.setdefault('bg', PANEL)
        kw.setdefault('highlightthickness', 0)
        super().__init__(parent, width=size, height=size, **kw)
        self._size = size
        self._score = 100

    def set_score(self, score: int):
        self._score = max(0, min(100, score))
        self._draw()

    def _draw(self):
        s = self._size
        self.delete('all')
        pad = 14
        x0, y0, x1, y1 = pad, pad, s - pad, s - pad

        # Background arc
        self.create_arc(x0, y0, x1, y1, start=0, extent=359.9,
                        style='arc', outline=BORDER, width=12)

        # Score arc
        score = self._score
        if score >= 80:
            color = GREEN_L
        elif score >= 55:
            color = YELLOW
        elif score >= 30:
            color = '#FF8C00'
        else:
            color = RED

        extent = score / 100 * 359.9
        self.create_arc(x0, y0, x1, y1, start=90, extent=-extent,
                        style='arc', outline=color, width=12)

        # Score text
        cx, cy = s / 2, s / 2
        self.create_text(cx, cy - 10, text=str(score),
                         font=('Segoe UI', 28, 'bold'), fill=color)
        self.create_text(cx, cy + 16, text='Health', font=('Segoe UI', 11), fill=TXT2)


# -----------------------------------------------------------------------
# Sidebar
# -----------------------------------------------------------------------

class Sidebar(ctk.CTkFrame):
    NAV = [
        ('dashboard',   '⊞ Dashboard'),
        ('diagnostics', '◎ Scan & Diagnose'),
        ('fixes',       '⚙ Fix Center'),
        ('report',      '≡ Report'),
        ('settings',    '☰ Settings'),
    ]

    def __init__(self, parent, on_nav, **kw):
        super().__init__(parent, width=215, fg_color=PANEL, corner_radius=0, **kw)
        self.grid_propagate(False)
        self.pack_propagate(False)
        self._on_nav  = on_nav
        self._buttons: Dict[str, ctk.CTkButton] = {}
        self._active  = 'dashboard'
        self._build()

    def _build(self):
        self.grid_rowconfigure(1, weight=1)

        # Logo area
        logo = ctk.CTkFrame(self, fg_color=ACCENT_DARK, height=56, corner_radius=0)
        logo.grid(row=0, column=0, sticky='ew')
        logo.grid_propagate(False)
        ctk.CTkLabel(logo, text='WinDiag Pro',
                     font=('Segoe UI', 16, 'bold'),
                     text_color=TXT).place(relx=0.5, rely=0.5, anchor='center')

        # Nav buttons
        nav_frame = ctk.CTkFrame(self, fg_color='transparent')
        nav_frame.grid(row=1, column=0, sticky='nsew', padx=8, pady=(16, 8))

        for page_id, label in self.NAV:
            btn = ctk.CTkButton(nav_frame, text=label,
                                font=('Segoe UI', 13),
                                fg_color='transparent',
                                hover_color=CARD,
                                text_color=TXT2,
                                anchor='w',
                                height=40,
                                corner_radius=6,
                                command=lambda p=page_id: self._nav(p))
            btn.pack(fill='x', pady=2)
            self._buttons[page_id] = btn

        # Admin badge
        self._admin_label = ctk.CTkLabel(
            self, text='',
            font=('Segoe UI', 10),
            text_color=TXT3,
            wraplength=190)
        self._admin_label.grid(row=2, column=0, padx=12, pady=(0, 12))
        self._update_admin_badge()

        self.select('dashboard')

    def _update_admin_badge(self):
        if is_admin():
            self._admin_label.configure(text='🔓 Running as Administrator', text_color=GREEN_L)
        else:
            self._admin_label.configure(
                text='⚠ Not Administrator\nSome fixes require elevation.',
                text_color=YELLOW)

    def _nav(self, page_id: str):
        self.select(page_id)
        self._on_nav(page_id)

    def select(self, page_id: str):
        for pid, btn in self._buttons.items():
            if pid == page_id:
                btn.configure(fg_color=CARD, text_color=TXT)
            else:
                btn.configure(fg_color='transparent', text_color=TXT2)
        self._active = page_id


# -----------------------------------------------------------------------
# Page: Dashboard
# -----------------------------------------------------------------------

class DashboardPage(ctk.CTkFrame):
    def __init__(self, parent, app, **kw):
        super().__init__(parent, fg_color=BG, corner_radius=0, **kw)
        self._app = app
        self._ring: Optional[HealthRing] = None
        self._stat_labels: Dict[str, ctk.CTkLabel] = {}
        self._build()

    def _build(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        # Title bar
        title_row = ctk.CTkFrame(self, fg_color='transparent')
        title_row.grid(row=0, column=0, sticky='ew', padx=24, pady=(20, 0))
        make_label(title_row, 'Dashboard', size=22, bold=True).pack(side='left')

        self._scan_btn = make_button(title_row, '▶  Run Scan',
                                     command=self._app.start_scan,
                                     width=140, height=36)
        self._scan_btn.pack(side='right')

        # Status bar
        self._status_lbl = make_label(self, 'Ready — click Run Scan to begin.',
                                      size=11, color=TXT3)
        self._status_lbl.grid(row=1, column=0, sticky='w', padx=26, pady=(6, 12))

        # Main content
        content = ctk.CTkFrame(self, fg_color='transparent')
        content.grid(row=2, column=0, sticky='nsew', padx=24, pady=0)
        content.grid_columnconfigure(1, weight=1)
        content.grid_rowconfigure(1, weight=1)

        # --- Health panel (left) ---
        health_panel = make_frame(content, width=230, fg_color=PANEL)
        health_panel.grid(row=0, column=0, rowspan=2, sticky='ns', padx=(0, 16), pady=(0, 16))
        health_panel.grid_propagate(False)

        make_label(health_panel, 'System Health', size=13, bold=True)\
            .pack(pady=(18, 4), padx=16)

        self._ring = HealthRing(health_panel, size=160, bg=PANEL)
        self._ring.pack(pady=(8, 8))

        self._health_desc = make_label(health_panel, 'Run a scan to check\nyour system.',
                                       size=11, color=TXT2)
        self._health_desc.pack(pady=(0, 12), padx=12)

        sep = ctk.CTkFrame(health_panel, fg_color=SEP, height=1)
        sep.pack(fill='x', padx=16)

        stats_grid = ctk.CTkFrame(health_panel, fg_color='transparent')
        stats_grid.pack(fill='x', padx=16, pady=12)

        for i, (key, icon, color) in enumerate([
            ('critical', '●', RED),
            ('warnings', '▲', YELLOW),
            ('info',     '◆', BLUE_INFO),
            ('fixable',  '⚙', GREEN_L),
        ]):
            row = ctk.CTkFrame(stats_grid, fg_color='transparent')
            row.pack(fill='x', pady=2)
            ctk.CTkLabel(row, text=icon, font=('Segoe UI', 12), text_color=color,
                         width=20).pack(side='left')
            make_label(row, key.capitalize(), size=11, color=TXT2).pack(side='left', padx=4)
            lbl = make_label(row, '—', size=12, bold=True)
            lbl.pack(side='right')
            self._stat_labels[key] = lbl

        # --- Right panels ---
        right = ctk.CTkFrame(content, fg_color='transparent')
        right.grid(row=0, column=1, rowspan=2, sticky='nsew')
        right.grid_columnconfigure((0, 1), weight=1)
        right.grid_rowconfigure(1, weight=1)

        # System info cards (top row)
        self._sysinfo_frame = ctk.CTkFrame(right, fg_color='transparent')
        self._sysinfo_frame.grid(row=0, column=0, columnspan=2, sticky='ew', pady=(0, 12))
        self._build_sysinfo()

        # Recent issues list
        issues_panel = make_frame(right, fg_color=PANEL)
        issues_panel.grid(row=1, column=0, columnspan=2, sticky='nsew')

        header = ctk.CTkFrame(issues_panel, fg_color='transparent')
        header.pack(fill='x', padx=16, pady=(14, 6))
        make_label(header, 'Recent Issues', size=13, bold=True).pack(side='left')
        make_button(header, 'View All', command=lambda: self._app.nav('diagnostics'),
                    width=90, height=28, color=CARD, hover=BORDER, txt_color=TXT2)\
            .pack(side='right')

        self._issues_scroll = ctk.CTkScrollableFrame(issues_panel, fg_color='transparent',
                                                      scrollbar_button_color=BORDER)
        self._issues_scroll.pack(fill='both', expand=True, padx=8, pady=(0, 8))

        self._no_issues_lbl = make_label(self._issues_scroll,
                                         'No issues found yet.\nRun a scan to check your system.',
                                         size=12, color=TXT3)
        self._no_issues_lbl.pack(pady=30)

    def _build_sysinfo(self):
        for w in self._sysinfo_frame.winfo_children():
            w.destroy()

        try:
            import psutil
            mem  = psutil.virtual_memory()
            cpu  = platform.processor() or 'Unknown CPU'
            mem_str = f'{mem.total / (1024**3):.1f} GB RAM'
        except Exception:
            cpu     = 'Unknown'
            mem_str = 'Unknown'

        cards = [
            ('💻 OS',  platform.version()[:40] if platform.version() else 'Windows'),
            ('⚡ CPU', cpu[:40]),
            ('💾 RAM', mem_str),
            ('🏠 Host', platform.node() or 'Unknown'),
        ]

        self._sysinfo_frame.grid_columnconfigure(tuple(range(len(cards))), weight=1)

        for i, (label, value) in enumerate(cards):
            card = make_frame(self._sysinfo_frame, fg_color=PANEL)
            card.grid(row=0, column=i, sticky='ew',
                      padx=(0 if i else 0, 8 if i < len(cards) - 1 else 0),
                      pady=(0, 0))
            make_label(card, label, size=10, color=TXT3).pack(anchor='w', padx=12, pady=(10, 0))
            make_label(card, value, size=11, bold=True).pack(anchor='w', padx=12, pady=(2, 10))

    def update_results(self, issues: List[Issue], summary: Dict):
        score = summary.get('health_score', 100)
        self._ring.set_score(score)

        if score >= 80:
            desc, color = 'System looks healthy', GREEN_L
        elif score >= 55:
            desc, color = 'Minor issues found', YELLOW
        elif score >= 30:
            desc, color = 'Multiple issues detected', '#FF8C00'
        else:
            desc, color = 'Serious problems found', RED

        self._health_desc.configure(text=desc, text_color=color)

        for key in ('critical', 'warnings', 'info', 'fixable'):
            val = summary.get(key, 0)
            lbl = self._stat_labels.get(key)
            if lbl:
                lbl.configure(text=str(val))

        # Update recent issues
        for w in self._issues_scroll.winfo_children():
            w.destroy()

        top = sorted(issues, key=lambda i: -i.severity.priority)[:10]
        if not top:
            make_label(self._issues_scroll,
                       '✓ No issues found!', size=13, color=GREEN_L).pack(pady=30)
            return

        for issue in top:
            row = ctk.CTkFrame(self._issues_scroll, fg_color=CARD,
                               corner_radius=6)
            row.pack(fill='x', pady=3, padx=4)
            row.grid_columnconfigure(1, weight=1)

            color = SEV_COLORS.get(issue.severity, TXT)
            ctk.CTkLabel(row, text=sev_icon(issue.severity),
                         font=('Segoe UI', 14), text_color=color,
                         width=28).grid(row=0, column=0, padx=(10, 4), pady=8)

            text_col = ctk.CTkFrame(row, fg_color='transparent')
            text_col.grid(row=0, column=1, sticky='ew', padx=4, pady=6)
            make_label(text_col, issue.title[:70], size=11, bold=True).pack(anchor='w')
            make_label(text_col, issue.category.value, size=10, color=TXT3).pack(anchor='w')

            if issue.fix_available:
                make_button(row, 'Fix', width=56, height=26,
                            command=lambda fid=issue.fix_id: self._app.apply_fix(fid))\
                    .grid(row=0, column=2, padx=(4, 10))

    def set_status(self, msg: str, color: str = TXT2):
        self._status_lbl.configure(text=msg, text_color=color)


# -----------------------------------------------------------------------
# Page: Scan & Diagnose
# -----------------------------------------------------------------------

class DiagnosticsPage(ctk.CTkFrame):
    def __init__(self, parent, app, **kw):
        super().__init__(parent, fg_color=BG, corner_radius=0, **kw)
        self._app    = app
        self._issues: List[Issue] = []
        self._filter_sev: Optional[str] = None
        self._filter_cat: Optional[str] = None
        self._build()

    def _build(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        # Header
        hdr = ctk.CTkFrame(self, fg_color='transparent')
        hdr.grid(row=0, column=0, sticky='ew', padx=24, pady=(20, 6))
        make_label(hdr, 'Scan & Diagnose', size=22, bold=True).pack(side='left')
        make_button(hdr, '▶  Run Scan', command=self._app.start_scan,
                    width=140, height=36).pack(side='right')

        # Progress
        prog_frame = ctk.CTkFrame(self, fg_color=PANEL, corner_radius=8)
        prog_frame.grid(row=1, column=0, sticky='ew', padx=24, pady=(0, 12))
        prog_frame.grid_columnconfigure(0, weight=1)

        self._prog_lbl = make_label(prog_frame, 'Ready', size=11, color=TXT2)
        self._prog_lbl.grid(row=0, column=0, sticky='w', padx=14, pady=(10, 4))

        self._progress = ctk.CTkProgressBar(prog_frame, fg_color=BORDER,
                                             progress_color=ACCENT, height=6)
        self._progress.grid(row=1, column=0, sticky='ew', padx=14, pady=(0, 10))
        self._progress.set(0)

        # Filters + list
        main = ctk.CTkFrame(self, fg_color='transparent')
        main.grid(row=2, column=0, sticky='nsew', padx=24, pady=0)
        main.grid_columnconfigure(1, weight=1)
        main.grid_rowconfigure(0, weight=1)

        # Filter sidebar
        filter_col = make_frame(main, width=180, fg_color=PANEL)
        filter_col.grid(row=0, column=0, sticky='ns', padx=(0, 12))
        filter_col.grid_propagate(False)

        make_label(filter_col, 'Filter by Severity', size=11, bold=True, color=TXT2)\
            .pack(anchor='w', padx=12, pady=(14, 4))

        self._sev_btns: Dict[str, ctk.CTkButton] = {}
        for label, key in [('All', None), ('Critical', 'Critical'),
                            ('Warning', 'Warning'), ('Info', 'Info')]:
            color = {None: TXT2, 'Critical': RED, 'Warning': YELLOW, 'Info': BLUE_INFO}.get(key, TXT2)
            btn = ctk.CTkButton(filter_col, text=label, anchor='w',
                                font=('Segoe UI', 12), fg_color='transparent',
                                hover_color=CARD, text_color=color,
                                height=32, corner_radius=6,
                                command=lambda k=key: self._set_sev_filter(k))
            btn.pack(fill='x', padx=8, pady=2)
            self._sev_btns[str(key)] = btn

        make_label(filter_col, 'Filter by Category', size=11, bold=True, color=TXT2)\
            .pack(anchor='w', padx=12, pady=(14, 4))

        self._cat_btns: Dict[str, ctk.CTkButton] = {}
        for cat in [None] + list(ScanCategory):
            label = 'All' if cat is None else cat.value
            btn = ctk.CTkButton(filter_col, text=label, anchor='w',
                                font=('Segoe UI', 11), fg_color='transparent',
                                hover_color=CARD, text_color=TXT2,
                                height=30, corner_radius=6,
                                command=lambda c=cat: self._set_cat_filter(c))
            btn.pack(fill='x', padx=8, pady=1)
            self._cat_btns[str(cat)] = btn

        # Issue list
        list_col = ctk.CTkFrame(main, fg_color='transparent')
        list_col.grid(row=0, column=1, sticky='nsew')
        list_col.grid_columnconfigure(0, weight=1)
        list_col.grid_rowconfigure(1, weight=1)

        list_hdr = ctk.CTkFrame(list_col, fg_color='transparent')
        list_hdr.grid(row=0, column=0, sticky='ew', pady=(0, 8))
        self._count_lbl = make_label(list_hdr, 'No scan run yet', size=11, color=TXT3)
        self._count_lbl.pack(side='left')

        self._issue_scroll = ctk.CTkScrollableFrame(list_col, fg_color='transparent',
                                                     scrollbar_button_color=BORDER)
        self._issue_scroll.grid(row=1, column=0, sticky='nsew')

        self._empty_lbl = make_label(self._issue_scroll,
                                     'Run a scan to see results here.',
                                     size=13, color=TXT3)
        self._empty_lbl.pack(pady=40)

    def _set_sev_filter(self, key):
        self._filter_sev = key
        for k, btn in self._sev_btns.items():
            btn.configure(fg_color=CARD if str(key) == k else 'transparent')
        self._render_issues()

    def _set_cat_filter(self, cat):
        self._filter_cat = cat
        for k, btn in self._cat_btns.items():
            btn.configure(fg_color=CARD if str(cat) == k else 'transparent')
        self._render_issues()

    def set_progress(self, msg: str, pct: float):
        self._prog_lbl.configure(text=msg)
        self._progress.set(pct / 100)

    def add_issue(self, issue: Issue):
        self._issues.append(issue)
        self._render_issues()

    def set_issues(self, issues: List[Issue]):
        self._issues = list(issues)
        self._render_issues()

    def _render_issues(self):
        filtered = self._issues
        if self._filter_sev:
            filtered = [i for i in filtered if i.severity.label == self._filter_sev]
        if self._filter_cat:
            filtered = [i for i in filtered if i.category == self._filter_cat]

        filtered = sorted(filtered, key=lambda i: -i.severity.priority)

        for w in self._issue_scroll.winfo_children():
            w.destroy()

        total = len(self._issues)
        shown = len(filtered)
        self._count_lbl.configure(
            text=f'Showing {shown} of {total} issue{"s" if total != 1 else ""}')

        if not filtered:
            msg = ('No issues match the current filter.' if self._issues
                   else 'No issues found. System looks healthy!')
            color = TXT3 if self._issues else GREEN_L
            make_label(self._issue_scroll, msg, size=13, color=color).pack(pady=40)
            return

        for issue in filtered:
            self._make_issue_card(issue)

    def _make_issue_card(self, issue: Issue):
        sev_color = SEV_COLORS.get(issue.severity, TXT)
        card = ctk.CTkFrame(self._issue_scroll, fg_color=CARD, corner_radius=8)
        card.pack(fill='x', pady=4, padx=2)
        card.grid_columnconfigure(1, weight=1)

        # Severity stripe
        stripe = ctk.CTkFrame(card, fg_color=sev_color, width=4, corner_radius=0)
        stripe.grid(row=0, column=0, rowspan=2, sticky='ns', padx=(0, 0))
        stripe.grid_propagate(False)

        # Icon + title
        top = ctk.CTkFrame(card, fg_color='transparent')
        top.grid(row=0, column=1, sticky='ew', padx=(12, 12), pady=(10, 2))
        top.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(top, text=sev_icon(issue.severity),
                     font=('Segoe UI', 13), text_color=sev_color,
                     width=20).grid(row=0, column=0, padx=(0, 8))

        title_frame = ctk.CTkFrame(top, fg_color='transparent')
        title_frame.grid(row=0, column=1, sticky='ew')
        make_label(title_frame, issue.title, size=12, bold=True).pack(anchor='w')

        meta = f'{issue.category.value}'
        if issue.timestamp:
            try:
                meta += f'  ·  {issue.timestamp.strftime("%Y-%m-%d %H:%M")}'
            except Exception:
                pass
        make_label(title_frame, meta, size=10, color=TXT3).pack(anchor='w')

        # Description
        desc_frame = ctk.CTkFrame(card, fg_color='transparent')
        desc_frame.grid(row=1, column=1, sticky='ew', padx=(40, 12), pady=(0, 8))
        make_label(desc_frame, issue.description, size=11, color=TXT2,
                   wraplength=600, justify='left').pack(anchor='w')

        # Fix button
        if issue.fix_available and issue.fix_id:
            fix_row = ctk.CTkFrame(card, fg_color='transparent')
            fix_row.grid(row=2, column=1, sticky='e', padx=12, pady=(0, 10))
            make_button(fix_row, '⚙ Apply Fix', width=110, height=28,
                        command=lambda fid=issue.fix_id: self._app.apply_fix(fid),
                        height=28).pack()

    def clear(self):
        self._issues = []
        self._render_issues()
        self.set_progress('Ready', 0)


# -----------------------------------------------------------------------
# Page: Fix Center
# -----------------------------------------------------------------------

class FixCenterPage(ctk.CTkFrame):
    def __init__(self, parent, app, **kw):
        super().__init__(parent, fg_color=BG, corner_radius=0, **kw)
        self._app        = app
        self._suggested: List[str] = []
        self._build()

    def _build(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        hdr = ctk.CTkFrame(self, fg_color='transparent')
        hdr.grid(row=0, column=0, sticky='ew', padx=24, pady=(20, 16))
        make_label(hdr, 'Fix Center', size=22, bold=True).pack(side='left')
        self._admin_badge = make_label(
            hdr,
            '🔓 Admin' if is_admin() else '⚠ Not Admin',
            size=11,
            color=GREEN_L if is_admin() else YELLOW)
        self._admin_badge.pack(side='right', padx=8)

        main = ctk.CTkFrame(self, fg_color='transparent')
        main.grid(row=1, column=0, sticky='nsew', padx=24, pady=0)
        main.grid_columnconfigure(0, weight=3)
        main.grid_columnconfigure(1, weight=2)
        main.grid_rowconfigure(0, weight=1)

        # Fix list (left)
        fixes_panel = make_frame(main, fg_color=PANEL)
        fixes_panel.grid(row=0, column=0, sticky='nsew', padx=(0, 12))
        fixes_panel.grid_columnconfigure(0, weight=1)
        fixes_panel.grid_rowconfigure(1, weight=1)

        fhdr = ctk.CTkFrame(fixes_panel, fg_color='transparent')
        fhdr.grid(row=0, column=0, sticky='ew', padx=16, pady=(14, 8))
        make_label(fhdr, 'Available Fixes', size=13, bold=True).pack(side='left')

        self._fix_scroll = ctk.CTkScrollableFrame(fixes_panel, fg_color='transparent',
                                                   scrollbar_button_color=BORDER)
        self._fix_scroll.grid(row=1, column=0, sticky='nsew', padx=8, pady=(0, 8))
        self._populate_fixes()

        # Output log (right)
        log_panel = make_frame(main, fg_color=PANEL)
        log_panel.grid(row=0, column=1, sticky='nsew')
        log_panel.grid_columnconfigure(0, weight=1)
        log_panel.grid_rowconfigure(1, weight=1)

        lhdr = ctk.CTkFrame(log_panel, fg_color='transparent')
        lhdr.grid(row=0, column=0, sticky='ew', padx=16, pady=(14, 8))
        make_label(lhdr, 'Fix Output', size=13, bold=True).pack(side='left')
        make_button(lhdr, 'Clear', width=64, height=26,
                    command=self._clear_log,
                    color=CARD, hover=BORDER, txt_color=TXT2).pack(side='right')

        self._log = ctk.CTkTextbox(log_panel, fg_color=BG, text_color=TXT2,
                                    font=('Consolas', 11), corner_radius=6,
                                    state='disabled')
        self._log.grid(row=1, column=0, sticky='nsew', padx=8, pady=(0, 8))

    def _populate_fixes(self):
        for w in self._fix_scroll.winfo_children():
            w.destroy()

        cats: Dict[str, List[FixMeta]] = {}
        for fix in ALL_FIXES:
            cats.setdefault(fix.category, []).append(fix)

        for cat_name, fixes in cats.items():
            # Category header
            cat_lbl = ctk.CTkFrame(self._fix_scroll, fg_color='transparent')
            cat_lbl.pack(fill='x', pady=(10, 2), padx=4)
            ctk.CTkFrame(cat_lbl, fg_color=ACCENT, width=3, height=16,
                         corner_radius=1).pack(side='left', padx=(0, 8))
            make_label(cat_lbl, cat_name.upper(), size=10, bold=True, color=ACCENT)\
                .pack(side='left')

            for fix in fixes:
                self._make_fix_card(fix)

    def _make_fix_card(self, fix: FixMeta):
        is_suggested = fix.id in self._suggested
        border_color = ACCENT if is_suggested else BORDER

        card = ctk.CTkFrame(self._fix_scroll, fg_color=CARD, corner_radius=8,
                             border_width=1, border_color=border_color)
        card.pack(fill='x', pady=3, padx=4)
        card.grid_columnconfigure(0, weight=1)

        top = ctk.CTkFrame(card, fg_color='transparent')
        top.grid(row=0, column=0, sticky='ew', padx=12, pady=(10, 4))
        top.grid_columnconfigure(0, weight=1)

        title_row = ctk.CTkFrame(top, fg_color='transparent')
        title_row.grid(row=0, column=0, sticky='ew')
        title_row.grid_columnconfigure(0, weight=1)

        name_lbl = make_label(title_row, fix.name, size=12, bold=True)
        name_lbl.grid(row=0, column=0, sticky='w')

        badges = ctk.CTkFrame(title_row, fg_color='transparent')
        badges.grid(row=0, column=1, sticky='e')

        if fix.requires_admin:
            ctk.CTkLabel(badges, text='Admin',
                         font=('Segoe UI', 9, 'bold'),
                         fg_color='#3A2200', text_color=YELLOW,
                         corner_radius=4, width=46, height=18)\
                .pack(side='left', padx=4)

        if is_suggested:
            ctk.CTkLabel(badges, text='Suggested',
                         font=('Segoe UI', 9, 'bold'),
                         fg_color='#001F3A', text_color=BLUE_INFO,
                         corner_radius=4, width=60, height=18)\
                .pack(side='left', padx=2)

        make_label(card, fix.description, size=10, color=TXT2,
                   wraplength=320, justify='left')\
            .grid(row=1, column=0, sticky='w', padx=12, pady=(0, 4))

        bottom = ctk.CTkFrame(card, fg_color='transparent')
        bottom.grid(row=2, column=0, sticky='ew', padx=12, pady=(0, 10))
        bottom.grid_columnconfigure(0, weight=1)

        make_label(bottom, f'⏱ {fix.estimated_time}', size=10, color=TXT3)\
            .grid(row=0, column=0, sticky='w')

        make_button(bottom, '▶ Apply', width=90, height=28,
                    command=lambda fid=fix.id: self._app.apply_fix(fid))\
            .grid(row=0, column=1, sticky='e')

    def set_suggested(self, fix_ids: List[str]):
        self._suggested = fix_ids
        self._populate_fixes()

    def log(self, text: str, color: str = TXT2):
        self._log.configure(state='normal')
        ts = datetime.datetime.now().strftime('%H:%M:%S')
        self._log.insert('end', f'[{ts}] {text}\n')
        self._log.see('end')
        self._log.configure(state='disabled')

    def _clear_log(self):
        self._log.configure(state='normal')
        self._log.delete('1.0', 'end')
        self._log.configure(state='disabled')


# -----------------------------------------------------------------------
# Page: Report
# -----------------------------------------------------------------------

class ReportPage(ctk.CTkFrame):
    def __init__(self, parent, app, **kw):
        super().__init__(parent, fg_color=BG, corner_radius=0, **kw)
        self._app    = app
        self._issues: List[Issue] = []
        self._build()

    def _build(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        hdr = ctk.CTkFrame(self, fg_color='transparent')
        hdr.grid(row=0, column=0, sticky='ew', padx=24, pady=(20, 16))
        make_label(hdr, 'Diagnostic Report', size=22, bold=True).pack(side='left')

        btn_row = ctk.CTkFrame(hdr, fg_color='transparent')
        btn_row.pack(side='right')
        make_button(btn_row, '📋 Generate', command=self._generate, width=120)\
            .pack(side='left', padx=4)
        make_button(btn_row, '💾 Save TXT', command=self._save_txt,
                    width=110, color=CARD, hover=BORDER, txt_color=TXT2)\
            .pack(side='left', padx=4)
        make_button(btn_row, '🌐 Save HTML', command=self._save_html,
                    width=120, color=CARD, hover=BORDER, txt_color=TXT2)\
            .pack(side='left', padx=4)

        panel = make_frame(self, fg_color=PANEL)
        panel.grid(row=1, column=0, sticky='nsew', padx=24, pady=(0, 24))
        panel.grid_columnconfigure(0, weight=1)
        panel.grid_rowconfigure(0, weight=1)

        self._text = ctk.CTkTextbox(panel, fg_color=BG, text_color=TXT,
                                     font=('Consolas', 11), corner_radius=6,
                                     state='disabled')
        self._text.grid(row=0, column=0, sticky='nsew', padx=8, pady=8)

        self._show('Click "Generate" to build a full diagnostic report.')

    def _show(self, txt: str):
        self._text.configure(state='normal')
        self._text.delete('1.0', 'end')
        self._text.insert('end', txt)
        self._text.configure(state='disabled')

    def set_issues(self, issues: List[Issue]):
        self._issues = list(issues)

    def _generate(self):
        self._show(self._build_text())

    def _build_text(self) -> str:
        now  = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        host = platform.node()
        lines = [
            '=' * 64,
            'WINDIAG PRO — DIAGNOSTIC REPORT',
            f'Generated : {now}',
            f'Computer  : {host}',
            f'OS        : {platform.platform()}',
            f'Admin     : {"Yes" if is_admin() else "No"}',
            '=' * 64,
            '',
        ]

        from scanner import DiagnosticScanner
        tmp = DiagnosticScanner()
        tmp.issues = self._issues
        s = tmp.summary()

        lines += [
            f'SUMMARY',
            f'  Health Score : {s["health_score"]}/100',
            f'  Critical     : {s["critical"]}',
            f'  Warnings     : {s["warnings"]}',
            f'  Info         : {s["info"]}',
            f'  Total Issues : {s["total"]}',
            '',
        ]

        for sev in (Severity.CRITICAL, Severity.WARNING, Severity.INFO):
            matching = [i for i in self._issues if i.severity == sev]
            if not matching:
                continue
            lines.append(f'{"─" * 30} {sev.label.upper()} ISSUES ({len(matching)}) {"─" * 10}')
            for issue in matching:
                lines += [
                    f'  [{issue.category.value}] {issue.title}',
                    f'  {issue.description.replace(chr(10), "  ")}',
                    f'  Fix available: {"Yes — " + (issue.fix_id or "") if issue.fix_available else "No"}',
                    '',
                ]

        lines += ['=' * 64, 'END OF REPORT']
        return '\n'.join(lines)

    def _save_txt(self):
        from tkinter import filedialog
        path = filedialog.asksaveasfilename(
            defaultextension='.txt', title='Save Report',
            filetypes=[('Text files', '*.txt'), ('All files', '*.*')])
        if path:
            try:
                with open(path, 'w', encoding='utf-8') as f:
                    f.write(self._build_text())
                self._show(f'Report saved to:\n{path}\n\n' + self._build_text())
            except Exception as e:
                self._show(f'Error saving: {e}')

    def _save_html(self):
        from tkinter import filedialog
        path = filedialog.asksaveasfilename(
            defaultextension='.html', title='Save HTML Report',
            filetypes=[('HTML files', '*.html'), ('All files', '*.*')])
        if not path:
            return
        try:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(self._build_html())
            self._show(f'HTML report saved to:\n{path}')
        except Exception as e:
            self._show(f'Error saving: {e}')

    def _build_html(self) -> str:
        now    = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        rows   = ''
        for i in self._issues:
            color = {'Critical': '#E74856', 'Warning': '#FCB900', 'Info': '#60CDFF'}\
                .get(i.severity.label, '#aaa')
            rows += (f'<tr><td style="color:{color};font-weight:bold">{i.severity.label}</td>'
                     f'<td>{i.category.value}</td>'
                     f'<td>{i.title}</td>'
                     f'<td>{"✓" if i.fix_available else ""}</td></tr>\n')

        return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>WinDiag Pro Report</title>
<style>body{{font-family:Segoe UI,sans-serif;background:#1c1c1c;color:#ccc;padding:24px}}
h1{{color:#0078d4}}table{{width:100%;border-collapse:collapse}}
th{{background:#252525;padding:10px;text-align:left}}
td{{padding:8px 10px;border-bottom:1px solid #333}}
</style></head><body>
<h1>WinDiag Pro — Diagnostic Report</h1>
<p>Generated: {now} | Host: {platform.node()}</p>
<table>
<tr><th>Severity</th><th>Category</th><th>Issue</th><th>Fixable</th></tr>
{rows}
</table></body></html>"""


# -----------------------------------------------------------------------
# Page: Settings
# -----------------------------------------------------------------------

class SettingsPage(ctk.CTkFrame):
    def __init__(self, parent, app, settings: Dict, **kw):
        super().__init__(parent, fg_color=BG, corner_radius=0, **kw)
        self._app      = app
        self._settings = settings
        self._vars: Dict[str, Any] = {}
        self._build()

    def _build(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        hdr = ctk.CTkFrame(self, fg_color='transparent')
        hdr.grid(row=0, column=0, sticky='ew', padx=24, pady=(20, 16))
        make_label(hdr, 'Settings', size=22, bold=True).pack(side='left')
        make_button(hdr, '💾 Save Settings', command=self._save,
                    width=140).pack(side='right')

        tabs = ctk.CTkTabview(self, fg_color=PANEL, segmented_button_fg_color=BG,
                               segmented_button_selected_color=ACCENT,
                               segmented_button_selected_hover_color=ACCENT_H,
                               text_color=TXT, corner_radius=8)
        tabs.grid(row=1, column=0, sticky='nsew', padx=24, pady=(0, 24))

        for name in ('Scan Options', 'Appearance', 'About'):
            tabs.add(name)

        self._build_scan_tab(tabs.tab('Scan Options'))
        self._build_appearance_tab(tabs.tab('Appearance'))
        self._build_about_tab(tabs.tab('About'))

    def _section(self, parent, title: str) -> ctk.CTkFrame:
        frame = make_frame(parent, fg_color=CARD)
        frame.pack(fill='x', pady=6)
        make_label(frame, title, size=12, bold=True, color=ACCENT)\
            .pack(anchor='w', padx=16, pady=(12, 6))
        sep = ctk.CTkFrame(frame, fg_color=SEP, height=1)
        sep.pack(fill='x', padx=16)
        return frame

    def _build_scan_tab(self, parent):
        scroll = ctk.CTkScrollableFrame(parent, fg_color='transparent',
                                         scrollbar_button_color=BORDER)
        scroll.pack(fill='both', expand=True, padx=8, pady=8)

        # Days back
        s1 = self._section(scroll, 'Event Log History')
        row = ctk.CTkFrame(s1, fg_color='transparent')
        row.pack(fill='x', padx=16, pady=(8, 12))
        make_label(row, 'Days to look back:', size=12).pack(side='left')

        days_var = ctk.StringVar(value=str(self._settings.get('days_back', 7)))
        self._vars['days_back_var'] = days_var
        seg = ctk.CTkSegmentedButton(row, values=['1', '3', '7', '14', '30'],
                                      variable=days_var,
                                      fg_color=BG, selected_color=ACCENT,
                                      selected_hover_color=ACCENT_H,
                                      unselected_color=CARD, font=('Segoe UI', 12))
        seg.pack(side='right')

        # Log names
        s2 = self._section(scroll, 'Event Logs to Scan')
        inner2 = ctk.CTkFrame(s2, fg_color='transparent')
        inner2.pack(fill='x', padx=16, pady=(8, 12))
        log_vars = {}
        for log_name in ['System', 'Application', 'Security', 'Setup']:
            checked = log_name in self._settings.get('log_names', ['System', 'Application'])
            v = ctk.BooleanVar(value=checked)
            log_vars[log_name] = v
            ctk.CTkCheckBox(inner2, text=log_name, variable=v,
                             font=('Segoe UI', 12),
                             fg_color=ACCENT, hover_color=ACCENT_H,
                             text_color=TXT).pack(anchor='w', pady=3)
        self._vars['log_vars'] = log_vars

        # Categories
        s3 = self._section(scroll, 'Scan Categories')
        inner3 = ctk.CTkFrame(s3, fg_color='transparent')
        inner3.pack(fill='x', padx=16, pady=(8, 12))
        cat_vars = {}
        enabled_cats = self._settings.get('scan_categories', [c.value for c in ScanCategory])
        for cat in ScanCategory:
            v = ctk.BooleanVar(value=cat.value in enabled_cats)
            cat_vars[cat.value] = v
            ctk.CTkCheckBox(inner3, text=cat.value, variable=v,
                             font=('Segoe UI', 12),
                             fg_color=ACCENT, hover_color=ACCENT_H,
                             text_color=TXT).pack(anchor='w', pady=3)
        self._vars['cat_vars'] = cat_vars

        # Misc
        s4 = self._section(scroll, 'Behaviour')
        inner4 = ctk.CTkFrame(s4, fg_color='transparent')
        inner4.pack(fill='x', padx=16, pady=(8, 12))

        auto_var = ctk.BooleanVar(value=self._settings.get('auto_scan_on_start', False))
        self._vars['auto_var'] = auto_var
        ctk.CTkCheckBox(inner4, text='Run scan automatically on startup',
                         variable=auto_var,
                         font=('Segoe UI', 12),
                         fg_color=ACCENT, hover_color=ACCENT_H, text_color=TXT)\
            .pack(anchor='w', pady=3)

        info_var = ctk.BooleanVar(value=self._settings.get('show_info_issues', True))
        self._vars['info_var'] = info_var
        ctk.CTkCheckBox(inner4, text='Show informational issues',
                         variable=info_var,
                         font=('Segoe UI', 12),
                         fg_color=ACCENT, hover_color=ACCENT_H, text_color=TXT)\
            .pack(anchor='w', pady=3)

    def _build_appearance_tab(self, parent):
        frame = ctk.CTkFrame(parent, fg_color='transparent')
        frame.pack(fill='x', padx=16, pady=16)

        s = self._section(frame, 'Color Theme')
        inner = ctk.CTkFrame(s, fg_color='transparent')
        inner.pack(fill='x', padx=16, pady=(8, 12))
        make_label(inner, 'UI Theme:', size=12).pack(side='left')

        theme_var = ctk.StringVar(value=self._settings.get('theme', 'dark').capitalize())
        self._vars['theme_var'] = theme_var
        ctk.CTkSegmentedButton(inner, values=['Dark', 'Light', 'System'],
                                variable=theme_var,
                                fg_color=BG, selected_color=ACCENT,
                                selected_hover_color=ACCENT_H,
                                unselected_color=CARD, font=('Segoe UI', 12),
                                command=self._apply_theme)\
            .pack(side='right')

    def _apply_theme(self, val: str):
        ctk.set_appearance_mode(val.lower())

    def _build_about_tab(self, parent):
        frame = ctk.CTkFrame(parent, fg_color='transparent')
        frame.pack(fill='both', expand=True, padx=24, pady=24)

        make_label(frame, 'WinDiag Pro', size=24, bold=True, color=ACCENT)\
            .pack(pady=(20, 4))
        make_label(frame, 'Windows 10/11 Diagnostic & Repair Tool',
                   size=13, color=TXT2).pack()
        make_label(frame, 'Version 1.0.0', size=11, color=TXT3).pack(pady=4)

        sep = ctk.CTkFrame(frame, fg_color=SEP, height=1)
        sep.pack(fill='x', pady=20)

        info = [
            ('Python',    platform.python_version()),
            ('OS',        platform.platform()),
            ('Admin',     'Yes' if is_admin() else 'No — some fixes require elevation'),
            ('Settings',  str(SETTINGS_PATH)),
        ]
        for key, val in info:
            row = ctk.CTkFrame(frame, fg_color='transparent')
            row.pack(fill='x', pady=3)
            make_label(row, f'{key}:', size=12, bold=True, color=TXT2).pack(side='left', width=80)
            make_label(row, val, size=11, color=TXT3).pack(side='left')

        sep2 = ctk.CTkFrame(frame, fg_color=SEP, height=1)
        sep2.pack(fill='x', pady=20)

        if not is_admin():
            make_button(frame, '🔓 Restart as Administrator',
                        command=lambda: (request_elevation(), sys.exit()),
                        width=240, height=38).pack(pady=8)
            make_label(frame, 'Required for SFC, DISM, service restart, and network reset.',
                       size=10, color=TXT3).pack()

    def _save(self):
        try:
            days = int(self._vars['days_back_var'].get())
        except ValueError:
            days = 7

        logs = [name for name, v in self._vars['log_vars'].items() if v.get()]
        cats = [name for name, v in self._vars['cat_vars'].items() if v.get()]

        self._settings.update({
            'days_back':          days,
            'log_names':          logs,
            'scan_categories':    cats,
            'auto_scan_on_start': self._vars['auto_var'].get(),
            'show_info_issues':   self._vars['info_var'].get(),
            'theme':              self._vars['theme_var'].get().lower(),
        })
        save_settings(self._settings)
        self._app.show_toast('Settings saved successfully.')


# -----------------------------------------------------------------------
# Toast notification
# -----------------------------------------------------------------------

class Toast(ctk.CTkToplevel):
    def __init__(self, parent, msg: str):
        super().__init__(parent)
        self.overrideredirect(True)
        self.attributes('-topmost', True)
        self.configure(fg_color=CARD)

        ctk.CTkLabel(self, text=msg, font=('Segoe UI', 12),
                     text_color=TXT, padx=20, pady=12).pack()

        # Position bottom-right
        self.update_idletasks()
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        w, h = self.winfo_width(), self.winfo_height()
        self.geometry(f'+{sw - w - 32}+{sh - h - 60}')
        self.after(3000, self.destroy)


# -----------------------------------------------------------------------
# Fix Dialog
# -----------------------------------------------------------------------

class FixDialog(ctk.CTkToplevel):
    def __init__(self, parent, fix_id: str, on_confirm):
        super().__init__(parent)
        meta = FIX_MAP.get(fix_id)
        name = meta.name if meta else fix_id

        self.title('Apply Fix')
        self.geometry('460x260')
        self.resizable(False, False)
        self.configure(fg_color=PANEL)
        self.attributes('-topmost', True)
        self.grab_set()

        ctk.CTkLabel(self, text='Apply Fix?',
                     font=('Segoe UI', 17, 'bold'),
                     text_color=TXT).pack(pady=(24, 4))
        ctk.CTkLabel(self, text=name,
                     font=('Segoe UI', 13),
                     text_color=ACCENT).pack()
        if meta:
            ctk.CTkLabel(self, text=meta.description,
                         font=('Segoe UI', 11),
                         text_color=TXT2, wraplength=380,
                         justify='center').pack(pady=(8, 4))

            if meta.requires_admin and not is_admin():
                ctk.CTkLabel(self, text='⚠ Requires Administrator — may fail',
                             font=('Segoe UI', 11),
                             text_color=YELLOW).pack(pady=4)

            ctk.CTkLabel(self, text=f'Estimated time: {meta.estimated_time}',
                         font=('Segoe UI', 10),
                         text_color=TXT3).pack()

        btns = ctk.CTkFrame(self, fg_color='transparent')
        btns.pack(pady=20)
        make_button(btns, 'Apply', command=lambda: (self.destroy(), on_confirm()),
                    width=110).pack(side='left', padx=8)
        make_button(btns, 'Cancel', command=self.destroy,
                    width=90, color=CARD, hover=BORDER, txt_color=TXT2).pack(side='left')


# -----------------------------------------------------------------------
# Main Application
# -----------------------------------------------------------------------

class App(ctk.CTk):
    def __init__(self):
        self._settings = load_settings()
        ctk.set_appearance_mode(self._settings.get('theme', 'dark'))
        ctk.set_default_color_theme('blue')
        super().__init__()

        self.title('WinDiag Pro — Windows Diagnostic Tool')
        self.geometry('1340x820')
        self.minsize(900, 600)
        self.configure(fg_color=BG)

        self._scanner  = DiagnosticScanner(settings=self._settings)
        self._fixer    = DiagnosticFixer(progress_cb=self._on_fix_progress)
        self._scanning = False
        self._queue:   queue.Queue = queue.Queue()
        self._issues:  List[Issue] = []

        self._build()

        if self._settings.get('auto_scan_on_start', False):
            self.after(500, self.start_scan)

        self.after(100, self._poll_queue)

    def _build(self):
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._sidebar = Sidebar(self, on_nav=self.nav)
        self._sidebar.grid(row=0, column=0, sticky='nsew')

        self._content = ctk.CTkFrame(self, fg_color=BG, corner_radius=0)
        self._content.grid(row=0, column=1, sticky='nsew')
        self._content.grid_columnconfigure(0, weight=1)
        self._content.grid_rowconfigure(0, weight=1)

        self._pages: Dict[str, ctk.CTkFrame] = {}
        self._pages['dashboard']   = DashboardPage(self._content, app=self)
        self._pages['diagnostics'] = DiagnosticsPage(self._content, app=self)
        self._pages['fixes']       = FixCenterPage(self._content, app=self)
        self._pages['report']      = ReportPage(self._content, app=self)
        self._pages['settings']    = SettingsPage(self._content, app=self,
                                                   settings=self._settings)

        for page in self._pages.values():
            page.grid(row=0, column=0, sticky='nsew')

        self.nav('dashboard')

    def nav(self, page_id: str):
        self._sidebar.select(page_id)
        for pid, page in self._pages.items():
            if pid == page_id:
                page.tkraise()

    # -------------------------------------------------------------------
    # Scanning
    # -------------------------------------------------------------------

    def start_scan(self):
        if self._scanning:
            return
        self._scanning = True
        self._pages['diagnostics'].clear()

        enabled_cats = [c for c in ScanCategory
                        if c.value in self._settings.get('scan_categories',
                                                          [c.value for c in ScanCategory])]

        self._scanner = DiagnosticScanner(settings=self._settings)
        self._scanner.on_progress(
            lambda msg, pct: self._queue.put(('progress', msg, pct)))
        self._scanner.on_issue(
            lambda issue: self._queue.put(('issue', issue)))

        def run():
            try:
                issues = self._scanner.scan_all(categories=enabled_cats)
                self._queue.put(('done', issues))
            except Exception as e:
                self._queue.put(('error', str(e)))

        threading.Thread(target=run, daemon=True).start()
        self.nav('diagnostics')

    def _poll_queue(self):
        try:
            while True:
                msg = self._queue.get_nowait()
                self._handle_queue(msg)
        except queue.Empty:
            pass
        self.after(80, self._poll_queue)

    def _handle_queue(self, msg):
        kind = msg[0]

        if kind == 'progress':
            _, text, pct = msg
            self._pages['diagnostics'].set_progress(text, pct)
            self._pages['dashboard'].set_status(text)

        elif kind == 'issue':
            _, issue = msg
            self._pages['diagnostics'].add_issue(issue)

        elif kind == 'done':
            _, issues = msg
            self._issues = list(issues)
            self._scanning = False

            summary = self._scanner.summary()
            self._pages['dashboard'].update_results(issues, summary)
            self._pages['report'].set_issues(issues)

            suggested = [i.fix_id for i in issues if i.fix_available and i.fix_id]
            self._pages['fixes'].set_suggested(list(dict.fromkeys(suggested)))

            self._pages['diagnostics'].set_progress(
                f'Scan complete — {summary["total"]} issue(s) found', 100)
            self._pages['dashboard'].set_status(
                f'Last scan: {datetime.datetime.now().strftime("%H:%M:%S")}  '
                f'| Score: {summary["health_score"]}/100  '
                f'| {summary["critical"]} critical, {summary["warnings"]} warnings')

        elif kind == 'error':
            _, err = msg
            self._scanning = False
            self._pages['diagnostics'].set_progress(f'Scan error: {err}', 0)

        elif kind == 'fix_done':
            _, result = msg
            color  = GREEN_L if result.success else RED
            status = '✓' if result.success else '✗'
            self._pages['fixes'].log(f'{status} {result.message}', color)
            if result.details:
                self._pages['fixes'].log(f'   {result.details}', TXT2)
            if result.requires_reboot:
                self._pages['fixes'].log('   ⚠ Restart your computer to complete this fix.', YELLOW)
            self.show_toast(result.message)

    # -------------------------------------------------------------------
    # Fixes
    # -------------------------------------------------------------------

    def apply_fix(self, fix_id: Optional[str]):
        if not fix_id:
            return
        FixDialog(self, fix_id, on_confirm=lambda: self._run_fix(fix_id))

    def _run_fix(self, fix_id: str):
        self.nav('fixes')
        self._pages['fixes'].log(f'Applying: {FIX_MAP.get(fix_id, type("", (), {"name": fix_id})()).name if fix_id in FIX_MAP else fix_id}…')

        def run():
            result = self._fixer.apply_fix(fix_id)
            self._queue.put(('fix_done', result))

        threading.Thread(target=run, daemon=True).start()

    def _on_fix_progress(self, msg: str, pct: float):
        self._queue.put(('progress', msg, pct))

    # -------------------------------------------------------------------
    # UI helpers
    # -------------------------------------------------------------------

    def show_toast(self, msg: str):
        try:
            Toast(self, msg)
        except Exception:
            pass


# -----------------------------------------------------------------------
# Entry point
# -----------------------------------------------------------------------

def main():
    app = App()
    app.mainloop()


if __name__ == '__main__':
    main()
