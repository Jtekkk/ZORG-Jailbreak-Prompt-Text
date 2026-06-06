#!/usr/bin/env python3
"""WinDiag Pro — Cyberpunk Edition"""

import customtkinter as ctk
import tkinter as tk
import threading, queue, json, os, sys, datetime, platform, math
from pathlib import Path
from typing import List, Optional, Dict, Any

from scanner import DiagnosticScanner, Issue, Severity, ScanCategory
from fixer   import DiagnosticFixer, FixResult, FixMeta, ALL_FIXES, FIX_MAP, is_admin, request_elevation

# ── CYBERPUNK PALETTE ─────────────────────────────────────────────────────────
BG       = '#06060F'
PANEL    = '#0A0A1A'
CARD     = '#0D0D20'
CARD2    = '#111128'
BORDER   = '#1C1C3C'
BORDER2  = '#262648'

CYAN     = '#00F5FF'
CYAN_DIM = '#004D55'
CYAN_BG  = '#001418'
PINK     = '#FF2D78'
PINK_DIM = '#550020'
GREEN    = '#00FF88'
GREEN_DIM= '#004422'
YELLOW   = '#FFE600'
YELLOW_DIM='#443C00'
ORANGE   = '#FF6A00'

CRIT     = '#FF2D78'
WARN     = '#FFE600'
INFO     = '#00AAFF'
SUCC     = '#00FF88'

TXT      = '#C8C8E8'
TXT2     = '#606090'
TXT3     = '#2A2A50'
TXT_C    = '#80F0FF'

# ── FONTS ─────────────────────────────────────────────────────────────────────
F_TITLE = ('Consolas', 18, 'bold')
F_HEAD  = ('Consolas', 13, 'bold')
F_SUB   = ('Consolas', 11, 'bold')
F_BODY  = ('Consolas', 11)
F_SMALL = ('Consolas', 9)
F_HUD   = ('Consolas', 42, 'bold')
F_MED   = ('Consolas', 22, 'bold')
F_MONO  = ('Consolas', 11)

SEV_COLORS = {Severity.CRITICAL: CRIT, Severity.WARNING: WARN, Severity.INFO: INFO}
SEV_BG     = {Severity.CRITICAL: PINK_DIM, Severity.WARNING: YELLOW_DIM, Severity.INFO: CYAN_DIM}
SEV_ICON   = {Severity.CRITICAL: '[!]', Severity.WARNING: '[~]', Severity.INFO: '[i]'}

SETTINGS_PATH = Path(os.environ.get('APPDATA', Path.home())) / 'WinDiagPro' / 'settings.json'
DEFAULT_SETTINGS = {
    'days_back': 7, 'log_names': ['System','Application'],
    'scan_categories': [c.value for c in ScanCategory],
    'theme': 'dark', 'auto_scan_on_start': False, 'show_info_issues': True,
}

def load_settings() -> Dict:
    try:
        if SETTINGS_PATH.exists():
            return {**DEFAULT_SETTINGS, **json.loads(SETTINGS_PATH.read_text())}
    except Exception:
        pass
    return dict(DEFAULT_SETTINGS)

def save_settings(s: Dict):
    try:
        SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
        SETTINGS_PATH.write_text(json.dumps(s, indent=2))
    except Exception:
        pass

# ── HELPER CONSTRUCTORS ───────────────────────────────────────────────────────

def frame(parent, color=CARD, radius=0, **kw) -> ctk.CTkFrame:
    return ctk.CTkFrame(parent, fg_color=color, corner_radius=radius, **kw)

def label(parent, text='', size=11, bold=False, color=TXT, **kw) -> ctk.CTkLabel:
    w = 'bold' if bold else 'normal'
    return ctk.CTkLabel(parent, text=text, font=('Consolas', size, w),
                        text_color=color, **kw)

def btn(parent, text, cmd=None, w=120, h=32, fg=CYAN, hv=None, tc=BG, **kw) -> ctk.CTkButton:
    hv = hv or fg
    return ctk.CTkButton(parent, text=text, command=cmd, width=w, height=h,
                         fg_color=fg, hover_color=hv, text_color=tc,
                         font=('Consolas', 11, 'bold'), corner_radius=0, **kw)

def neon_sep(parent, color=CYAN_DIM, h=1) -> ctk.CTkFrame:
    return ctk.CTkFrame(parent, fg_color=color, height=h, corner_radius=0)

def section_header(parent, text: str, color=CYAN) -> ctk.CTkFrame:
    row = frame(parent, color='transparent')
    label(row, f'▸ {text.upper()}', size=10, bold=True, color=color).pack(side='left')
    neon_sep(row, color=color).pack(side='left', fill='x', expand=True, padx=(8,0), pady=1)
    return row

# ── CYBER PANEL (neon corner brackets via Canvas overlay) ─────────────────────

class CyberPanel(ctk.CTkFrame):
    def __init__(self, parent, accent=CYAN, title='', **kw):
        kw.setdefault('fg_color', CARD)
        kw.setdefault('corner_radius', 0)
        super().__init__(parent, **kw)
        self._accent = accent
        self._title  = title
        self._cv = tk.Canvas(self, bg=kw['fg_color'],
                             highlightthickness=0, cursor='')
        self._cv.place(x=0, y=0, relwidth=1, relheight=1)
        self._cv.lower('all')
        self.bind('<Configure>', lambda e: self.after(10, self._draw))

    def _draw(self):
        self._cv.configure(bg=str(self.cget('fg_color')))
        self._cv.delete('all')
        w, h = self.winfo_width(), self.winfo_height()
        if w < 10 or h < 10:
            return
        c, cs = self._accent, 18
        # Octagonal border (cut corners)
        pts = [cs,0, w-cs,0, w,cs, w,h-cs, w-cs,h, cs,h, 0,h-cs, 0,cs]
        self._cv.create_polygon(pts, outline=c, fill='', width=1)
        # Corner accent dots
        for x, y in [(2,2),(w-3,2),(2,h-3),(w-3,h-3)]:
            self._cv.create_rectangle(x-1,y-1,x+1,y+1, fill=c, outline='')
        # Title tab
        if self._title:
            txt = f' {self._title.upper()} '
            tw  = len(txt) * 7 + 4
            self._cv.create_rectangle(cs, -1, cs+tw, 1,
                                      fill=str(self.cget('fg_color')), outline='')
            self._cv.create_text(cs+4, 0, text=txt, fill=c,
                                 font=('Consolas', 9, 'bold'), anchor='w')

    def get_inner(self) -> ctk.CTkFrame:
        f = frame(self, color=str(self.cget('fg_color')))
        f.place(x=6, y=6, relwidth=1, relheight=1, width=-12, height=-12)
        return f

# ── SCANLINE HEADER ────────────────────────────────────────────────────────────

class ScanlineHeader(tk.Canvas):
    def __init__(self, parent, **kw):
        kw.setdefault('bg', BG)
        kw.setdefault('height', 3)
        kw.setdefault('highlightthickness', 0)
        super().__init__(parent, **kw)
        self._pos   = 0
        self._speed = 4
        self._animate()

    def _animate(self):
        self.delete('all')
        w = self.winfo_width() or 1200
        # Base line
        self.create_line(0, 1, w, 1, fill=CYAN_DIM, width=1)
        # Glowing sweep head
        x = self._pos % (w + 120) - 60
        for i, (offset, alpha) in enumerate([(0,CYAN),(6,CYAN_DIM),(14,'#003038'),(24,'#001820')]):
            if 0 <= x-offset < w:
                self.create_line(x-offset, 0, x-offset, 3, fill=alpha, width=1)
        self._pos += self._speed
        self.after(20, self._animate)

# ── CYBER PROGRESS BAR ─────────────────────────────────────────────────────────

class CyberProgressBar(tk.Canvas):
    def __init__(self, parent, color=CYAN, bg_color=CARD, **kw):
        kw.setdefault('height', 8)
        kw.setdefault('highlightthickness', 0)
        super().__init__(parent, bg=bg_color, **kw)
        self._color    = color
        self._bg_color = bg_color
        self._value    = 0.0
        self._pulse    = 0
        self._anim()

    def set(self, v: float):
        self._value = max(0.0, min(1.0, v))

    def _anim(self):
        self.delete('all')
        w = self.winfo_width() or 400
        h = self.winfo_height() or 8
        # Track
        self.create_rectangle(0, 1, w, h-1, fill=BORDER, outline='')
        # Fill
        fw = int(w * self._value)
        if fw > 2:
            # Solid fill
            self.create_rectangle(0, 1, fw, h-1, fill=self._color, outline='')
            # Bright leading edge
            self.create_rectangle(fw-2, 0, fw, h, fill='#FFFFFF', outline='')
            # Scanline shimmer
            pulse_x = int(fw * ((self._pulse % 100) / 100))
            self.create_rectangle(pulse_x, 1, pulse_x+4, h-1,
                                  fill='#FFFFFF', outline='', stipple='gray25')
        self._pulse += 3
        self.after(40, self._anim)

# ── HEALTH DISPLAY ─────────────────────────────────────────────────────────────

class HealthDisplay(tk.Canvas):
    def __init__(self, parent, **kw):
        kw.setdefault('bg', PANEL)
        kw.setdefault('highlightthickness', 0)
        kw.setdefault('width', 200)
        kw.setdefault('height', 200)
        super().__init__(parent, **kw)
        self._score  = 100
        self._pulse  = 0
        self._anim()

    def set_score(self, s: int):
        self._score = max(0, min(100, s))

    def _color(self):
        s = self._score
        if s >= 80: return GREEN
        if s >= 55: return YELLOW
        if s >= 30: return ORANGE
        return CRIT

    def _anim(self):
        self.delete('all')
        w = self.winfo_width() or 200
        h = self.winfo_height() or 200
        bg = str(self['bg'])
        cx, cy = w // 2, h // 2
        c  = self._color()
        s  = self._score

        # Outer octagon ring (arc approximation)
        r  = min(w, h) // 2 - 12
        self.create_oval(cx-r, cy-r, cx+r, cy+r, outline=BORDER, width=2)

        # Score arc
        if s > 0:
            ext = s / 100 * 359.9
            # Glow layers
            for gw, gc in [(6,'#111111'),(4,c+'44'),(2,c)]:
                try:
                    self.create_arc(cx-r, cy-r, cx+r, cy+r,
                                    start=90, extent=-ext,
                                    style='arc', outline=gc, width=gw)
                except Exception:
                    pass

        # Pulse dot at arc end
        if s > 0:
            ang = math.radians(90 - s / 100 * 360)
            px  = cx + r * math.cos(ang)
            py  = cy - r * math.sin(ang)
            pulse_r = 4 + int(2 * abs(math.sin(self._pulse * 0.15)))
            self.create_oval(px-pulse_r, py-pulse_r, px+pulse_r, py+pulse_r,
                             fill=c, outline='#FFFFFF', width=1)

        # Score text
        self.create_text(cx, cy - 14, text=str(s),
                         font=('Consolas', 34, 'bold'), fill=c)
        self.create_text(cx, cy + 18, text='/ 100',
                         font=('Consolas', 11), fill=TXT2)

        # Status label
        status = {range(80,101):'NOMINAL', range(55,80):'DEGRADED',
                  range(30,55):'CRITICAL', range(0,30):'SYSTEM FAILURE'}
        for r_obj, lbl in status.items():
            if s in r_obj:
                self.create_text(cx, cy + 38, text=lbl,
                                 font=('Consolas', 9, 'bold'), fill=c)
                break

        self._pulse += 1
        self.after(50, self._anim)

# ── BLINK MANAGER ──────────────────────────────────────────────────────────────

class BlinkLabel(ctk.CTkLabel):
    def __init__(self, parent, text='', color=CRIT, **kw):
        super().__init__(parent, text=text, text_color=color,
                         font=('Consolas', 11, 'bold'), **kw)
        self._color  = color
        self._on     = True
        self._blink()

    def _blink(self):
        self.configure(text_color=self._color if self._on else TXT3)
        self._on = not self._on
        self.after(600, self._blink)

# ── SIDEBAR ────────────────────────────────────────────────────────────────────

class Sidebar(ctk.CTkFrame):
    NAV = [
        ('dashboard',   '⊞  DASHBOARD'),
        ('diagnostics', '◎  SCAN.SYS'),
        ('fixes',       '⚙  FIX.CENTER'),
        ('report',      '≡  REPORT.LOG'),
        ('settings',    '☰  CONFIG'),
    ]

    def __init__(self, parent, on_nav, **kw):
        super().__init__(parent, width=210, fg_color=PANEL, corner_radius=0, **kw)
        self.grid_propagate(False)
        self._on_nav = on_nav
        self._btns:  Dict[str, ctk.CTkButton] = {}
        self._active = 'dashboard'
        self._build()

    def _build(self):
        self.grid_rowconfigure(2, weight=1)

        # Logo block
        logo = tk.Canvas(self, bg=CYAN_BG, height=58, highlightthickness=0)
        logo.grid(row=0, column=0, sticky='ew')
        logo.bind('<Configure>', lambda e: self._draw_logo(logo))

    def _draw_logo(self, cv):
        cv.delete('all')
        w = cv.winfo_width() or 210
        cv.create_line(0, 0, w, 0, fill=CYAN, width=2)
        cv.create_line(0, 57, w, 57, fill=CYAN_DIM, width=1)
        cv.create_text(w//2, 20, text='WINDIAG.EXE',
                       font=('Consolas', 14, 'bold'), fill=CYAN)
        cv.create_text(w//2, 38, text='v1.0  //  WIN10/11',
                       font=('Consolas', 9), fill=TXT2)

    def _build_nav(self):
        nav = frame(self, color='transparent')
        nav.grid(row=1, column=0, sticky='ew', padx=0, pady=(12, 0))

        for page_id, lbl in self.NAV:
            b = ctk.CTkButton(nav, text=lbl, anchor='w',
                              font=('Consolas', 12),
                              fg_color='transparent', hover_color=CARD2,
                              text_color=TXT2, height=38, corner_radius=0,
                              border_width=0,
                              command=lambda p=page_id: self._nav(p))
            b.pack(fill='x', padx=0, pady=1)
            self._btns[page_id] = b

        # Divider
        neon_sep(nav, BORDER).pack(fill='x', pady=8)

        # Admin status
        is_adm = is_admin()
        adm_frame = frame(nav, color='transparent')
        adm_frame.pack(fill='x', padx=12, pady=4)
        label(adm_frame,
              '✓ ADMIN MODE' if is_adm else '⚠ NO ADMIN',
              size=9, bold=True,
              color=SUCC if is_adm else WARN).pack(anchor='w')
        if not is_adm:
            label(adm_frame, 'some fixes require elevation',
                  size=8, color=TXT3).pack(anchor='w')
            btn(adm_frame, '[ ELEVATE ]', cmd=lambda: (request_elevation(), sys.exit()),
                w=150, h=26, fg=YELLOW_DIM, hv=YELLOW, tc=YELLOW).pack(anchor='w', pady=(4,0))

        # Bottom info
        info = frame(self, color='transparent')
        info.grid(row=3, column=0, sticky='ew', padx=12, pady=8)
        label(info, platform.node()[:22], size=8, color=TXT3).pack(anchor='w')
        label(info, datetime.datetime.now().strftime('%Y.%m.%d'), size=8, color=TXT3).pack(anchor='w')

        self.grid_rowconfigure(2, weight=1)

        self.select('dashboard')

    def _nav(self, page_id: str):
        self.select(page_id)
        self._on_nav(page_id)

    def select(self, page_id: str):
        for pid, b in self._btns.items():
            if pid == page_id:
                b.configure(fg_color=CARD2, text_color=CYAN,
                             border_width=0)
            else:
                b.configure(fg_color='transparent', text_color=TXT2,
                             border_width=0)
        self._active = page_id

# ── PAGE: DASHBOARD ────────────────────────────────────────────────────────────

class DashboardPage(ctk.CTkFrame):
    def __init__(self, parent, app, **kw):
        super().__init__(parent, fg_color=BG, corner_radius=0, **kw)
        self._app = app
        self._stat_lbls: Dict[str, ctk.CTkLabel] = {}
        self._build()

    def _build(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # Top bar
        top = frame(self, color='transparent')
        top.grid(row=0, column=0, sticky='ew', padx=20, pady=(16,0))
        label(top, '// SYSTEM OVERVIEW', size=16, bold=True, color=CYAN).pack(side='left')
        btn(top, '[ RUN SCAN ]', cmd=self._app.start_scan,
            w=140, h=34, fg=CYAN, hv=CYAN, tc=BG).pack(side='right')

        self._status_lbl = label(self, '> READY — AWAITING SCAN COMMAND',
                                 size=9, color=TXT3)
        self._status_lbl.grid(row=0, column=0, sticky='w', padx=24, pady=(36,0))

        ScanlineHeader(self).grid(row=0, column=0, sticky='ew', pady=(0,0))

        # Main body
        body = frame(self, color='transparent')
        body.grid(row=1, column=0, sticky='nsew', padx=20, pady=(10,16))
        body.grid_columnconfigure(1, weight=1)
        body.grid_rowconfigure(0, weight=1)

        # Left: health + stats
        left = frame(body, color='transparent')
        left.grid(row=0, column=0, sticky='ns', padx=(0,12))

        hp = CyberPanel(left, accent=CYAN, title='HEALTH')
        hp.pack(fill='x', pady=(0,10))
        inner_hp = frame(hp, color=CARD)
        inner_hp.place(x=6, y=14, relwidth=1, relheight=1, width=-12, height=-20)

        self._health = HealthDisplay(inner_hp, bg=CARD, width=200, height=200)
        self._health.pack(padx=16, pady=12)

        # Stats
        sp = CyberPanel(left, accent=CYAN_DIM, title='COUNTERS')
        sp.pack(fill='x')
        inner_sp = frame(sp, color=CARD)
        inner_sp.place(x=6, y=14, relwidth=1, relheight=1, width=-12, height=-20)
        inner_sp.pack_propagate(False)

        for key, icon, color in [
            ('critical', '[!]', CRIT),
            ('warnings', '[~]', WARN),
            ('info',     '[i]', INFO),
            ('fixable',  '[⚙]', SUCC),
        ]:
            row = frame(inner_sp, color='transparent')
            row.pack(fill='x', padx=12, pady=3)
            label(row, icon, size=10, bold=True, color=color).pack(side='left')
            label(row, key.upper(), size=9, color=TXT2).pack(side='left', padx=6)
            v = label(row, '—', size=13, bold=True, color=color)
            v.pack(side='right', padx=4)
            self._stat_lbls[key] = v

        # Right: issues list
        right = frame(body, color='transparent')
        right.grid(row=0, column=1, sticky='nsew')
        right.grid_columnconfigure(0, weight=1)
        right.grid_rowconfigure(1, weight=1)

        # Sys info strip
        sysrow = frame(right, color=PANEL, border_width=1, border_color=BORDER)
        sysrow.grid(row=0, column=0, sticky='ew', pady=(0,10))
        sysrow.grid_columnconfigure(tuple(range(4)), weight=1)
        for i, (k, v) in enumerate([
            ('OS',   platform.version()[:30] if platform.version() else 'Windows'),
            ('HOST', platform.node()[:20]),
            ('ARCH', platform.machine()),
            ('PY',   platform.python_version()),
        ]):
            c = frame(sysrow, color='transparent')
            c.grid(row=0, column=i, padx=12, pady=8)
            label(c, k, size=8, color=TXT3).pack(anchor='w')
            label(c, v, size=10, bold=True, color=TXT_C).pack(anchor='w')

        # Issues
        ip = CyberPanel(right, accent=CYAN_DIM, title='RECENT ISSUES')
        ip.grid(row=1, column=0, sticky='nsew')
        inner_ip = frame(ip, color=CARD)
        inner_ip.place(x=6, y=14, relwidth=1, relheight=1, width=-12, height=-20)
        inner_ip.grid_columnconfigure(0, weight=1)
        inner_ip.grid_rowconfigure(0, weight=1)

        hdr = frame(inner_ip, color='transparent')
        hdr.grid(row=0, column=0, sticky='ew', padx=12, pady=(8,4))
        label(hdr, 'ACTIVE ALERTS', size=10, bold=True, color=TXT2).pack(side='left')
        btn(hdr, '[ VIEW ALL ]', cmd=lambda: self._app.nav('diagnostics'),
            w=100, h=24, fg=BORDER, hv=BORDER2, tc=CYAN).pack(side='right')

        self._issues_frame = ctk.CTkScrollableFrame(inner_ip, fg_color='transparent',
                                                     scrollbar_button_color=BORDER)
        self._issues_frame.grid(row=1, column=0, sticky='nsew', padx=8, pady=(0,8))
        inner_ip.grid_rowconfigure(1, weight=1)

        self._empty_lbl = label(self._issues_frame,
                                '> NO DATA — RUN SCAN TO POPULATE',
                                size=10, color=TXT3)
        self._empty_lbl.pack(pady=30)

    def update_results(self, issues: List[Issue], summary: Dict):
        self._health.set_score(summary.get('health_score', 100))
        for key in ('critical','warnings','info','fixable'):
            lbl = self._stat_lbls.get(key)
            if lbl:
                lbl.configure(text=str(summary.get(key, 0)))

        for w in self._issues_frame.winfo_children():
            w.destroy()

        top = sorted(issues, key=lambda i: -i.severity.priority)[:12]
        if not top:
            label(self._issues_frame, '> ALL CLEAR — NO ISSUES DETECTED',
                  size=11, color=SUCC).pack(pady=30)
            return

        for issue in top:
            sc = SEV_COLORS.get(issue.severity, TXT)
            icon = SEV_ICON.get(issue.severity, '[?]')
            row  = frame(self._issues_frame, color=CARD2,
                         border_width=1, border_color=BORDER)
            row.pack(fill='x', pady=2)
            row.grid_columnconfigure(1, weight=1)

            # Severity stripe
            stripe = frame(row, color=sc)
            stripe.configure(width=3)
            stripe.grid(row=0, column=0, rowspan=2, sticky='ns', padx=(0,8))
            stripe.grid_propagate(False)

            label(row, icon, size=10, bold=True, color=sc).grid(
                row=0, column=1, sticky='w', padx=(0,6), pady=(6,0))
            label(row, issue.title[:65], size=10, bold=True).grid(
                row=0, column=2, sticky='w', pady=(6,0))
            label(row, issue.category.value.upper(), size=8, color=TXT3).grid(
                row=1, column=1, columnspan=2, sticky='w', padx=(0,0), pady=(0,6))

            if issue.fix_available:
                btn(row, '[FIX]', cmd=lambda fid=issue.fix_id: self._app.apply_fix(fid),
                    w=60, h=24, fg=CYAN_DIM, hv=CYAN, tc=CYAN).grid(
                    row=0, column=3, rowspan=2, padx=8)

    def set_status(self, msg: str, color=TXT3):
        self._status_lbl.configure(text=f'> {msg.upper()}', text_color=color)

# ── PAGE: DIAGNOSTICS ──────────────────────────────────────────────────────────

class DiagnosticsPage(ctk.CTkFrame):
    def __init__(self, parent, app, **kw):
        super().__init__(parent, fg_color=BG, corner_radius=0, **kw)
        self._app     = app
        self._issues: List[Issue] = []
        self._f_sev:  Optional[str] = None
        self._f_cat:  Optional[str] = None
        self._build()

    def _build(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        hdr = frame(self, color='transparent')
        hdr.grid(row=0, column=0, sticky='ew', padx=20, pady=(16,0))
        label(hdr, '// SCAN & DIAGNOSE', size=16, bold=True, color=CYAN).pack(side='left')
        btn(hdr, '[ RUN SCAN ]', cmd=self._app.start_scan,
            w=140, h=34, fg=CYAN, hv=CYAN, tc=BG).pack(side='right')

        # Progress block
        prog = frame(self, color=PANEL, border_width=1, border_color=BORDER)
        prog.grid(row=1, column=0, sticky='ew', padx=20, pady=(10,8))
        prog.grid_columnconfigure(0, weight=1)

        self._prog_lbl = label(prog, '> READY', size=9, color=CYAN)
        self._prog_lbl.grid(row=0, column=0, sticky='w', padx=12, pady=(8,2))

        self._prog_bar = CyberProgressBar(prog, color=CYAN, bg_color=PANEL)
        self._prog_bar.grid(row=1, column=0, sticky='ew', padx=12, pady=(0,8))

        # Filters + list
        body = frame(self, color='transparent')
        body.grid(row=2, column=0, sticky='nsew', padx=20, pady=(0,12))
        body.grid_columnconfigure(1, weight=1)
        body.grid_rowconfigure(0, weight=1)

        # Filter column
        fc = CyberPanel(body, accent=CYAN_DIM, title='FILTERS')
        fc.configure(width=180)
        fc.grid(row=0, column=0, sticky='ns', padx=(0,10))
        fc.grid_propagate(False)
        fi = frame(fc, color=CARD)
        fi.place(x=6, y=14, relwidth=1, relheight=1, width=-12, height=-20)

        label(fi, 'SEVERITY', size=8, bold=True, color=TXT3).pack(anchor='w', padx=10, pady=(10,2))
        self._sev_btns: Dict = {}
        for lbl_t, key, c in [('ALL',None,TXT2),('CRITICAL','Critical',CRIT),
                                ('WARNING','Warning',WARN),('INFO','Info',INFO)]:
            b = ctk.CTkButton(fi, text=lbl_t, anchor='w',
                              font=('Consolas',10), fg_color='transparent',
                              hover_color=CARD2, text_color=c, height=28,
                              corner_radius=0,
                              command=lambda k=key: self._set_sev(k))
            b.pack(fill='x', padx=6, pady=1)
            self._sev_btns[str(key)] = b

        neon_sep(fi, BORDER).pack(fill='x', padx=10, pady=6)
        label(fi, 'CATEGORY', size=8, bold=True, color=TXT3).pack(anchor='w', padx=10, pady=(0,2))
        self._cat_btns: Dict = {}
        for cat in [None] + list(ScanCategory):
            t = 'ALL' if cat is None else cat.value.upper()[:14]
            b = ctk.CTkButton(fi, text=t, anchor='w',
                              font=('Consolas',9), fg_color='transparent',
                              hover_color=CARD2, text_color=TXT2, height=26,
                              corner_radius=0,
                              command=lambda c=cat: self._set_cat(c))
            b.pack(fill='x', padx=6, pady=1)
            self._cat_btns[str(cat)] = b

        # Issue list
        lc = frame(body, color='transparent')
        lc.grid(row=0, column=1, sticky='nsew')
        lc.grid_columnconfigure(0, weight=1)
        lc.grid_rowconfigure(1, weight=1)

        lhdr = frame(lc, color='transparent')
        lhdr.grid(row=0, column=0, sticky='ew', pady=(0,6))
        self._count_lbl = label(lhdr, 'NO SCAN DATA', size=9, color=TXT3)
        self._count_lbl.pack(side='left')

        self._scroll = ctk.CTkScrollableFrame(lc, fg_color='transparent',
                                               scrollbar_button_color=BORDER)
        self._scroll.grid(row=1, column=0, sticky='nsew')

        self._empty_lbl = label(self._scroll, '> RUN A SCAN TO SEE RESULTS',
                                size=11, color=TXT3)
        self._empty_lbl.pack(pady=40)

    def _set_sev(self, key):
        self._f_sev = key
        for k, b in self._sev_btns.items():
            b.configure(fg_color=CARD2 if str(key)==k else 'transparent')
        self._render()

    def _set_cat(self, cat):
        self._f_cat = cat
        for k, b in self._cat_btns.items():
            b.configure(fg_color=CARD2 if str(cat)==k else 'transparent')
        self._render()

    def set_progress(self, msg: str, pct: float):
        self._prog_lbl.configure(text=f'> {msg.upper()}')
        self._prog_bar.set(pct / 100)

    def add_issue(self, issue: Issue):
        self._issues.append(issue)
        self._render()

    def set_issues(self, issues: List[Issue]):
        self._issues = list(issues)
        self._render()

    def clear(self):
        self._issues = []
        self._render()
        self.set_progress('READY', 0)

    def _render(self):
        filtered = self._issues
        if self._f_sev:
            filtered = [i for i in filtered if i.severity.label == self._f_sev]
        if self._f_cat:
            filtered = [i for i in filtered if i.category == self._f_cat]
        filtered = sorted(filtered, key=lambda i: -i.severity.priority)

        self._count_lbl.configure(
            text=f'SHOWING {len(filtered)} / {len(self._issues)} RESULTS')

        for w in self._scroll.winfo_children():
            w.destroy()

        if not filtered:
            msg = '> NO RESULTS MATCH FILTER' if self._issues else '> ALL CLEAR'
            c   = TXT3 if self._issues else SUCC
            label(self._scroll, msg, size=11, color=c).pack(pady=40)
            return

        for issue in filtered:
            self._make_card(issue)

    def _make_card(self, issue: Issue):
        sc   = SEV_COLORS.get(issue.severity, TXT)
        icon = SEV_ICON.get(issue.severity, '[?]')
        sbg  = SEV_BG.get(issue.severity, CARD)

        card = frame(self._scroll, color=CARD2,
                     border_width=1, border_color=BORDER)
        card.pack(fill='x', pady=3, padx=2)
        card.grid_columnconfigure(1, weight=1)

        # Left severity bar
        bar = frame(card, color=sc)
        bar.configure(width=4)
        bar.grid(row=0, column=0, rowspan=3, sticky='ns')
        bar.grid_propagate(False)

        # Header row
        hdr = frame(card, color='transparent')
        hdr.grid(row=0, column=1, sticky='ew', padx=(10,10), pady=(8,2))
        hdr.grid_columnconfigure(1, weight=1)

        label(hdr, icon, size=10, bold=True, color=sc).grid(row=0, column=0, padx=(0,8))

        title_col = frame(hdr, color='transparent')
        title_col.grid(row=0, column=1, sticky='ew')
        label(title_col, issue.title[:72], size=10, bold=True).pack(anchor='w')
        meta = issue.category.value.upper()
        if issue.timestamp:
            try: meta += f'  ·  {issue.timestamp.strftime("%Y-%m-%d %H:%M")}'
            except Exception: pass
        label(title_col, meta, size=8, color=TXT3).pack(anchor='w')

        # Description
        label(card, issue.description, size=9, color=TXT2,
              wraplength=640, justify='left').grid(
            row=1, column=1, sticky='w', padx=(10,10), pady=(0,4))

        # Fix button
        if issue.fix_available and issue.fix_id:
            fix_row = frame(card, color='transparent')
            fix_row.grid(row=2, column=1, sticky='e', padx=10, pady=(0,8))
            btn(fix_row, '[ APPLY FIX ]', w=120, h=26,
                cmd=lambda fid=issue.fix_id: self._app.apply_fix(fid),
                fg=CYAN_DIM, hv=CYAN, tc=CYAN).pack()

# ── PAGE: FIX CENTER ───────────────────────────────────────────────────────────

class FixCenterPage(ctk.CTkFrame):
    def __init__(self, parent, app, **kw):
        super().__init__(parent, fg_color=BG, corner_radius=0, **kw)
        self._app       = app
        self._suggested: List[str] = []
        self._build()

    def _build(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        hdr = frame(self, color='transparent')
        hdr.grid(row=0, column=0, sticky='ew', padx=20, pady=(16,12))
        label(hdr, '// FIX.CENTER', size=16, bold=True, color=CYAN).pack(side='left')
        adm = is_admin()
        label(hdr, '[ ADMIN ]' if adm else '[ USER MODE ]', size=10, bold=True,
              color=SUCC if adm else WARN).pack(side='right')

        body = frame(self, color='transparent')
        body.grid(row=1, column=0, sticky='nsew', padx=20, pady=(0,12))
        body.grid_columnconfigure(0, weight=3)
        body.grid_columnconfigure(1, weight=2)
        body.grid_rowconfigure(0, weight=1)

        # Fix list
        fp = CyberPanel(body, accent=CYAN_DIM, title='AVAILABLE FIXES')
        fp.grid(row=0, column=0, sticky='nsew', padx=(0,10))
        fi = frame(fp, color=CARD)
        fi.place(x=6, y=14, relwidth=1, relheight=1, width=-12, height=-20)
        fi.grid_columnconfigure(0, weight=1)
        fi.grid_rowconfigure(0, weight=1)

        self._fix_scroll = ctk.CTkScrollableFrame(fi, fg_color='transparent',
                                                   scrollbar_button_color=BORDER)
        self._fix_scroll.grid(row=0, column=0, sticky='nsew', padx=4, pady=4)
        self._render_fixes()

        # Log
        lp = CyberPanel(body, accent=CYAN_DIM, title='EXECUTION LOG')
        lp.grid(row=0, column=1, sticky='nsew')
        li = frame(lp, color=CARD)
        li.place(x=6, y=14, relwidth=1, relheight=1, width=-12, height=-20)
        li.grid_columnconfigure(0, weight=1)
        li.grid_rowconfigure(0, weight=1)

        lhdr = frame(li, color='transparent')
        lhdr.pack(fill='x', padx=8, pady=(6,4))
        btn(lhdr, '[ CLR ]', cmd=self._clear_log,
            w=60, h=22, fg=BORDER, hv=BORDER2, tc=TXT2).pack(side='right')

        self._log = ctk.CTkTextbox(li, fg_color=BG, text_color=CYAN,
                                    font=('Consolas', 10), corner_radius=0,
                                    state='disabled')
        self._log.pack(fill='both', expand=True, padx=8, pady=(0,8))

    def _render_fixes(self):
        for w in self._fix_scroll.winfo_children():
            w.destroy()

        cats: Dict[str, List[FixMeta]] = {}
        for f in ALL_FIXES:
            cats.setdefault(f.category, []).append(f)

        for cat_name, fixes in cats.items():
            ch = section_header(self._fix_scroll, cat_name, CYAN_DIM)
            ch.pack(fill='x', padx=4, pady=(10,4))
            for fix in fixes:
                self._make_fix_card(fix)

    def _make_fix_card(self, fix: FixMeta):
        is_sug   = fix.id in self._suggested
        bdr      = CYAN if is_sug else BORDER
        card = frame(self._fix_scroll, color=CARD2,
                     border_width=1, border_color=bdr)
        card.pack(fill='x', pady=2, padx=2)
        card.grid_columnconfigure(0, weight=1)

        hdr = frame(card, color='transparent')
        hdr.grid(row=0, column=0, sticky='ew', padx=10, pady=(8,2))
        hdr.grid_columnconfigure(0, weight=1)

        name_row = frame(hdr, color='transparent')
        name_row.grid(row=0, column=0, sticky='ew')
        name_row.grid_columnconfigure(0, weight=1)
        label(name_row, fix.name.upper(), size=10, bold=True, color=TXT_C).grid(row=0, column=0, sticky='w')

        badges = frame(name_row, color='transparent')
        badges.grid(row=0, column=1)
        if fix.requires_admin:
            ctk.CTkLabel(badges, text='ADMIN', font=('Consolas',8,'bold'),
                         fg_color=YELLOW_DIM, text_color=YELLOW,
                         corner_radius=0, width=46, height=16).pack(side='left', padx=2)
        if is_sug:
            ctk.CTkLabel(badges, text='SUGGESTED', font=('Consolas',8,'bold'),
                         fg_color=CYAN_DIM, text_color=CYAN,
                         corner_radius=0, width=70, height=16).pack(side='left', padx=2)

        label(card, fix.description, size=9, color=TXT2,
              wraplength=300, justify='left').grid(
            row=1, column=0, sticky='w', padx=10, pady=(0,4))

        foot = frame(card, color='transparent')
        foot.grid(row=2, column=0, sticky='ew', padx=10, pady=(0,8))
        label(foot, f'⏱ {fix.estimated_time}', size=8, color=TXT3).pack(side='left')
        btn(foot, '[ EXECUTE ]', w=100, h=26,
            cmd=lambda fid=fix.id: self._app.apply_fix(fid),
            fg=CYAN_DIM, hv=CYAN, tc=CYAN).pack(side='right')

    def set_suggested(self, ids: List[str]):
        self._suggested = ids
        self._render_fixes()

    def log(self, text: str, color=CYAN):
        self._log.configure(state='normal')
        ts = datetime.datetime.now().strftime('%H:%M:%S')
        self._log.insert('end', f'[{ts}] {text}\n')
        self._log.see('end')
        self._log.configure(state='disabled')

    def _clear_log(self):
        self._log.configure(state='normal')
        self._log.delete('1.0','end')
        self._log.configure(state='disabled')

# ── PAGE: REPORT ───────────────────────────────────────────────────────────────

class ReportPage(ctk.CTkFrame):
    def __init__(self, parent, app, **kw):
        super().__init__(parent, fg_color=BG, corner_radius=0, **kw)
        self._app    = app
        self._issues: List[Issue] = []
        self._build()

    def _build(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        hdr = frame(self, color='transparent')
        hdr.grid(row=0, column=0, sticky='ew', padx=20, pady=(16,12))
        label(hdr, '// REPORT.LOG', size=16, bold=True, color=CYAN).pack(side='left')

        brow = frame(hdr, color='transparent')
        brow.pack(side='right')
        for txt, cmd in [('[ GENERATE ]', self._gen),
                          ('[ SAVE .TXT ]', self._save_txt),
                          ('[ SAVE .HTML ]', self._save_html)]:
            fg_c = CYAN if '[ GEN' in txt else BORDER
            tc_c = BG   if '[ GEN' in txt else CYAN
            btn(brow, txt, cmd=cmd, w=120, h=30,
                fg=fg_c, hv=CYAN, tc=tc_c).pack(side='left', padx=3)

        panel = CyberPanel(self, accent=CYAN_DIM, title='OUTPUT')
        panel.grid(row=1, column=0, sticky='nsew', padx=20, pady=(0,20))
        inner = frame(panel, color=CARD)
        inner.place(x=6, y=14, relwidth=1, relheight=1, width=-12, height=-20)
        inner.grid_columnconfigure(0, weight=1)
        inner.grid_rowconfigure(0, weight=1)

        self._text = ctk.CTkTextbox(inner, fg_color=BG, text_color=CYAN,
                                     font=('Consolas', 10), corner_radius=0,
                                     state='disabled')
        self._text.grid(row=0, column=0, sticky='nsew', padx=8, pady=8)
        self._show('> CLICK [ GENERATE ] TO BUILD DIAGNOSTIC REPORT\n')

    def _show(self, t: str):
        self._text.configure(state='normal')
        self._text.delete('1.0','end')
        self._text.insert('end', t)
        self._text.configure(state='disabled')

    def set_issues(self, issues: List[Issue]):
        self._issues = list(issues)

    def _gen(self):
        self._show(self._build_txt())

    def _build_txt(self) -> str:
        now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        lines = [
            '╔' + '═'*62 + '╗',
            '║  WINDIAG PRO // DIAGNOSTIC REPORT' + ' '*27 + '║',
            f'║  Generated : {now}' + ' '*(47-len(now)) + '║',
            f'║  Host      : {platform.node():<47}║',
            f'║  OS        : {platform.platform()[:46]:<47}║',
            f'║  Admin     : {"YES" if is_admin() else "NO — some checks may be incomplete":<47}║',
            '╚' + '═'*62 + '╝', '',
        ]
        from scanner import DiagnosticScanner as _DS
        tmp = _DS(); tmp.issues = self._issues
        s = tmp.summary()
        lines += [
            f'  HEALTH SCORE : {s["health_score"]}/100',
            f'  CRITICAL     : {s["critical"]}',
            f'  WARNINGS     : {s["warnings"]}',
            f'  INFO         : {s["info"]}',
            f'  TOTAL        : {s["total"]}',
            '',
        ]
        for sev in (Severity.CRITICAL, Severity.WARNING, Severity.INFO):
            items = [i for i in self._issues if i.severity == sev]
            if not items: continue
            lines.append(f'── {sev.label.upper()} ({len(items)}) ' + '─'*40)
            for i in items:
                lines += [f'  {SEV_ICON[sev]} [{i.category.value}] {i.title}',
                           f'     {i.description[:100]}', '']
        lines += ['═'*64, 'END OF REPORT']
        return '\n'.join(lines)

    def _save_txt(self):
        from tkinter import filedialog
        p = filedialog.asksaveasfilename(defaultextension='.txt',
            filetypes=[('Text','*.txt'),('All','*.*')])
        if p:
            try:
                Path(p).write_text(self._build_txt(), encoding='utf-8')
                self._show(f'> REPORT SAVED: {p}\n\n' + self._build_txt())
            except Exception as e:
                self._show(f'> ERROR: {e}')

    def _save_html(self):
        from tkinter import filedialog
        p = filedialog.asksaveasfilename(defaultextension='.html',
            filetypes=[('HTML','*.html'),('All','*.*')])
        if not p: return
        try:
            rows = ''
            for i in self._issues:
                c = {'Critical':CRIT,'Warning':WARN,'Info':INFO}.get(i.severity.label,'#aaa')
                rows += (f'<tr><td style="color:{c};font-weight:bold">{i.severity.label}</td>'
                         f'<td style="color:#888">{i.category.value}</td>'
                         f'<td>{i.title}</td>'
                         f'<td style="color:#0f9">{"✓" if i.fix_available else ""}</td></tr>\n')
            html = f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>WinDiag Pro Report</title>
<style>
*{{box-sizing:border-box}}
body{{font-family:Consolas,monospace;background:#06060F;color:#C8C8E8;padding:24px;margin:0}}
h1{{color:#00F5FF;border-bottom:1px solid #1C1C3C;padding-bottom:12px}}
.meta{{color:#606090;font-size:12px;margin-bottom:24px}}
table{{width:100%;border-collapse:collapse}}
th{{background:#0A0A1A;color:#00F5FF;padding:10px;text-align:left;border-bottom:1px solid #1C1C3C}}
td{{padding:8px 10px;border-bottom:1px solid #111128;font-size:13px}}
tr:hover td{{background:#0D0D20}}
</style></head><body>
<h1>// WINDIAG PRO — DIAGNOSTIC REPORT</h1>
<div class="meta">
Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} &nbsp;|&nbsp;
Host: {platform.node()} &nbsp;|&nbsp;
Health: {DiagnosticScanner().health_score() if False else '—'}/100
</div>
<table>
<tr><th>SEVERITY</th><th>CATEGORY</th><th>ISSUE</th><th>FIX</th></tr>
{rows}
</table></body></html>"""
            Path(p).write_text(html, encoding='utf-8')
            self._show(f'> HTML REPORT SAVED: {p}')
        except Exception as e:
            self._show(f'> ERROR: {e}')

# ── PAGE: SETTINGS ─────────────────────────────────────────────────────────────

class SettingsPage(ctk.CTkFrame):
    def __init__(self, parent, app, settings: Dict, **kw):
        super().__init__(parent, fg_color=BG, corner_radius=0, **kw)
        self._app      = app
        self._settings = settings
        self._vars: Dict = {}
        self._build()

    def _build(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        hdr = frame(self, color='transparent')
        hdr.grid(row=0, column=0, sticky='ew', padx=20, pady=(16,12))
        label(hdr, '// CONFIG', size=16, bold=True, color=CYAN).pack(side='left')
        btn(hdr, '[ SAVE CONFIG ]', cmd=self._save,
            w=150, h=34, fg=CYAN, hv=CYAN, tc=BG).pack(side='right')

        tabs = ctk.CTkTabview(self, fg_color=PANEL, corner_radius=0,
                               segmented_button_fg_color=CARD,
                               segmented_button_selected_color=CYAN,
                               segmented_button_selected_hover_color=CYAN,
                               segmented_button_unselected_color=CARD,
                               segmented_button_unselected_hover_color=CARD2,
                               text_color=TXT, text_color_disabled=TXT3,
                               border_width=1, border_color=BORDER)
        tabs.grid(row=1, column=0, sticky='nsew', padx=20, pady=(0,20))
        for n in ('SCAN OPTIONS', 'APPEARANCE', 'SYSTEM INFO'):
            tabs.add(n)
        self._build_scan(tabs.tab('SCAN OPTIONS'))
        self._build_appear(tabs.tab('APPEARANCE'))
        self._build_info(tabs.tab('SYSTEM INFO'))

    def _cfg_row(self, parent, title: str) -> ctk.CTkFrame:
        f = frame(parent, color=CARD2, border_width=1, border_color=BORDER)
        f.pack(fill='x', pady=3)
        label(f, f'▸ {title.upper()}', size=9, bold=True, color=CYAN).pack(
            anchor='w', padx=12, pady=(10,4))
        neon_sep(f, BORDER).pack(fill='x', padx=12)
        inner = frame(f, color='transparent')
        inner.pack(fill='x', padx=12, pady=(6,10))
        return inner

    def _build_scan(self, parent):
        sc = ctk.CTkScrollableFrame(parent, fg_color='transparent',
                                     scrollbar_button_color=BORDER)
        sc.pack(fill='both', expand=True, padx=8, pady=8)

        # Days back
        r1 = self._cfg_row(sc, 'Event Log Lookback Period')
        label(r1, 'DAYS TO SCAN:', size=10, color=TXT2).pack(side='left')
        dv = ctk.StringVar(value=str(self._settings.get('days_back',7)))
        self._vars['days_back'] = dv
        ctk.CTkSegmentedButton(r1, values=['1','3','7','14','30'],
                                variable=dv,
                                fg_color=CARD, selected_color=CYAN,
                                selected_hover_color=CYAN,
                                unselected_color=CARD, unselected_hover_color=BORDER,
                                text_color=BG, font=('Consolas',11)
                                ).pack(side='right')

        # Log names
        r2 = self._cfg_row(sc, 'Event Log Sources')
        lv: Dict[str, ctk.BooleanVar] = {}
        cur_logs = self._settings.get('log_names', ['System','Application'])
        for log in ['System','Application','Security','Setup']:
            v = ctk.BooleanVar(value=log in cur_logs)
            lv[log] = v
            ctk.CTkCheckBox(r2, text=log.upper(), variable=v,
                             font=('Consolas',11), fg_color=CYAN,
                             hover_color=CYAN, text_color=TXT,
                             checkmark_color=BG).pack(anchor='w', pady=2)
        self._vars['log_vars'] = lv

        # Categories
        r3 = self._cfg_row(sc, 'Scan Categories')
        cv: Dict[str, ctk.BooleanVar] = {}
        cur_cats = self._settings.get('scan_categories', [c.value for c in ScanCategory])
        for cat in ScanCategory:
            v = ctk.BooleanVar(value=cat.value in cur_cats)
            cv[cat.value] = v
            ctk.CTkCheckBox(r3, text=cat.value.upper(), variable=v,
                             font=('Consolas',11), fg_color=CYAN,
                             hover_color=CYAN, text_color=TXT,
                             checkmark_color=BG).pack(anchor='w', pady=2)
        self._vars['cat_vars'] = cv

        # Misc
        r4 = self._cfg_row(sc, 'Behaviour')
        av = ctk.BooleanVar(value=self._settings.get('auto_scan_on_start',False))
        iv = ctk.BooleanVar(value=self._settings.get('show_info_issues',True))
        self._vars['auto'] = av
        self._vars['info'] = iv
        for text, v in [('AUTO-SCAN ON STARTUP', av), ('SHOW INFO-LEVEL ISSUES', iv)]:
            ctk.CTkCheckBox(r4, text=text, variable=v,
                             font=('Consolas',11), fg_color=CYAN,
                             hover_color=CYAN, text_color=TXT,
                             checkmark_color=BG).pack(anchor='w', pady=2)

    def _build_appear(self, parent):
        f = frame(parent, color='transparent')
        f.pack(fill='x', padx=16, pady=16)
        r = self._cfg_row(f, 'UI Theme')
        label(r, 'THEME:', size=10, color=TXT2).pack(side='left')
        tv = ctk.StringVar(value=self._settings.get('theme','dark').capitalize())
        self._vars['theme'] = tv
        ctk.CTkSegmentedButton(r, values=['Dark','Light','System'], variable=tv,
                                fg_color=CARD, selected_color=CYAN,
                                selected_hover_color=CYAN,
                                unselected_color=CARD, text_color=BG,
                                font=('Consolas',11),
                                command=lambda v: ctk.set_appearance_mode(v.lower())
                                ).pack(side='right')

    def _build_info(self, parent):
        f = frame(parent, color='transparent')
        f.pack(fill='both', expand=True, padx=20, pady=20)

        label(f, 'WINDIAG.EXE', size=20, bold=True, color=CYAN).pack(pady=(10,2))
        label(f, 'Windows 10/11 Diagnostic & Repair Tool', size=11, color=TXT2).pack()
        label(f, 'v1.0.0  //  Cyberpunk Edition', size=10, color=TXT3).pack(pady=(2,16))
        neon_sep(f, CYAN_DIM).pack(fill='x', pady=8)

        for k, v in [
            ('PYTHON',    platform.python_version()),
            ('OS',        platform.platform()[:50]),
            ('HOSTNAME',  platform.node()),
            ('ADMIN',     'YES' if is_admin() else 'NO'),
            ('SETTINGS',  str(SETTINGS_PATH)),
        ]:
            row = frame(f, color='transparent')
            row.pack(fill='x', pady=3)
            label(row, f'{k}:', size=10, bold=True, color=CYAN_DIM).pack(side='left', padx=(0,12))
            label(row, v[:60], size=10, color=TXT2).pack(side='left')

        neon_sep(f, CYAN_DIM).pack(fill='x', pady=16)
        if not is_admin():
            btn(f, '[ RESTART AS ADMINISTRATOR ]',
                cmd=lambda: (request_elevation(), sys.exit()),
                w=280, h=36, fg=YELLOW_DIM, hv=YELLOW, tc=YELLOW).pack(pady=8)
            label(f, 'Required for SFC, DISM, network reset, and service fixes.',
                  size=9, color=TXT3).pack()

    def _save(self):
        try: days = int(self._vars['days_back'].get())
        except ValueError: days = 7
        logs = [k for k,v in self._vars['log_vars'].items() if v.get()]
        cats = [k for k,v in self._vars['cat_vars'].items() if v.get()]
        self._settings.update({
            'days_back': days, 'log_names': logs, 'scan_categories': cats,
            'auto_scan_on_start': self._vars['auto'].get(),
            'show_info_issues': self._vars['info'].get(),
            'theme': self._vars['theme'].get().lower(),
        })
        save_settings(self._settings)
        self._app.show_toast('CONFIG SAVED')

# ── TOAST ──────────────────────────────────────────────────────────────────────

class Toast(ctk.CTkToplevel):
    def __init__(self, parent, msg: str, color=CYAN):
        super().__init__(parent)
        self.overrideredirect(True)
        self.attributes('-topmost', True)
        self.configure(fg_color=CARD2)

        f = frame(self, color=CARD2, border_width=1, border_color=color)
        f.pack()
        label(f, f'  {msg}  ', size=11, bold=True, color=color).pack(padx=4, pady=10)

        self.update_idletasks()
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        self.geometry(f'+{sw - self.winfo_width() - 28}+{sh - self.winfo_height() - 56}')
        self.after(3000, self.destroy)

# ── FIX CONFIRM DIALOG ─────────────────────────────────────────────────────────

class FixDialog(ctk.CTkToplevel):
    def __init__(self, parent, fix_id: str, on_confirm):
        super().__init__(parent)
        meta = FIX_MAP.get(fix_id)
        self.title('CONFIRM FIX')
        self.geometry('480x280')
        self.resizable(False, False)
        self.configure(fg_color=PANEL)
        self.attributes('-topmost', True)
        self.grab_set()

        cv = tk.Canvas(self, bg=PANEL, highlightthickness=0, height=3)
        cv.pack(fill='x')
        cv.create_line(0,1,480,1, fill=CYAN, width=2)

        label(self, '// EXECUTE FIX', size=14, bold=True, color=CYAN).pack(pady=(16,4))
        name = meta.name.upper() if meta else fix_id
        label(self, name, size=12, bold=True, color=TXT).pack()

        if meta:
            label(self, meta.description, size=10, color=TXT2,
                  wraplength=400, justify='center').pack(pady=(8,4))
            if meta.requires_admin and not is_admin():
                label(self, '⚠ REQUIRES ADMIN — MAY FAIL WITHOUT ELEVATION',
                      size=9, bold=True, color=WARN).pack(pady=2)
            label(self, f'EST. TIME: {meta.estimated_time.upper()}',
                  size=9, color=TXT3).pack()

        brow = frame(self, color='transparent')
        brow.pack(pady=20)
        btn(brow, '[ EXECUTE ]', cmd=lambda: (self.destroy(), on_confirm()),
            w=120, h=34, fg=CYAN, hv=CYAN, tc=BG).pack(side='left', padx=10)
        btn(brow, '[ CANCEL ]', cmd=self.destroy,
            w=100, h=34, fg=BORDER, hv=BORDER2, tc=TXT2).pack(side='left')

# ── MAIN APP ───────────────────────────────────────────────────────────────────

class App(ctk.CTk):
    def __init__(self):
        self._settings = load_settings()
        ctk.set_appearance_mode(self._settings.get('theme','dark'))
        ctk.set_default_color_theme('blue')
        super().__init__()

        self.title('[ WINDIAG.EXE ]  —  Windows 10/11 Diagnostic Tool')
        self.geometry('1360x840')
        self.minsize(960, 620)
        self.configure(fg_color=BG)

        self._scanner  = DiagnosticScanner(settings=self._settings)
        self._fixer    = DiagnosticFixer(progress_cb=self._on_fix_prog)
        self._scanning = False
        self._q: queue.Queue = queue.Queue()
        self._issues: List[Issue] = []

        self._build()
        if self._settings.get('auto_scan_on_start', False):
            self.after(600, self.start_scan)
        self.after(100, self._poll)

    def _build(self):
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # Top scanline
        ScanlineHeader(self, height=4).grid(row=0, column=0, columnspan=2, sticky='ew')

        self._sidebar = Sidebar(self, on_nav=self.nav)
        self._sidebar.grid(row=1, column=0, sticky='nsew')
        # Build nav after sidebar is placed
        self._sidebar._build_nav()

        self._content = frame(self, color=BG)
        self._content.grid(row=1, column=1, sticky='nsew')
        self._content.grid_columnconfigure(0, weight=1)
        self._content.grid_rowconfigure(0, weight=1)

        self._pages: Dict[str, ctk.CTkFrame] = {
            'dashboard':   DashboardPage(self._content, app=self),
            'diagnostics': DiagnosticsPage(self._content, app=self),
            'fixes':       FixCenterPage(self._content, app=self),
            'report':      ReportPage(self._content, app=self),
            'settings':    SettingsPage(self._content, app=self, settings=self._settings),
        }
        for p in self._pages.values():
            p.grid(row=0, column=0, sticky='nsew')

        self.nav('dashboard')

    def nav(self, page_id: str):
        self._sidebar.select(page_id)
        self._pages[page_id].tkraise()

    # ── Scanning ──────────────────────────────────────────────────────────────

    def start_scan(self):
        if self._scanning:
            return
        self._scanning = True
        self._pages['diagnostics'].clear()
        self.nav('diagnostics')

        enabled = [c for c in ScanCategory
                   if c.value in self._settings.get('scan_categories',
                                                     [c.value for c in ScanCategory])]
        self._scanner = DiagnosticScanner(settings=self._settings)
        self._scanner.on_progress(lambda m, p: self._q.put(('progress', m, p)))
        self._scanner.on_issue(lambda i: self._q.put(('issue', i)))

        def run():
            try:
                issues = self._scanner.scan_all(categories=enabled)
                self._q.put(('done', issues))
            except Exception as e:
                self._q.put(('error', str(e)))

        threading.Thread(target=run, daemon=True).start()

    def _poll(self):
        try:
            while True:
                self._handle(self._q.get_nowait())
        except queue.Empty:
            pass
        self.after(80, self._poll)

    def _handle(self, msg):
        kind = msg[0]
        if kind == 'progress':
            _, text, pct = msg
            self._pages['diagnostics'].set_progress(text, pct)
            self._pages['dashboard'].set_status(text)
        elif kind == 'issue':
            self._pages['diagnostics'].add_issue(msg[1])
        elif kind == 'done':
            issues = msg[1]
            self._issues = list(issues)
            self._scanning = False
            s = self._scanner.summary()
            self._pages['dashboard'].update_results(issues, s)
            self._pages['report'].set_issues(issues)
            sug = list(dict.fromkeys(i.fix_id for i in issues if i.fix_available and i.fix_id))
            self._pages['fixes'].set_suggested(sug)
            self._pages['diagnostics'].set_progress(
                f'SCAN COMPLETE  //  {s["total"]} ISSUES FOUND', 100)
            self._pages['dashboard'].set_status(
                f'LAST SCAN {datetime.datetime.now().strftime("%H:%M:%S")}  '
                f'//  SCORE {s["health_score"]}/100  '
                f'//  {s["critical"]} CRITICAL  {s["warnings"]} WARN',
                color=CRIT if s['critical'] > 0 else (WARN if s['warnings'] > 0 else SUCC))
        elif kind == 'error':
            self._scanning = False
            self._pages['diagnostics'].set_progress(f'ERROR: {msg[1]}', 0)
        elif kind == 'fix_done':
            res: FixResult = msg[1]
            c = SUCC if res.success else CRIT
            self._pages['fixes'].log(f'{"OK" if res.success else "FAIL"}  {res.message}', c)
            if res.details:
                self._pages['fixes'].log(f'     {res.details}', TXT2)
            if res.requires_reboot:
                self._pages['fixes'].log('     >> RESTART REQUIRED TO COMPLETE', WARN)
            self.show_toast(res.message, c)

    # ── Fixes ─────────────────────────────────────────────────────────────────

    def apply_fix(self, fix_id: Optional[str]):
        if not fix_id:
            return
        FixDialog(self, fix_id, on_confirm=lambda: self._run_fix(fix_id))

    def _run_fix(self, fix_id: str):
        self.nav('fixes')
        meta = FIX_MAP.get(fix_id)
        self._pages['fixes'].log(f'EXECUTING: {meta.name.upper() if meta else fix_id}')

        def run():
            result = self._fixer.apply_fix(fix_id)
            self._q.put(('fix_done', result))

        threading.Thread(target=run, daemon=True).start()

    def _on_fix_prog(self, msg: str, pct: float):
        self._q.put(('progress', msg, pct))

    def show_toast(self, msg: str, color=CYAN):
        try:
            Toast(self, msg.upper(), color)
        except Exception:
            pass


def main():
    app = App()
    app.mainloop()

if __name__ == '__main__':
    main()
