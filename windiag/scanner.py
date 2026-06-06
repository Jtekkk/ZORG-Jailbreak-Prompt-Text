"""
WinDiag Pro - Diagnostic Scanner
"""

import subprocess
import xml.etree.ElementTree as ET
import datetime
import os
import glob as glob_mod
import socket
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Callable, Tuple
from enum import Enum

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

try:
    import winreg
    WINREG_AVAILABLE = True
except ImportError:
    WINREG_AVAILABLE = False

_EVTNS   = 'http://schemas.microsoft.com/win/2004/08/events/event'
_NO_WIN  = getattr(subprocess, 'CREATE_NO_WINDOW', 0)


# -----------------------------------------------------------------------
# Enums & dataclasses
# -----------------------------------------------------------------------

class Severity(Enum):
    INFO     = ('Info',     0, '#60CDFF')
    WARNING  = ('Warning',  1, '#FCB900')
    CRITICAL = ('Critical', 2, '#E74856')

    def __init__(self, label: str, priority: int, color: str):
        self.label    = label
        self.priority = priority
        self.color    = color


class ScanCategory(Enum):
    EVENT_LOG   = 'Event Logs'
    HARDWARE    = 'Hardware'
    PERFORMANCE = 'Performance'
    NETWORK     = 'Network'
    SERVICES    = 'Services'
    SYSTEM      = 'System'
    SECURITY    = 'Security'
    DRIVERS     = 'Drivers'
    STARTUP     = 'Startup'
    RELIABILITY = 'Reliability'


@dataclass
class Issue:
    id:            str
    title:         str
    description:   str
    severity:      Severity
    category:      ScanCategory
    fix_available: bool              = False
    fix_id:        Optional[str]     = None
    details:       Dict[str, Any]    = field(default_factory=dict)
    timestamp:     Optional[datetime.datetime] = None

    def to_dict(self) -> Dict:
        return {
            'id':           self.id,
            'title':        self.title,
            'description':  self.description,
            'severity':     self.severity.label,
            'category':     self.category.value,
            'fix_available': self.fix_available,
            'fix_id':       self.fix_id,
            'timestamp':    self.timestamp.isoformat() if self.timestamp else None,
            'details':      self.details,
        }


# -----------------------------------------------------------------------
# System / Application log — known bad event IDs
# -----------------------------------------------------------------------

CRITICAL_EVENT_IDS: Dict[str, Tuple[str, str]] = {
    '41':   ('Kernel-Power',            'System crashed or lost power unexpectedly'),
    '6008': ('EventLog',                'Previous system shutdown was unexpected'),
    '1001': ('BugCheck',                'Blue Screen of Death (system crash)'),
    '55':   ('Ntfs',                    'NTFS file system structure on disk is corrupt'),
    '7023': ('Service Control Manager', 'Critical service terminated with an error'),
    '7024': ('Service Control Manager', 'Service terminated with a service-specific error'),
    '7026': ('Service Control Manager', 'Boot-start or system-start driver failed to load'),
    '7034': ('Service Control Manager', 'Service terminated unexpectedly'),
    '157':  ('disk',                    'Disk was surprise-removed or suffered I/O failure'),
}

WARNING_EVENT_IDS: Dict[str, Tuple[str, str]] = {
    '51':   ('disk',                    'Disk paging error detected on a device'),
    '11':   ('disk',                    'Controller error detected on a disk device'),
    '129':  ('StorPort',                'A reset was issued to the disk device'),
    '219':  ('',                        'A driver package failed to load'),
    '7031': ('Service Control Manager', 'Service crashed and was restarted'),
    '7036': ('Service Control Manager', 'Service changed state unexpectedly'),
    '7040': ('Service Control Manager', 'Service start type was changed'),
    '1000': ('Application Error',       'Application crashed (unhandled exception)'),
    '1002': ('Application Hang',        'Application stopped responding'),
    '1026': ('.NET Runtime',            '.NET runtime error occurred'),
    '36':   ('volmgr',                  'Crash dump was not created — paging file may be misconfigured'),
    '153':  ('disk',                    'The IO operation at block X failed after retries'),
}

# -----------------------------------------------------------------------
# Extended channel knowledge bases
# -----------------------------------------------------------------------

# WHEA — hardware errors (CPU, RAM, chipset)
WHEA_CRIT = {
    '1':  'Fatal hardware error — possible CPU, RAM, or chipset fault',
    '18': 'A fatal machine check exception was reported',
    '47': 'Predictive hardware failure detected on a component',
}
WHEA_WARN = {
    '19': 'Corrected hardware error (system recovered but hardware may be degrading)',
    '20': 'Hardware error threshold exceeded',
}

# Windows Update Client
WU_CRIT = {
    '20': 'Windows Update failed to install an update',
    '31': 'Windows Update failed to download an update',
}
WU_WARN = {
    '43': 'Windows Update search failed',
    '25': 'Windows requires a restart to finish installing updates',
}

# Task Scheduler
TASK_CRIT = {
    '101': 'Scheduled task failed to start',
    '202': 'Task action completed with non-zero return code',
}
TASK_WARN = {
    '103': 'Task was terminated because it exceeded its time limit',
}

# Code Integrity — driver signing violations
CI_CRIT = {
    '3001': 'An unsigned kernel module was blocked from loading',
    '3002': 'Code integrity could not verify the file — driver may be tampered',
    '3003': 'An unsigned driver was blocked',
    '3004': 'Windows could not verify file due to missing page hash',
    '3033': 'Code integrity check failed — driver cannot be loaded',
    '3034': 'An untrusted driver was blocked',
}

# Kernel-Boot performance
BOOT_WARN = {
    '20': 'System boot performance issue — unusually slow startup',
    '27': 'System did not resume from hibernation correctly',
}

# Diagnostics-Performance
PERF_WARN = {
    '100': 'System boot is slower than expected',
    '102': 'System shutdown was slow',
    '200': 'An application degraded boot performance',
    '201': 'An application degraded shutdown performance',
}

# Memory Diagnostics results
MEMDUMP_CRIT = {
    '1201': 'Windows Memory Diagnostic found memory errors — RAM may be failing',
    '1202': 'Memory diagnostic completed with errors',
}

# Security log anomalies (admin only)
SEC_WARN = {
    '4625': 'Failed logon attempt',
    '4740': 'A user account was locked out',
    '4719': 'System audit policy was changed',
}
SEC_CRIT = {
    '4732': 'A member was added to the local Administrators group',
    '4776': 'NTLM credential validation failure (possible brute-force)',
    '4697': 'A service was installed in the system',
}

# -----------------------------------------------------------------------
# Extended channels: (log_name, category, crit_dict, warn_dict)
# -----------------------------------------------------------------------

EXTENDED_CHANNELS = [
    ('Microsoft-Windows-WHEA-Logger/Operational',
     ScanCategory.HARDWARE,     WHEA_CRIT, WHEA_WARN),

    ('Microsoft-Windows-WindowsUpdateClient/Operational',
     ScanCategory.SYSTEM,       WU_CRIT,   WU_WARN),

    ('Microsoft-Windows-TaskScheduler/Operational',
     ScanCategory.SYSTEM,       TASK_CRIT, TASK_WARN),

    ('Microsoft-Windows-CodeIntegrity/Operational',
     ScanCategory.DRIVERS,      CI_CRIT,   {}),

    ('Microsoft-Windows-Kernel-Boot/Operational',
     ScanCategory.PERFORMANCE,  {},        BOOT_WARN),

    ('Microsoft-Windows-Diagnostics-Performance/Operational',
     ScanCategory.PERFORMANCE,  {},        PERF_WARN),

    ('Microsoft-Windows-MemoryDiagnostics-Results/Debug',
     ScanCategory.HARDWARE,     MEMDUMP_CRIT, {}),
]

# -----------------------------------------------------------------------
# Services that should be running
# -----------------------------------------------------------------------

CRITICAL_SERVICES = [
    ('wuauserv',          'Windows Update'),
    ('WinDefend',         'Windows Defender Antivirus'),
    ('EventLog',          'Windows Event Log'),
    ('Dnscache',          'DNS Client'),
    ('DHCP',              'DHCP Client'),
    ('RpcSs',             'Remote Procedure Call (RPC)'),
    ('Schedule',          'Task Scheduler'),
    ('LanmanWorkstation', 'Workstation'),
    ('BFE',               'Base Filtering Engine (Firewall)'),
    ('mpssvc',            'Windows Firewall'),
    ('VSS',               'Volume Shadow Copy'),
    ('Spooler',           'Print Spooler'),
    ('W32Time',           'Windows Time'),
    ('CryptSvc',          'Cryptographic Services'),
    ('TrustedInstaller',  'Windows Modules Installer'),
]

# Device Manager error code descriptions
DEVICE_ERRORS = {
    1:  'Device is not configured correctly',
    2:  'Windows cannot find required drivers',
    3:  'Driver for this device may be corrupt',
    10: 'Device cannot start',
    12: 'Cannot find enough free resources',
    14: 'Restart required to finish device setup',
    18: 'Reinstall device drivers',
    19: 'Device registry may be corrupt',
    21: 'System is removing this device',
    22: 'Device is disabled',
    24: 'Device is not present or working properly',
    28: 'Drivers for this device are not installed',
    31: 'Device is not working — may need reinstall',
    43: 'Windows stopped this device due to reported problems',
    45: 'Device is not connected',
    52: 'Windows cannot verify digital signature of drivers',
}


# -----------------------------------------------------------------------
# Main scanner class
# -----------------------------------------------------------------------

class DiagnosticScanner:
    def __init__(self, settings: Optional[Dict] = None):
        self.settings  = settings or {}
        self.issues:   List[Issue] = []
        self._on_progress: Optional[Callable[[str, float], None]] = None
        self._on_issue:    Optional[Callable[[Issue], None]]      = None

    def on_progress(self, cb: Callable[[str, float], None]):
        self._on_progress = cb

    def on_issue(self, cb: Callable[[Issue], None]):
        self._on_issue = cb

    def _progress(self, msg: str, pct: float):
        if self._on_progress:
            self._on_progress(msg, pct)

    def _add(self, issue: Issue):
        self.issues.append(issue)
        if self._on_issue:
            self._on_issue(issue)

    # ------------------------------------------------------------------
    # Orchestration
    # ------------------------------------------------------------------

    def scan_all(self, categories: Optional[List[ScanCategory]] = None) -> List[Issue]:
        self.issues = []
        enabled = set(categories or list(ScanCategory))

        steps = [
            (ScanCategory.EVENT_LOG,   'Scanning System & Application logs…',    self._scan_event_logs),
            (ScanCategory.EVENT_LOG,   'Scanning operational event channels…',    self._scan_extended_logs),
            (ScanCategory.HARDWARE,    'Checking disk health (SMART)…',           self._scan_disk_smart),
            (ScanCategory.HARDWARE,    'Checking disk space & battery…',          self._scan_hardware),
            (ScanCategory.PERFORMANCE, 'Checking memory, CPU, page file…',        self._scan_performance),
            (ScanCategory.PERFORMANCE, 'Checking temp files & hibernate…',        self._scan_hiberfil),
            (ScanCategory.NETWORK,     'Checking network connectivity…',          self._scan_network),
            (ScanCategory.NETWORK,     'Checking time synchronisation…',          self._scan_time_sync),
            (ScanCategory.SERVICES,    'Checking critical services…',             self._scan_services),
            (ScanCategory.SYSTEM,      'Checking system health & WMI…',           self._scan_system),
            (ScanCategory.SYSTEM,      'Checking WMI repository…',                self._scan_wmi),
            (ScanCategory.RELIABILITY, 'Checking crash dumps…',                   self._scan_crash_dumps),
            (ScanCategory.RELIABILITY, 'Checking restore points & pending reboot…', self._scan_reliability_misc),
            (ScanCategory.SECURITY,    'Checking firewall & UAC…',                self._scan_uac_firewall),
            (ScanCategory.SECURITY,    'Checking user accounts…',                 self._scan_user_accounts),
            (ScanCategory.SECURITY,    'Scanning Security event log…',            self._scan_security_log),
            (ScanCategory.DRIVERS,     'Checking Device Manager…',                self._scan_device_manager),
            (ScanCategory.STARTUP,     'Checking startup programs…',              self._scan_startup_programs),
        ]

        active = [(cat, msg, fn) for (cat, msg, fn) in steps if cat in enabled]
        total  = max(len(active), 1)

        for idx, (_, msg, fn) in enumerate(active):
            self._progress(msg, idx / total * 100)
            try:
                fn()
            except Exception:
                pass

        self._progress('Scan complete', 100.0)
        return self.issues

    # ------------------------------------------------------------------
    # Event log helpers
    # ------------------------------------------------------------------

    def _query_log(self, log_name: str, hours_back: int,
                   max_events: int = 300, level_filter: int = 3) -> List[Dict]:
        start    = datetime.datetime.utcnow() - datetime.timedelta(hours=hours_back)
        start_s  = start.strftime('%Y-%m-%dT%H:%M:%S')
        q = (f"*[System[(Level<={level_filter}) and "
             f"TimeCreated[@SystemTime>='{start_s}']]]")
        cmd = ['wevtutil', 'qe', log_name,
               f'/c:{max_events}', '/f:xml', '/rd:true', f'/q:{q}']
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=30, creationflags=_NO_WIN)
            return self._parse_wevtutil(r.stdout)
        except Exception:
            return []

    def _parse_wevtutil(self, output: str) -> List[Dict]:
        if not output.strip():
            return []
        try:
            root = ET.fromstring(f'<R>{output}</R>')
            return [e for e in (self._parse_el(el) for el in root) if e]
        except ET.ParseError:
            events = []
            for chunk in output.split('</Event>'):
                chunk = chunk.strip()
                if not chunk:
                    continue
                try:
                    ev = self._parse_el(ET.fromstring(chunk + '</Event>'))
                    if ev:
                        events.append(ev)
                except ET.ParseError:
                    continue
            return events

    def _parse_el(self, el) -> Optional[Dict]:
        try:
            ns  = _EVTNS
            sys = el.find(f'{{{ns}}}System')
            if sys is None:
                return None

            def txt(tag):
                n = sys.find(f'{{{ns}}}{tag}')
                return n.text if n is not None else ''

            def attr(tag, key):
                n = sys.find(f'{{{ns}}}{tag}')
                return n.get(key, '') if n is not None else ''

            lvl_s = txt('Level')
            level = int(lvl_s) if lvl_s.isdigit() else 4
            if level > 3:
                return None

            ts = None
            ts_s = attr('TimeCreated', 'SystemTime')
            if ts_s:
                for fmt in ('%Y-%m-%dT%H:%M:%S.%f%z', '%Y-%m-%dT%H:%M:%S%z',
                            '%Y-%m-%dT%H:%M:%S'):
                    try:
                        ts = datetime.datetime.strptime(ts_s[:26], fmt[:len(ts_s)])
                        break
                    except ValueError:
                        pass

            data_el = el.find(f'{{{ns}}}EventData')
            data = []
            if data_el is not None:
                data = [d.text.strip() for d in data_el if d.text and d.text.strip()]

            return {
                'event_id': txt('EventID'),
                'level':    level,
                'provider': attr('Provider', 'Name'),
                'timestamp': ts,
                'data':     data,
            }
        except Exception:
            return None

    def _analyze_events(self, events: List[Dict], log_name: str):
        """Analyze events from System/Application log."""
        seen: Dict[str, int] = {}
        for ev in events:
            eid   = ev.get('event_id', '')
            level = ev.get('level', 4)
            prov  = ev.get('provider', '')
            ts    = ev.get('timestamp')
            data  = ev.get('data', [])
            detail = '; '.join(data[:3]) if data else ''

            if eid in CRITICAL_EVENT_IDS:
                _, desc = CRITICAL_EVENT_IDS[eid]
                sev = Severity.CRITICAL
                fix_id = {
                    '41': 'fix_check_disk', '55': 'fix_check_disk',
                    '7023': 'fix_sfc_dism', '7024': 'fix_sfc_dism',
                    '7026': 'fix_sfc_dism', '7034': None,
                }.get(eid)

            elif eid in WARNING_EVENT_IDS:
                _, desc = WARNING_EVENT_IDS[eid]
                sev = Severity.WARNING
                fix_id = 'fix_sfc_dism' if eid in ('55', '51', '153') else None

            elif level <= 2:
                desc   = f'Critical error from {prov or "unknown source"}'
                sev    = Severity.CRITICAL
                fix_id = None
            else:
                continue

            key   = f'{log_name}_{eid}'
            count = seen.get(key, 0)
            seen[key] = count + 1
            if count >= 3:
                continue

            extra = f'\nDetails: {detail}' if detail else ''
            self._add(Issue(
                id=f'evt_{log_name}_{eid}_{count}',
                title=f'[{log_name}] Event {eid}: {desc[:80]}',
                description=f'{desc}{extra}',
                severity=sev,
                category=ScanCategory.EVENT_LOG,
                fix_available=fix_id is not None,
                fix_id=fix_id,
                timestamp=ts,
                details={'event_id': eid, 'log': log_name, 'provider': prov,
                         'occurrences': seen[key]},
            ))

    def _analyze_channel(self, events: List[Dict], channel: str,
                         category: ScanCategory,
                         crit: Dict, warn: Dict):
        """Generic analyzer for extended operational log channels."""
        short = channel.split('Microsoft-Windows-')[-1].split('/')[0]
        seen: Dict[str, int] = {}

        for ev in events:
            eid   = ev.get('event_id', '')
            level = ev.get('level', 4)
            ts    = ev.get('timestamp')
            data  = ev.get('data', [])
            detail = '; '.join(data[:3]) if data else ''

            if eid in crit:
                desc, sev = crit[eid], Severity.CRITICAL
            elif eid in warn:
                desc, sev = warn[eid], Severity.WARNING
            elif level <= 2:
                desc, sev = f'Error in {short}', Severity.CRITICAL
            else:
                continue

            key   = f'{short}_{eid}'
            count = seen.get(key, 0)
            seen[key] = count + 1
            if count >= 2:
                continue

            extra = f'\nDetails: {detail}' if detail else ''
            is_ci = category == ScanCategory.DRIVERS and eid in CI_CRIT
            self._add(Issue(
                id=f'ch_{short.lower()[:20].replace("-","_")}_{eid}_{count}',
                title=f'[{short}] Event {eid}: {desc[:80]}',
                description=f'{desc}{extra}',
                severity=sev,
                category=category,
                fix_available=is_ci or (category == ScanCategory.HARDWARE and sev == Severity.CRITICAL),
                fix_id='fix_sfc_dism' if is_ci else None,
                timestamp=ts,
                details={'event_id': eid, 'channel': channel},
            ))

    # ------------------------------------------------------------------
    # Scan: System & Application event logs
    # ------------------------------------------------------------------

    def _scan_event_logs(self):
        days_back = int(self.settings.get('days_back', 7))
        for log in self.settings.get('log_names', ['System', 'Application']):
            if log in ('Security',):
                continue  # handled separately
            events = self._query_log(log, days_back * 24)
            self._analyze_events(events, log)

    # ------------------------------------------------------------------
    # Scan: Extended operational channels
    # ------------------------------------------------------------------

    def _scan_extended_logs(self):
        days_back = int(self.settings.get('days_back', 7))
        for channel, cat, crit, warn in EXTENDED_CHANNELS:
            events = self._query_log(channel, days_back * 24, max_events=200)
            self._analyze_channel(events, channel, cat, crit, warn)

    # ------------------------------------------------------------------
    # Scan: Security event log
    # ------------------------------------------------------------------

    def _scan_security_log(self):
        if 'Security' not in self.settings.get('log_names', []):
            return
        days_back = int(self.settings.get('days_back', 7))
        events = self._query_log('Security', days_back * 24,
                                 max_events=500, level_filter=4)
        self._analyze_channel(events, 'Security', ScanCategory.SECURITY,
                              SEC_CRIT, SEC_WARN)

    # ------------------------------------------------------------------
    # Scan: Hardware
    # ------------------------------------------------------------------

    def _scan_hardware(self):
        self._check_disk_space()
        self._check_battery()

    def _check_disk_space(self):
        if PSUTIL_AVAILABLE:
            try:
                for p in psutil.disk_partitions():
                    if 'cdrom' in p.opts or not p.fstype:
                        continue
                    try:
                        u = psutil.disk_usage(p.mountpoint)
                        self._emit_disk(p.device, u.percent,
                                        u.free / 1073741824, u.total / 1073741824)
                    except PermissionError:
                        pass
                return
            except Exception:
                pass
        # fallback
        try:
            r = subprocess.run(
                ['wmic', 'logicaldisk', 'get', 'DeviceID,FreeSpace,Size'],
                capture_output=True, text=True, timeout=15, creationflags=_NO_WIN)
            for line in r.stdout.strip().splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 3:
                    try:
                        free_b, tot_b = int(parts[1]), int(parts[2])
                        if tot_b:
                            pct = (tot_b - free_b) / tot_b * 100
                            self._emit_disk(parts[0], pct,
                                            free_b / 1073741824, tot_b / 1073741824)
                    except (ValueError, ZeroDivisionError):
                        pass
        except Exception:
            pass

    def _emit_disk(self, dev: str, pct: float, free_gb: float, total_gb: float):
        if pct > 95:
            sev, title = Severity.CRITICAL, f'Drive {dev} Critically Full ({pct:.0f}%)'
            desc = (f'{dev} is {pct:.1f}% full ({free_gb:.1f} GB free of {total_gb:.1f} GB). '
                    'Windows may become unstable.')
        elif pct > 85:
            sev, title = Severity.WARNING, f'Drive {dev} Running Low ({pct:.0f}%)'
            desc = f'{dev} is {pct:.1f}% full ({free_gb:.1f} GB free). Consider freeing space.'
        else:
            return
        self._add(Issue(id=f'disk_{dev.replace(":", "")}', title=title, description=desc,
                        severity=sev, category=ScanCategory.HARDWARE,
                        fix_available=True, fix_id='fix_disk_cleanup',
                        details={'device': dev, 'percent': round(pct, 1), 'free_gb': round(free_gb, 2)}))

    def _check_battery(self):
        if not PSUTIL_AVAILABLE:
            return
        try:
            bat = psutil.sensors_battery()
            if bat is None or bat.power_plugged:
                return
            if bat.percent < 10:
                self._add(Issue(id='battery_critical',
                                title=f'Battery Critically Low ({bat.percent:.0f}%)',
                                description='Battery almost empty. Connect power immediately.',
                                severity=Severity.CRITICAL, category=ScanCategory.HARDWARE,
                                details={'percent': bat.percent}))
            elif bat.percent < 20:
                self._add(Issue(id='battery_low',
                                title=f'Battery Low ({bat.percent:.0f}%)',
                                description='Consider plugging in soon.',
                                severity=Severity.WARNING, category=ScanCategory.HARDWARE,
                                details={'percent': bat.percent}))
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Scan: Disk SMART health
    # ------------------------------------------------------------------

    def _scan_disk_smart(self):
        try:
            r = subprocess.run(
                ['powershell', '-NoProfile', '-Command',
                 'Get-PhysicalDisk | Select-Object FriendlyName,HealthStatus,OperationalStatus |'
                 ' ConvertTo-Csv -NoTypeInformation'],
                capture_output=True, text=True, timeout=15, creationflags=_NO_WIN)
            if r.returncode != 0:
                return
            for line in r.stdout.strip().splitlines()[1:]:
                parts = [p.strip('"') for p in line.split(',')]
                if len(parts) < 2:
                    continue
                name, health = parts[0], parts[1]
                h = health.lower()
                if h == 'unhealthy':
                    self._add(Issue(
                        id=f'smart_fail_{name.replace(" ", "_")[:30]}',
                        title=f'DISK FAILURE IMMINENT: {name}',
                        description=f'Drive "{name}" reports UNHEALTHY status. Back up data immediately.',
                        severity=Severity.CRITICAL, category=ScanCategory.HARDWARE,
                        details={'disk': name, 'health': health}))
                elif h in ('warning', 'degraded'):
                    self._add(Issue(
                        id=f'smart_warn_{name.replace(" ", "_")[:30]}',
                        title=f'Disk Health Warning: {name}',
                        description=f'Drive "{name}" reports {health} health status. Monitor closely.',
                        severity=Severity.WARNING, category=ScanCategory.HARDWARE,
                        details={'disk': name, 'health': health}))
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Scan: Performance
    # ------------------------------------------------------------------

    def _scan_performance(self):
        self._check_memory()
        self._check_cpu()
        self._check_pagefile()
        self._check_temp_files()

    def _check_memory(self):
        if not PSUTIL_AVAILABLE:
            return
        try:
            m = psutil.virtual_memory()
            avail = m.available / 1073741824
            total = m.total / 1073741824
            if m.percent > 90:
                self._add(Issue(id='memory_critical',
                                title=f'Critical Memory Pressure ({m.percent:.0f}%)',
                                description=f'RAM is {m.percent:.1f}% full ({avail:.1f} GB free of {total:.1f} GB). System may be unstable.',
                                severity=Severity.CRITICAL, category=ScanCategory.PERFORMANCE,
                                details={'percent': m.percent, 'avail_gb': round(avail, 2)}))
            elif m.percent > 80:
                self._add(Issue(id='memory_high',
                                title=f'High Memory Usage ({m.percent:.0f}%)',
                                description=f'RAM at {m.percent:.1f}%. Consider closing unused applications.',
                                severity=Severity.WARNING, category=ScanCategory.PERFORMANCE,
                                details={'percent': m.percent}))
        except Exception:
            pass

    def _check_cpu(self):
        if not PSUTIL_AVAILABLE:
            return
        try:
            pct = psutil.cpu_percent(interval=0.5)
            if pct > 90:
                self._add(Issue(id='cpu_high',
                                title=f'High CPU Usage ({pct:.0f}%)',
                                description=f'CPU at {pct:.0f}%. A runaway process may be consuming resources.',
                                severity=Severity.WARNING, category=ScanCategory.PERFORMANCE,
                                details={'cpu_percent': pct}))
        except Exception:
            pass

    def _check_pagefile(self):
        if not PSUTIL_AVAILABLE:
            return
        try:
            sw = psutil.swap_memory()
            if sw.total > 0 and sw.percent > 80:
                self._add(Issue(id='pagefile_high',
                                title=f'Page File Usage High ({sw.percent:.0f}%)',
                                description='Virtual memory heavily used, indicating insufficient RAM.',
                                severity=Severity.WARNING, category=ScanCategory.PERFORMANCE,
                                details={'percent': sw.percent}))
        except Exception:
            pass

    def _check_temp_files(self):
        dirs = list({os.environ.get('TEMP', ''), os.environ.get('TMP', ''),
                     r'C:\Windows\Temp'})
        total = 0
        for d in dirs:
            if not d or not os.path.isdir(d):
                continue
            try:
                for root, _, files in os.walk(d):
                    for f in files:
                        try:
                            total += os.path.getsize(os.path.join(root, f))
                        except OSError:
                            pass
            except PermissionError:
                pass
        mb = total / 1048576
        if mb >= 1024:
            self._add(Issue(id='temp_large', title=f'Large Temp Files ({mb/1024:.1f} GB)',
                            description=f'Temporary files using {mb/1024:.1f} GB. Cleaning improves performance.',
                            severity=Severity.WARNING, category=ScanCategory.PERFORMANCE,
                            fix_available=True, fix_id='fix_temp_cleanup',
                            details={'size_mb': round(mb)}))
        elif mb >= 200:
            self._add(Issue(id='temp_medium', title=f'Temp File Accumulation ({mb:.0f} MB)',
                            description=f'Temporary files using {mb:.0f} MB.',
                            severity=Severity.INFO, category=ScanCategory.PERFORMANCE,
                            fix_available=True, fix_id='fix_temp_cleanup',
                            details={'size_mb': round(mb)}))

    def _scan_hiberfil(self):
        hib = r'C:\hiberfil.sys'
        try:
            if os.path.isfile(hib):
                gb = os.path.getsize(hib) / (1024 ** 3)
                if gb > 3:
                    self._add(Issue(id='hiberfil_large',
                                    title=f'Large Hibernate File ({gb:.1f} GB)',
                                    description=f'hiberfil.sys is {gb:.1f} GB. Disabling hibernate reclaims this space.',
                                    severity=Severity.INFO, category=ScanCategory.PERFORMANCE,
                                    fix_available=True, fix_id='fix_disable_hibernate',
                                    details={'size_gb': round(gb, 2)}))
        except (PermissionError, OSError):
            pass

    # ------------------------------------------------------------------
    # Scan: Network
    # ------------------------------------------------------------------

    def _scan_network(self):
        self._check_internet()
        self._check_dns()
        self._check_adapters()

    def _check_internet(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect(('8.8.8.8', 53))
            s.close()
        except OSError:
            self._add(Issue(id='net_no_internet', title='No Internet Connectivity',
                            description='Cannot reach the internet. Check cable, Wi-Fi, or router.',
                            severity=Severity.CRITICAL, category=ScanCategory.NETWORK,
                            fix_available=True, fix_id='fix_network_reset'))

    def _check_dns(self):
        try:
            socket.gethostbyname('www.google.com')
        except socket.gaierror:
            self._add(Issue(id='net_dns_fail', title='DNS Resolution Failing',
                            description='Cannot resolve domain names. DNS is not working.',
                            severity=Severity.CRITICAL, category=ScanCategory.NETWORK,
                            fix_available=True, fix_id='fix_flush_dns'))
        except Exception:
            pass

    def _check_adapters(self):
        try:
            r = subprocess.run(['netsh', 'interface', 'show', 'interface'],
                               capture_output=True, text=True, timeout=10,
                               creationflags=_NO_WIN)
            for line in r.stdout.splitlines():
                if 'Disconnected' in line and 'Loopback' not in line:
                    parts = line.split()
                    name = ' '.join(parts[3:]) if len(parts) >= 4 else line
                    self._add(Issue(
                        id=f'adapter_{name.replace(" ", "_")[:30]}',
                        title=f'Adapter Disconnected: {name}',
                        description=f"Network adapter '{name}' is disconnected or disabled.",
                        severity=Severity.WARNING, category=ScanCategory.NETWORK,
                        details={'adapter': name}))
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Scan: Time sync
    # ------------------------------------------------------------------

    def _scan_time_sync(self):
        try:
            r = subprocess.run(['w32tm', '/query', '/status'],
                               capture_output=True, text=True, timeout=10,
                               creationflags=_NO_WIN)
            out = r.stdout + r.stderr
            if r.returncode != 0 or 'error' in out.lower() or 'not running' in out.lower():
                self._add(Issue(id='time_sync_fail',
                                title='Windows Time Service Not Synchronising',
                                description='Cannot sync time with NTP server. Causes authentication and certificate failures.',
                                severity=Severity.WARNING, category=ScanCategory.NETWORK,
                                fix_available=True, fix_id='fix_sync_time'))
                return
            # Check age of last sync
            for line in r.stdout.splitlines():
                if 'last successful sync' in line.lower():
                    parts = line.split(':', 1)
                    if len(parts) > 1:
                        sync_str = parts[1].strip()
                        for fmt in ('%m/%d/%Y %I:%M:%S %p', '%d/%m/%Y %H:%M:%S',
                                    '%Y-%m-%dT%H:%M:%S'):
                            try:
                                sync_t = datetime.datetime.strptime(sync_str, fmt)
                                days = (datetime.datetime.now() - sync_t).days
                                if days > 7:
                                    self._add(Issue(
                                        id='time_sync_stale',
                                        title=f'Time Not Synced Recently ({days} days ago)',
                                        description='Stale time sync can cause security and certificate errors.',
                                        severity=Severity.WARNING, category=ScanCategory.NETWORK,
                                        fix_available=True, fix_id='fix_sync_time'))
                                break
                            except ValueError:
                                pass
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Scan: Services
    # ------------------------------------------------------------------

    def _scan_services(self):
        for svc, label in CRITICAL_SERVICES:
            try:
                r = subprocess.run(['sc', 'query', svc], capture_output=True, text=True,
                                   timeout=6, creationflags=_NO_WIN)
                if 'STOPPED' in r.stdout:
                    cfg = subprocess.run(['sc', 'qc', svc], capture_output=True,
                                         text=True, timeout=6, creationflags=_NO_WIN)
                    if 'AUTO_START' in cfg.stdout:
                        self._add(Issue(
                            id=f'svc_{svc}',
                            title=f'Auto-Start Service Stopped: {label}',
                            description=f"'{label}' ({svc}) is stopped but configured to auto-start.",
                            severity=Severity.CRITICAL, category=ScanCategory.SERVICES,
                            fix_available=True, fix_id=f'fix_start_service_{svc}',
                            details={'service': svc, 'label': label}))
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Scan: System
    # ------------------------------------------------------------------

    def _scan_system(self):
        self._check_windows_update()
        self._check_defender()
        self._check_sfc_log()

    def _check_windows_update(self):
        if not WINREG_AVAILABLE:
            return
        try:
            k = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r'SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install')
            val, _ = winreg.QueryValueEx(k, 'LastSuccessTime')
            winreg.CloseKey(k)
            if val:
                last  = datetime.datetime.strptime(str(val)[:10], '%Y-%m-%d')
                days  = (datetime.datetime.now() - last).days
                if days > 60:
                    self._add(Issue(
                        id='wu_overdue',
                        title=f'Windows Updates Overdue ({days} days)',
                        description=f'Last update was {days} days ago. Missing security patches.',
                        severity=Severity.CRITICAL if days > 90 else Severity.WARNING,
                        category=ScanCategory.SYSTEM, fix_available=True,
                        fix_id='fix_windows_update',
                        details={'days_since': days}))
        except (OSError, ValueError, AttributeError):
            pass

    def _check_defender(self):
        try:
            r = subprocess.run(
                ['powershell', '-NoProfile', '-Command',
                 '(Get-MpComputerStatus).RealTimeProtectionEnabled'],
                capture_output=True, text=True, timeout=10, creationflags=_NO_WIN)
            if r.returncode == 0 and 'False' in r.stdout:
                self._add(Issue(id='defender_off',
                                title='Windows Defender Real-Time Protection Disabled',
                                description='Real-time antivirus is off. System is at risk from malware.',
                                severity=Severity.CRITICAL, category=ScanCategory.SYSTEM,
                                fix_available=True, fix_id='fix_enable_defender'))
        except Exception:
            pass

    def _check_sfc_log(self):
        cbs = r'C:\Windows\Logs\CBS\CBS.log'
        if not os.path.isfile(cbs):
            return
        try:
            with open(cbs, 'r', encoding='utf-8', errors='ignore') as f:
                f.seek(0, 2)
                size = f.tell()
                f.seek(max(0, size - 40000))
                tail = f.read()
            if 'found corrupt files' in tail.lower():
                self._add(Issue(id='sfc_corrupt',
                                title='System File Corruption Detected (CBS log)',
                                description='Windows found corrupt system files. Run SFC and DISM to repair.',
                                severity=Severity.CRITICAL, category=ScanCategory.SYSTEM,
                                fix_available=True, fix_id='fix_sfc_dism'))
        except (PermissionError, OSError):
            pass

    # ------------------------------------------------------------------
    # Scan: WMI repository
    # ------------------------------------------------------------------

    def _scan_wmi(self):
        try:
            r = subprocess.run(['winmgmt', '/verifyrepository'],
                               capture_output=True, text=True, timeout=15,
                               creationflags=_NO_WIN)
            if 'inconsistent' in r.stdout.lower() or r.returncode != 0:
                self._add(Issue(id='wmi_corrupt',
                                title='WMI Repository May Be Corrupt',
                                description='WMI is inconsistent. This breaks many system management tools.',
                                severity=Severity.CRITICAL, category=ScanCategory.SYSTEM,
                                fix_available=True, fix_id='fix_rebuild_wmi'))
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Scan: Reliability
    # ------------------------------------------------------------------

    def _scan_crash_dumps(self):
        minidump = r'C:\Windows\Minidump'
        dumps    = []
        if os.path.isdir(minidump):
            dumps = glob_mod.glob(os.path.join(minidump, '*.dmp'))
        if os.path.isfile(r'C:\Windows\MEMORY.DMP'):
            dumps.append(r'C:\Windows\MEMORY.DMP')
        if not dumps:
            return

        recent = sorted(dumps, key=lambda p: os.path.getmtime(p) if os.path.exists(p) else 0,
                        reverse=True)[:5]
        dates  = []
        for d in recent:
            try:
                dates.append(datetime.datetime.fromtimestamp(
                    os.path.getmtime(d)).strftime('%Y-%m-%d'))
            except Exception:
                pass

        sev = Severity.CRITICAL if len(dumps) >= 3 else Severity.WARNING
        self._add(Issue(
            id='crash_dumps',
            title=f'Crash Dump Files Found ({len(dumps)} files)',
            description=(f'Found {len(dumps)} BSOD crash dump(s). Most recent: {", ".join(dates[:3])}. '
                         'Run SFC/DISM and check hardware.'),
            severity=sev, category=ScanCategory.RELIABILITY,
            fix_available=True, fix_id='fix_clear_minidumps',
            details={'count': len(dumps), 'dates': dates}))

    def _scan_reliability_misc(self):
        self._check_pending_reboot()
        self._check_system_restore()

    def _check_pending_reboot(self):
        if not WINREG_AVAILABLE:
            return
        checks = [
            (winreg.HKEY_LOCAL_MACHINE,
             r'SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing',
             'RebootPending'),
            (winreg.HKEY_LOCAL_MACHINE,
             r'SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update',
             'RebootRequired'),
        ]
        for hive, path, val_name in checks:
            try:
                k = winreg.OpenKey(hive, path)
                val, _ = winreg.QueryValueEx(k, val_name)
                winreg.CloseKey(k)
                if val:
                    self._add(Issue(
                        id='pending_reboot',
                        title='Restart Required to Complete Updates',
                        description='Windows has pending changes that require a restart.',
                        severity=Severity.WARNING, category=ScanCategory.RELIABILITY,
                        details={'source': path}))
                    return
            except (OSError, AttributeError):
                pass
        # Also check PendingFileRenameOperations
        try:
            k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                               r'SYSTEM\CurrentControlSet\Control\Session Manager')
            val, _ = winreg.QueryValueEx(k, 'PendingFileRenameOperations')
            winreg.CloseKey(k)
            if val:
                self._add(Issue(
                    id='pending_reboot_file',
                    title='Pending File Operations Require Restart',
                    description='File rename operations are pending restart.',
                    severity=Severity.INFO, category=ScanCategory.RELIABILITY))
        except (OSError, AttributeError):
            pass

    def _check_system_restore(self):
        try:
            r = subprocess.run(['vssadmin', 'list', 'shadowstorage'],
                               capture_output=True, text=True, timeout=10,
                               creationflags=_NO_WIN)
            if 'no items found' in r.stdout.lower() or r.returncode != 0:
                self._add(Issue(
                    id='no_restore_points',
                    title='No System Restore Points Available',
                    description='No restore points exist. Cannot roll back if something goes wrong.',
                    severity=Severity.WARNING, category=ScanCategory.RELIABILITY,
                    fix_available=True, fix_id='fix_enable_system_restore'))
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Scan: Security
    # ------------------------------------------------------------------

    def _scan_uac_firewall(self):
        # UAC
        if WINREG_AVAILABLE:
            try:
                k = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System')
                val, _ = winreg.QueryValueEx(k, 'EnableLUA')
                winreg.CloseKey(k)
                if val == 0:
                    self._add(Issue(id='uac_disabled',
                                    title='UAC (User Account Control) is Disabled',
                                    description='UAC is off. Malware can silently gain admin rights.',
                                    severity=Severity.CRITICAL, category=ScanCategory.SECURITY,
                                    fix_available=True, fix_id='fix_enable_uac'))
            except (OSError, AttributeError):
                pass

        # Firewall
        try:
            r = subprocess.run(['netsh', 'advfirewall', 'show', 'allprofiles', 'state'],
                               capture_output=True, text=True, timeout=10,
                               creationflags=_NO_WIN)
            off = []
            cur = None
            for line in r.stdout.splitlines():
                line = line.strip()
                if 'Profile Settings' in line:
                    cur = line.split()[0]
                elif cur and 'State' in line and 'OFF' in line.upper():
                    off.append(cur)
            if off:
                self._add(Issue(id='firewall_disabled',
                                title=f'Windows Firewall Disabled ({", ".join(off)})',
                                description=f'Firewall is off for: {", ".join(off)}. System exposed to network attacks.',
                                severity=Severity.CRITICAL, category=ScanCategory.SECURITY,
                                fix_available=True, fix_id='fix_enable_firewall',
                                details={'profiles': off}))
        except Exception:
            pass

        # BitLocker status (info only)
        try:
            r = subprocess.run(['manage-bde', '-status', 'C:'],
                               capture_output=True, text=True, timeout=10,
                               creationflags=_NO_WIN)
            if 'fully decrypted' in r.stdout.lower():
                self._add(Issue(id='bitlocker_off',
                                title='Drive C: Not Encrypted (BitLocker Off)',
                                description='BitLocker encryption is not enabled on the system drive. Physical theft can expose all data.',
                                severity=Severity.INFO, category=ScanCategory.SECURITY))
        except Exception:
            pass

    def _scan_user_accounts(self):
        # Guest account
        try:
            r = subprocess.run(['net', 'user', 'Guest'],
                               capture_output=True, text=True, timeout=10,
                               creationflags=_NO_WIN)
            if 'Account active' in r.stdout and 'Yes' in r.stdout:
                self._add(Issue(id='guest_enabled',
                                title='Guest Account is Enabled',
                                description='The Guest account is enabled. Anyone can log in with limited access.',
                                severity=Severity.WARNING, category=ScanCategory.SECURITY))
        except Exception:
            pass

        # Multiple admins
        try:
            r = subprocess.run(['net', 'localgroup', 'Administrators'],
                               capture_output=True, text=True, timeout=10,
                               creationflags=_NO_WIN)
            members = []
            in_m = False
            for line in r.stdout.splitlines():
                line = line.strip()
                if '---' in line:
                    in_m = True
                    continue
                if in_m and line and 'The command' not in line:
                    members.append(line)
            if len(members) > 3:
                self._add(Issue(
                    id='many_admins',
                    title=f'Many Administrator Accounts ({len(members)})',
                    description=f'{len(members)} accounts have Administrator rights. Each is a potential attack vector.',
                    severity=Severity.INFO, category=ScanCategory.SECURITY,
                    details={'count': len(members), 'members': members[:5]}))
        except Exception:
            pass

        # AutoAdminLogon (auto-login stored credentials)
        if WINREG_AVAILABLE:
            try:
                k = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon')
                val, _ = winreg.QueryValueEx(k, 'AutoAdminLogon')
                winreg.CloseKey(k)
                if str(val) == '1':
                    self._add(Issue(id='autologon',
                                    title='Automatic Login is Enabled',
                                    description='Windows logs in automatically without a password. Anyone with physical access can access the system.',
                                    severity=Severity.WARNING, category=ScanCategory.SECURITY))
            except (OSError, AttributeError):
                pass

    # ------------------------------------------------------------------
    # Scan: Drivers / Device Manager
    # ------------------------------------------------------------------

    def _scan_device_manager(self):
        try:
            r = subprocess.run(
                ['wmic', 'path', 'win32_pnpentity', 'where',
                 'ConfigManagerErrorCode!=0',
                 'get', 'Name,ConfigManagerErrorCode', '/format:csv'],
                capture_output=True, text=True, timeout=20, creationflags=_NO_WIN)

            found = []
            for line in r.stdout.strip().splitlines()[1:]:
                parts = line.split(',')
                if len(parts) >= 3:
                    try:
                        code = int(parts[-1].strip())
                        name = ','.join(parts[1:-1]).strip()
                        if name and code != 0 and code != 22:
                            found.append((name, code))
                    except ValueError:
                        pass

            for name, code in found[:8]:
                msg  = DEVICE_ERRORS.get(code, f'Error code {code}')
                sev  = Severity.CRITICAL if code in (1, 3, 10, 28, 43, 52) else Severity.WARNING
                self._add(Issue(
                    id=f'dev_{name.replace(" ", "_")[:30]}_{code}',
                    title=f'Device Error: {name[:60]}',
                    description=f'Device Manager error {code}: {msg}',
                    severity=sev, category=ScanCategory.DRIVERS,
                    fix_available=True, fix_id='fix_open_device_manager',
                    details={'device': name, 'error_code': code}))
        except Exception:
            pass

        # Check for driver verifier stops in event log
        try:
            r = subprocess.run(
                ['wevtutil', 'qe', 'System', '/c:5', '/f:xml', '/rd:true',
                 '/q:*[System[EventID=1003]]'],
                capture_output=True, text=True, timeout=10, creationflags=_NO_WIN)
            if r.stdout.strip():
                events = self._parse_wevtutil(r.stdout)
                if events:
                    self._add(Issue(
                        id='driver_verifier',
                        title=f'Driver Verifier Stops Detected ({len(events)})',
                        description='Driver Verifier has caught faulty driver behavior, causing system crashes.',
                        severity=Severity.CRITICAL, category=ScanCategory.DRIVERS,
                        fix_available=True, fix_id='fix_open_device_manager'))
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Scan: Startup programs
    # ------------------------------------------------------------------

    def _scan_startup_programs(self):
        if not WINREG_AVAILABLE:
            return
        run_keys = [
            (winreg.HKEY_CURRENT_USER,
             r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run'),
            (winreg.HKEY_LOCAL_MACHINE,
             r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run'),
            (winreg.HKEY_LOCAL_MACHINE,
             r'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'),
        ]
        startup_dirs = [
            os.path.join(os.environ.get('APPDATA', ''),
                         r'Microsoft\Windows\Start Menu\Programs\Startup'),
            r'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp',
        ]
        programs = []
        for hive, path in run_keys:
            try:
                k = winreg.OpenKey(hive, path)
                i = 0
                while True:
                    try:
                        name, _, _ = winreg.EnumValue(k, i)
                        programs.append(name)
                        i += 1
                    except OSError:
                        break
                winreg.CloseKey(k)
            except (OSError, AttributeError):
                pass
        for d in startup_dirs:
            if os.path.isdir(d):
                programs += [f for f in os.listdir(d) if not f.startswith('.')]

        n = len(programs)
        if n > 20:
            self._add(Issue(id='startup_excessive',
                            title=f'Excessive Startup Programs ({n})',
                            description=f'{n} programs launch at startup. Significantly increases boot time.',
                            severity=Severity.WARNING, category=ScanCategory.STARTUP,
                            fix_available=True, fix_id='fix_open_startup',
                            details={'count': n}))
        elif n > 12:
            self._add(Issue(id='startup_many',
                            title=f'Many Startup Programs ({n})',
                            description=f'{n} programs start with Windows. Consider disabling unused ones.',
                            severity=Severity.INFO, category=ScanCategory.STARTUP,
                            fix_available=True, fix_id='fix_open_startup',
                            details={'count': n}))

        # Check for RunOnce entries (may indicate pending installs/reboots)
        try:
            k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                               r'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce')
            count = 0
            i = 0
            while True:
                try:
                    winreg.EnumValue(k, i)
                    count += 1
                    i += 1
                except OSError:
                    break
            winreg.CloseKey(k)
            if count > 0:
                self._add(Issue(id='runonce_entries',
                                title=f'Pending RunOnce Actions ({count})',
                                description=f'{count} RunOnce entries found. A restart may be needed.',
                                severity=Severity.INFO, category=ScanCategory.STARTUP,
                                details={'count': count}))
        except (OSError, AttributeError):
            pass

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def health_score(self) -> int:
        score = 100
        for i in self.issues:
            if i.severity == Severity.CRITICAL:
                score -= 15
            elif i.severity == Severity.WARNING:
                score -= 5
            else:
                score -= 1
        return max(0, score)

    def summary(self) -> Dict:
        crit = sum(1 for i in self.issues if i.severity == Severity.CRITICAL)
        warn = sum(1 for i in self.issues if i.severity == Severity.WARNING)
        info = sum(1 for i in self.issues if i.severity == Severity.INFO)
        return {
            'total':        len(self.issues),
            'critical':     crit,
            'warnings':     warn,
            'info':         info,
            'health_score': self.health_score(),
            'fixable':      sum(1 for i in self.issues if i.fix_available),
        }
