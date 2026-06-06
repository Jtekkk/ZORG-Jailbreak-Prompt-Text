"""
WinDiag Pro - Diagnostic Scanner
Scans Windows event logs, hardware, performance, network, and services.
"""

import subprocess
import xml.etree.ElementTree as ET
import datetime
import os
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

_EVTNS = 'http://schemas.microsoft.com/win/2004/08/events/event'
_NO_WINDOW = getattr(subprocess, 'CREATE_NO_WINDOW', 0)

# Known critical event IDs: (provider_hint, human_readable_title)
CRITICAL_EVENT_IDS: Dict[str, Tuple[str, str]] = {
    '41':   ('Kernel-Power',               'System crashed or lost power unexpectedly'),
    '6008': ('EventLog',                   'Previous system shutdown was unexpected'),
    '1001': ('BugCheck',                   'Blue Screen of Death (system crash)'),
    '55':   ('Ntfs',                       'NTFS file system structure on disk is corrupt'),
    '7023': ('Service Control Manager',    'Critical service terminated with an error'),
    '7024': ('Service Control Manager',    'Service terminated with a service-specific error'),
    '7026': ('Service Control Manager',    'Boot-start or system-start driver failed to load'),
    '7034': ('Service Control Manager',    'Service terminated unexpectedly'),
}

WARNING_EVENT_IDS: Dict[str, Tuple[str, str]] = {
    '51':   ('disk',                       'Disk paging error detected on a device'),
    '11':   ('disk',                       'Controller error detected on a disk device'),
    '129':  ('StorPort',                   'A reset was issued to the disk device'),
    '219':  ('',                           'A driver package failed to load'),
    '7031': ('Service Control Manager',    'Service crashed and was restarted'),
    '7036': ('Service Control Manager',    'Service changed state unexpectedly'),
    '7040': ('Service Control Manager',    'Service start type was changed'),
    '1000': ('Application Error',          'Application crashed (unhandled exception)'),
    '1002': ('Application Hang',           'Application stopped responding'),
    '1026': ('.NET Runtime',               '.NET runtime error occurred'),
}

CRITICAL_SERVICES = [
    ('wuauserv',           'Windows Update'),
    ('WinDefend',          'Windows Defender Antivirus'),
    ('EventLog',           'Windows Event Log'),
    ('Dnscache',           'DNS Client'),
    ('DHCP',               'DHCP Client'),
    ('RpcSs',              'Remote Procedure Call (RPC)'),
    ('Schedule',           'Task Scheduler'),
    ('LanmanWorkstation',  'Workstation'),
]


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
            (ScanCategory.EVENT_LOG,   'Scanning event logs…',      self._scan_event_logs),
            (ScanCategory.HARDWARE,    'Checking hardware…',         self._scan_hardware),
            (ScanCategory.PERFORMANCE, 'Checking performance…',      self._scan_performance),
            (ScanCategory.NETWORK,     'Checking network…',          self._scan_network),
            (ScanCategory.SERVICES,    'Checking services…',         self._scan_services),
            (ScanCategory.SYSTEM,      'Checking system health…',    self._scan_system),
        ]

        active = [(cat, msg, fn) for (cat, msg, fn) in steps if cat in enabled]
        total  = len(active)

        for idx, (_, msg, fn) in enumerate(active):
            self._progress(msg, idx / max(total, 1) * 100)
            try:
                fn()
            except Exception:
                pass

        self._progress('Scan complete', 100.0)
        return self.issues

    # ------------------------------------------------------------------
    # Event Log Scanning
    # ------------------------------------------------------------------

    def _scan_event_logs(self):
        days_back  = int(self.settings.get('days_back', 7))
        hours_back = days_back * 24
        log_names  = self.settings.get('log_names', ['System', 'Application'])
        for log in log_names:
            events = self._query_log(log, hours_back)
            self._analyze_events(events, log)

    def _query_log(self, log_name: str, hours_back: int, max_events: int = 300) -> List[Dict]:
        start = datetime.datetime.utcnow() - datetime.timedelta(hours=hours_back)
        start_str = start.strftime('%Y-%m-%dT%H:%M:%S')
        query = f"*[System[(Level<=3) and TimeCreated[@SystemTime>='{start_str}']]]"

        cmd = [
            'wevtutil', 'qe', log_name,
            f'/c:{max_events}', '/f:xml', '/rd:true', f'/q:{query}',
        ]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=30, creationflags=_NO_WINDOW)
            return self._parse_wevtutil(r.stdout)
        except Exception:
            return []

    def _parse_wevtutil(self, output: str) -> List[Dict]:
        if not output.strip():
            return []
        try:
            root = ET.fromstring(f'<R>{output}</R>')
            return [e for e in (self._parse_event_el(el) for el in root) if e]
        except ET.ParseError:
            events = []
            for chunk in output.split('</Event>'):
                chunk = chunk.strip()
                if not chunk:
                    continue
                try:
                    el = ET.fromstring(chunk + '</Event>')
                    ev = self._parse_event_el(el)
                    if ev:
                        events.append(ev)
                except ET.ParseError:
                    continue
            return events

    def _parse_event_el(self, el) -> Optional[Dict]:
        try:
            ns  = _EVTNS
            sys = el.find(f'{{{ns}}}System')
            if sys is None:
                return None

            def txt(tag):
                node = sys.find(f'{{{ns}}}{tag}')
                return node.text if node is not None else ''

            def attr(tag, key):
                node = sys.find(f'{{{ns}}}{tag}')
                return node.get(key, '') if node is not None else ''

            level_str = txt('Level')
            level = int(level_str) if level_str.isdigit() else 4
            if level > 3:
                return None

            ts = None
            ts_str = attr('TimeCreated', 'SystemTime')
            if ts_str:
                for fmt in ('%Y-%m-%dT%H:%M:%S.%f%z', '%Y-%m-%dT%H:%M:%S%z',
                            '%Y-%m-%dT%H:%M:%S'):
                    try:
                        ts = datetime.datetime.strptime(ts_str[:26], fmt[:len(ts_str)])
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
        seen: Dict[str, int] = {}

        for ev in events:
            eid      = ev.get('event_id', '')
            level    = ev.get('level', 4)
            provider = ev.get('provider', '')
            ts       = ev.get('timestamp')
            data     = ev.get('data', [])

            detail_str = '; '.join(data[:3]) if data else ''

            if eid in CRITICAL_EVENT_IDS:
                prov_hint, desc = CRITICAL_EVENT_IDS[eid]
                sev = Severity.CRITICAL
                fix_id = {
                    '41':   'fix_check_disk',
                    '55':   'fix_check_disk',
                    '1001': None,
                    '7023': 'fix_sfc_dism',
                    '7024': 'fix_sfc_dism',
                    '7026': 'fix_sfc_dism',
                    '7034': None,
                }.get(eid)
                fix_avail = fix_id is not None

            elif eid in WARNING_EVENT_IDS:
                prov_hint, desc = WARNING_EVENT_IDS[eid]
                sev = Severity.WARNING
                fix_id    = 'fix_sfc_dism' if eid in ('55', '51') else None
                fix_avail = fix_id is not None

            elif level == 1:
                desc      = f'Critical error from {provider or "unknown"}'
                sev       = Severity.CRITICAL
                fix_id    = None
                fix_avail = False

            else:
                continue

            key   = f'{log_name}_{eid}'
            count = seen.get(key, 0)
            seen[key] = count + 1

            if count >= 3:
                continue

            extra = f'\nDetails: {detail_str}' if detail_str else ''
            self._add(Issue(
                id=f'evt_{log_name}_{eid}_{count}',
                title=f'[{log_name}] Event {eid}: {desc[:80]}',
                description=f'{desc}{extra}',
                severity=sev,
                category=ScanCategory.EVENT_LOG,
                fix_available=fix_avail,
                fix_id=fix_id,
                timestamp=ts,
                details={'event_id': eid, 'log': log_name, 'provider': provider,
                         'occurrences': seen[key]},
            ))

    # ------------------------------------------------------------------
    # Hardware Scanning
    # ------------------------------------------------------------------

    def _scan_hardware(self):
        self._check_disk_space()
        self._check_battery()

    def _check_disk_space(self):
        if PSUTIL_AVAILABLE:
            try:
                for part in psutil.disk_partitions():
                    if 'cdrom' in part.opts or not part.fstype:
                        continue
                    try:
                        u = psutil.disk_usage(part.mountpoint)
                        self._emit_disk_issue(part.device, u.percent,
                                              u.free / 1073741824, u.total / 1073741824)
                    except PermissionError:
                        pass
                return
            except Exception:
                pass

        # Fallback via wmic
        try:
            r = subprocess.run(
                ['wmic', 'logicaldisk', 'get', 'DeviceID,FreeSpace,Size'],
                capture_output=True, text=True, timeout=15, creationflags=_NO_WINDOW)
            for line in r.stdout.strip().splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 3:
                    try:
                        free_b  = int(parts[1])
                        total_b = int(parts[2])
                        if total_b:
                            pct = (total_b - free_b) / total_b * 100
                            self._emit_disk_issue(parts[0], pct,
                                                  free_b / 1073741824, total_b / 1073741824)
                    except (ValueError, ZeroDivisionError):
                        pass
        except Exception:
            pass

    def _emit_disk_issue(self, device: str, pct: float, free_gb: float, total_gb: float):
        if pct > 95:
            sev = Severity.CRITICAL
            title = f'Drive {device} Critically Full ({pct:.0f}%)'
            desc  = (f'Drive {device} is {pct:.1f}% full ({free_gb:.1f} GB free of '
                     f'{total_gb:.1f} GB). Windows may become unstable.')
        elif pct > 85:
            sev = Severity.WARNING
            title = f'Drive {device} Running Low ({pct:.0f}%)'
            desc  = (f'Drive {device} is {pct:.1f}% full ({free_gb:.1f} GB free). '
                     f'Consider freeing up space.')
        else:
            return

        self._add(Issue(
            id=f'disk_{device.replace(":", "")}',
            title=title,
            description=desc,
            severity=sev,
            category=ScanCategory.HARDWARE,
            fix_available=True,
            fix_id='fix_disk_cleanup',
            details={'device': device, 'percent': pct, 'free_gb': round(free_gb, 2)},
        ))

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
                                description='Battery is almost empty. Connect power immediately.',
                                severity=Severity.CRITICAL,
                                category=ScanCategory.HARDWARE,
                                details={'percent': bat.percent}))
            elif bat.percent < 20:
                self._add(Issue(id='battery_low',
                                title=f'Battery Low ({bat.percent:.0f}%)',
                                description='Battery is below 20%. Consider plugging in.',
                                severity=Severity.WARNING,
                                category=ScanCategory.HARDWARE,
                                details={'percent': bat.percent}))
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Performance Scanning
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
            avail_gb = m.available / 1073741824
            total_gb = m.total / 1073741824
            if m.percent > 90:
                self._add(Issue(id='memory_critical',
                                title=f'Critical Memory Pressure ({m.percent:.0f}% used)',
                                description=(f'RAM is {m.percent:.1f}% full '
                                             f'({avail_gb:.1f} GB available of {total_gb:.1f} GB). '
                                             'System may be unstable or very slow.'),
                                severity=Severity.CRITICAL,
                                category=ScanCategory.PERFORMANCE,
                                details={'percent': m.percent, 'available_gb': round(avail_gb, 2)}))
            elif m.percent > 80:
                self._add(Issue(id='memory_high',
                                title=f'High Memory Usage ({m.percent:.0f}% used)',
                                description=(f'RAM is {m.percent:.1f}% used. '
                                             'Consider closing unused applications.'),
                                severity=Severity.WARNING,
                                category=ScanCategory.PERFORMANCE,
                                details={'percent': m.percent, 'available_gb': round(avail_gb, 2)}))
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
                                description=(f'CPU usage is {pct:.0f}%. '
                                             'A runaway process may be consuming resources.'),
                                severity=Severity.WARNING,
                                category=ScanCategory.PERFORMANCE,
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
                                description=('Virtual memory (page file) usage is very high, '
                                             'indicating insufficient physical RAM.'),
                                severity=Severity.WARNING,
                                category=ScanCategory.PERFORMANCE,
                                details={'percent': sw.percent}))
        except Exception:
            pass

    def _check_temp_files(self):
        temp_dirs = list({
            os.environ.get('TEMP', ''),
            os.environ.get('TMP', ''),
            r'C:\Windows\Temp',
        })

        total = 0
        for d in temp_dirs:
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
        gb = mb / 1024

        if gb >= 1:
            self._add(Issue(id='temp_large',
                            title=f'Large Temp Files ({gb:.1f} GB)',
                            description=f'Temporary files are consuming {gb:.1f} GB. Cleaning them can free space and improve performance.',
                            severity=Severity.WARNING,
                            category=ScanCategory.PERFORMANCE,
                            fix_available=True, fix_id='fix_temp_cleanup',
                            details={'size_mb': round(mb)}))
        elif mb >= 200:
            self._add(Issue(id='temp_medium',
                            title=f'Temp File Accumulation ({mb:.0f} MB)',
                            description=f'Temporary files are using {mb:.0f} MB. Consider cleaning them.',
                            severity=Severity.INFO,
                            category=ScanCategory.PERFORMANCE,
                            fix_available=True, fix_id='fix_temp_cleanup',
                            details={'size_mb': round(mb)}))

    # ------------------------------------------------------------------
    # Network Scanning
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
            self._add(Issue(id='net_no_internet',
                            title='No Internet Connectivity',
                            description='Cannot reach the internet. Check your network cable, Wi-Fi, or router.',
                            severity=Severity.CRITICAL,
                            category=ScanCategory.NETWORK,
                            fix_available=True, fix_id='fix_network_reset'))

    def _check_dns(self):
        try:
            socket.gethostbyname('www.google.com')
        except socket.gaierror:
            self._add(Issue(id='net_dns_fail',
                            title='DNS Resolution Failing',
                            description='Cannot resolve domain names to IP addresses. DNS is not working.',
                            severity=Severity.CRITICAL,
                            category=ScanCategory.NETWORK,
                            fix_available=True, fix_id='fix_flush_dns'))
        except Exception:
            pass

    def _check_adapters(self):
        try:
            r = subprocess.run(['netsh', 'interface', 'show', 'interface'],
                               capture_output=True, text=True, timeout=10,
                               creationflags=_NO_WINDOW)
            for line in r.stdout.splitlines():
                if 'Disconnected' in line and 'Loopback' not in line:
                    name = ' '.join(line.split()[3:]) if len(line.split()) >= 4 else line
                    self._add(Issue(
                        id=f'adapter_disc_{name.replace(" ", "_")[:30]}',
                        title=f'Network Adapter Disconnected: {name}',
                        description=f"Adapter '{name}' shows as disconnected or disabled.",
                        severity=Severity.WARNING,
                        category=ScanCategory.NETWORK,
                        details={'adapter': name}))
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Services Scanning
    # ------------------------------------------------------------------

    def _scan_services(self):
        for svc_name, svc_label in CRITICAL_SERVICES:
            try:
                r = subprocess.run(['sc', 'query', svc_name],
                                   capture_output=True, text=True, timeout=6,
                                   creationflags=_NO_WINDOW)
                if 'STOPPED' in r.stdout:
                    cfg = subprocess.run(['sc', 'qc', svc_name],
                                         capture_output=True, text=True, timeout=6,
                                         creationflags=_NO_WINDOW)
                    if 'AUTO_START' in cfg.stdout:
                        self._add(Issue(
                            id=f'svc_stopped_{svc_name}',
                            title=f'Auto-Start Service Stopped: {svc_label}',
                            description=(f"'{svc_label}' ({svc_name}) is stopped but configured to "
                                         "start automatically. This may cause system problems."),
                            severity=Severity.CRITICAL,
                            category=ScanCategory.SERVICES,
                            fix_available=True,
                            fix_id=f'fix_start_service_{svc_name}',
                            details={'service': svc_name, 'label': svc_label}))
            except Exception:
                pass

    # ------------------------------------------------------------------
    # System Scanning
    # ------------------------------------------------------------------

    def _scan_system(self):
        self._check_windows_update()
        self._check_defender()
        self._check_sfc_log()

    def _check_windows_update(self):
        if not WINREG_AVAILABLE:
            return
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r'SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install')
            val, _ = winreg.QueryValueEx(key, 'LastSuccessTime')
            winreg.CloseKey(key)
            if val:
                last = datetime.datetime.strptime(str(val)[:10], '%Y-%m-%d')
                days = (datetime.datetime.now() - last).days
                if days > 60:
                    sev  = Severity.CRITICAL if days > 90 else Severity.WARNING
                    self._add(Issue(
                        id='wu_overdue',
                        title=f'Windows Updates Overdue ({days} days)',
                        description=(f'Last successful update was {days} days ago. '
                                     'Missing security patches may leave the system vulnerable.'),
                        severity=sev,
                        category=ScanCategory.SYSTEM,
                        fix_available=True, fix_id='fix_windows_update',
                        details={'days_since': days, 'last_update': str(val)}))
        except (OSError, ValueError, AttributeError):
            pass

    def _check_defender(self):
        try:
            r = subprocess.run(
                ['powershell', '-NoProfile', '-Command',
                 '(Get-MpComputerStatus).RealTimeProtectionEnabled'],
                capture_output=True, text=True, timeout=10, creationflags=_NO_WINDOW)
            if r.returncode == 0 and 'False' in r.stdout:
                self._add(Issue(
                    id='defender_off',
                    title='Windows Defender Real-Time Protection Disabled',
                    description='Real-time antivirus protection is off. The system is at risk from malware.',
                    severity=Severity.CRITICAL,
                    category=ScanCategory.SYSTEM,
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
                self._add(Issue(
                    id='sfc_corrupt',
                    title='System File Corruption Detected (CBS log)',
                    description='Windows has found corrupt system files. Run SFC and DISM to repair them.',
                    severity=Severity.CRITICAL,
                    category=ScanCategory.SYSTEM,
                    fix_available=True, fix_id='fix_sfc_dism'))
        except (PermissionError, OSError):
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
