"""
WinDiag Pro - Diagnostic Fixer
Implements one-click fixes for common Windows issues.
"""

import subprocess
import os
import sys
import shutil
import ctypes
import datetime
from dataclasses import dataclass, field
from typing import Optional, Callable, List, Dict, Any

_NO_WINDOW = getattr(subprocess, 'CREATE_NO_WINDOW', 0)


@dataclass
class FixResult:
    success:        bool
    message:        str
    details:        str  = ''
    requires_reboot: bool = False


@dataclass
class FixMeta:
    id:              str
    name:            str
    description:     str
    requires_admin:  bool
    category:        str
    severity_hint:   str   = 'info'
    estimated_time:  str   = 'Seconds'


# -----------------------------------------------------------------------
# Admin helpers
# -----------------------------------------------------------------------

def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def request_elevation():
    """Re-launch the current process with UAC elevation."""
    try:
        ctypes.windll.shell32.ShellExecuteW(
            None, 'runas', sys.executable, ' '.join(sys.argv), None, 1)
    except Exception:
        pass


def _run(cmd: List[str], timeout: int = 120) -> tuple:
    """Return (success, stdout, stderr)."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, creationflags=_NO_WINDOW)
        return r.returncode == 0, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return False, '', 'Command timed out'
    except FileNotFoundError:
        return False, '', f'Command not found: {cmd[0]}'
    except Exception as e:
        return False, '', str(e)


# -----------------------------------------------------------------------
# Fix catalogue metadata
# -----------------------------------------------------------------------

ALL_FIXES: List[FixMeta] = [
    FixMeta('fix_temp_cleanup',   'Clean Temporary Files',
            'Delete user and system temp folders to free disk space and improve performance.',
            requires_admin=False, category='Performance', severity_hint='warning',
            estimated_time='10–30 sec'),

    FixMeta('fix_disk_cleanup',   'Run Disk Cleanup',
            'Remove junk files, delivery optimisation cache, and recycle bin contents.',
            requires_admin=False, category='Performance', severity_hint='warning',
            estimated_time='1–3 min'),

    FixMeta('fix_flush_dns',      'Flush DNS Cache',
            'Clear the DNS resolver cache to fix browser and network name-resolution issues.',
            requires_admin=False, category='Network', severity_hint='info',
            estimated_time='Instant'),

    FixMeta('fix_network_reset',  'Reset Network Stack',
            'Reset Winsock, TCP/IP, and release/renew IP address to fix network problems.',
            requires_admin=True, category='Network', severity_hint='warning',
            estimated_time='~30 sec'),

    FixMeta('fix_sfc_dism',       'Repair System Files (SFC + DISM)',
            'Run SFC /scannow to repair corrupt Windows files and DISM to restore the component store.',
            requires_admin=True, category='System', severity_hint='critical',
            estimated_time='10–30 min'),

    FixMeta('fix_dism_only',      'Repair Windows Image (DISM)',
            'Restore the Windows component store from Windows Update without touching SFC.',
            requires_admin=True, category='System', severity_hint='critical',
            estimated_time='15–30 min'),

    FixMeta('fix_windows_update', 'Open Windows Update',
            'Open Windows Update settings so you can install pending security patches.',
            requires_admin=False, category='System', severity_hint='warning',
            estimated_time='Instant'),

    FixMeta('fix_enable_defender','Enable Windows Defender',
            'Re-enable Windows Defender real-time protection via PowerShell.',
            requires_admin=True, category='Security', severity_hint='critical',
            estimated_time='Instant'),

    FixMeta('fix_check_disk',     'Schedule Check Disk (CHKDSK)',
            'Schedule CHKDSK /f /r on the C: drive to run at next reboot.',
            requires_admin=True, category='Hardware', severity_hint='critical',
            estimated_time='Next reboot'),

    FixMeta('fix_clear_prefetch', 'Clear Prefetch Cache',
            'Delete the Windows Prefetch folder to resolve app launch errors.',
            requires_admin=True, category='Performance', severity_hint='info',
            estimated_time='Instant'),

    FixMeta('fix_reset_winsock',  'Reset Winsock Only',
            'Reset just the Winsock catalogue without touching TCP/IP.',
            requires_admin=True, category='Network', severity_hint='warning',
            estimated_time='Instant'),

    FixMeta('fix_sync_time',      'Sync Windows Time (NTP)',
            'Force an immediate NTP time synchronisation and restart the Windows Time service.',
            requires_admin=True, category='Network', severity_hint='warning',
            estimated_time='Instant'),

    FixMeta('fix_enable_firewall', 'Enable Windows Firewall',
            'Turn on Windows Firewall for all profiles (Domain, Private, Public).',
            requires_admin=True, category='Security', severity_hint='critical',
            estimated_time='Instant'),

    FixMeta('fix_enable_uac',     'Enable UAC',
            'Re-enable User Account Control in the registry and prompt for restart.',
            requires_admin=True, category='Security', severity_hint='critical',
            estimated_time='Instant'),

    FixMeta('fix_enable_system_restore', 'Enable System Restore',
            'Enable Volume Shadow Copy and create an immediate restore point.',
            requires_admin=True, category='Reliability', severity_hint='warning',
            estimated_time='1–3 min'),

    FixMeta('fix_clear_minidumps', 'Clear Crash Dump Files',
            'Delete BSOD minidump files from C:\\Windows\\Minidump to free space.',
            requires_admin=True, category='Reliability', severity_hint='info',
            estimated_time='Instant'),

    FixMeta('fix_disable_hibernate', 'Disable Hibernation',
            'Run powercfg /h off to delete hiberfil.sys and reclaim disk space.',
            requires_admin=True, category='Performance', severity_hint='info',
            estimated_time='Instant'),

    FixMeta('fix_rebuild_wmi',    'Rebuild WMI Repository',
            'Stop WMI, rename the broken repository, and rebuild from scratch.',
            requires_admin=True, category='System', severity_hint='critical',
            estimated_time='2–5 min'),

    FixMeta('fix_open_device_manager', 'Open Device Manager',
            'Launch Device Manager so you can update or roll back problematic drivers.',
            requires_admin=False, category='Drivers', severity_hint='warning',
            estimated_time='Instant'),

    FixMeta('fix_open_startup',   'Open Startup Manager',
            'Open Task Manager on the Startup tab to disable unnecessary startup programs.',
            requires_admin=False, category='Startup', severity_hint='info',
            estimated_time='Instant'),

    FixMeta('fix_repair_vcredist', 'Repair Visual C++ Runtimes',
            'Open Apps & Features to find and repair Microsoft Visual C++ Redistributables.',
            requires_admin=False, category='System', severity_hint='info',
            estimated_time='Instant'),

    FixMeta('fix_reset_store',    'Reset Microsoft Store Cache',
            'Run wsreset.exe to clear the Windows Store cache and fix install failures.',
            requires_admin=False, category='System', severity_hint='info',
            estimated_time='~1 min'),
]

FIX_MAP: Dict[str, FixMeta] = {f.id: f for f in ALL_FIXES}


# -----------------------------------------------------------------------
# Main fixer class
# -----------------------------------------------------------------------

class DiagnosticFixer:
    def __init__(self, progress_cb: Optional[Callable[[str, float], None]] = None):
        self._progress_cb = progress_cb

    def _progress(self, msg: str, pct: float = -1):
        if self._progress_cb:
            self._progress_cb(msg, pct)

    # -------------------------------------------------------------------
    # Individual fixes
    # -------------------------------------------------------------------

    def fix_temp_cleanup(self) -> FixResult:
        deleted, freed = 0, 0
        dirs = list({
            os.environ.get('TEMP', ''),
            os.environ.get('TMP', ''),
            r'C:\Windows\Temp',
        })
        for d in dirs:
            if not d or not os.path.isdir(d):
                continue
            for name in os.listdir(d):
                path = os.path.join(d, name)
                try:
                    if os.path.isfile(path) or os.path.islink(path):
                        freed += os.path.getsize(path)
                        os.remove(path)
                    elif os.path.isdir(path):
                        for r, _, fs in os.walk(path):
                            for f in fs:
                                try:
                                    freed += os.path.getsize(os.path.join(r, f))
                                except OSError:
                                    pass
                        shutil.rmtree(path, ignore_errors=True)
                    deleted += 1
                except (PermissionError, OSError):
                    pass

        mb = freed / 1048576
        size = f'{mb / 1024:.1f} GB' if mb >= 1024 else f'{mb:.0f} MB'
        return FixResult(success=True, message=f'Removed {deleted} items, freed {size}')

    def fix_disk_cleanup(self) -> FixResult:
        # Run built-in cleanup flags silently
        _run(['cleanmgr', '/sagerun:1'], timeout=180)
        temp = self.fix_temp_cleanup()
        return FixResult(success=True, message='Disk cleanup complete',
                         details=temp.message)

    def fix_flush_dns(self) -> FixResult:
        ok, out, err = _run(['ipconfig', '/flushdns'], timeout=15)
        if ok or 'flushed' in out.lower():
            return FixResult(success=True, message='DNS cache flushed successfully')
        return FixResult(success=False, message='DNS flush failed', details=err or out)

    def fix_network_reset(self) -> FixResult:
        if not is_admin():
            return FixResult(success=False, message='Administrator privileges required',
                             details='Restart WinDiag as Administrator to use this fix.')
        steps = [
            (['netsh', 'winsock', 'reset'],   'Winsock reset'),
            (['netsh', 'int', 'ip', 'reset'],  'TCP/IP reset'),
            (['ipconfig', '/release'],          'IP released'),
            (['ipconfig', '/flushdns'],         'DNS flushed'),
            (['ipconfig', '/renew'],            'IP renewed'),
        ]
        log = []
        for cmd, label in steps:
            ok, _, _ = _run(cmd, timeout=30)
            log.append(f'{"✓" if ok else "✗"} {label}')
        return FixResult(success=True, message='Network stack reset complete',
                         details='\n'.join(log), requires_reboot=True)

    def fix_reset_winsock(self) -> FixResult:
        if not is_admin():
            return FixResult(success=False, message='Administrator privileges required')
        ok, out, err = _run(['netsh', 'winsock', 'reset'], timeout=15)
        if ok:
            return FixResult(success=True, message='Winsock reset complete',
                             requires_reboot=True)
        return FixResult(success=False, message='Winsock reset failed', details=err)

    def fix_sfc_dism(self) -> FixResult:
        if not is_admin():
            return FixResult(success=False, message='Administrator privileges required',
                             details='Restart WinDiag as Administrator to use this fix.')
        self._progress('Running DISM RestoreHealth (can take 15–30 min)…', 10)
        ok_dism, dism_out, dism_err = _run(
            ['DISM', '/Online', '/Cleanup-Image', '/RestoreHealth'], timeout=1800)

        self._progress('Running SFC /scannow (can take 5–15 min)…', 60)
        ok_sfc, sfc_out, sfc_err = _run(['sfc', '/scannow'], timeout=900)

        msgs = []
        if ok_dism or 'completed successfully' in dism_out:
            msgs.append('✓ DISM repair completed')
        else:
            msgs.append('✗ DISM repair had errors')

        if 'no integrity violations' in sfc_out:
            msgs.append('✓ SFC: no corrupt files found')
        elif 'successfully repaired' in sfc_out:
            msgs.append('✓ SFC repaired corrupt files')
        else:
            msgs.append('? SFC scan finished (check CBS.log)')

        return FixResult(success=True, message='System file repair complete',
                         details='\n'.join(msgs), requires_reboot=True)

    def fix_dism_only(self) -> FixResult:
        if not is_admin():
            return FixResult(success=False, message='Administrator privileges required')
        self._progress('Running DISM RestoreHealth…', 20)
        ok, out, err = _run(
            ['DISM', '/Online', '/Cleanup-Image', '/RestoreHealth'], timeout=1800)
        if ok or 'completed successfully' in out:
            return FixResult(success=True, message='DISM repair completed',
                             details='Run SFC /scannow next to fix remaining issues.',
                             requires_reboot=True)
        return FixResult(success=False, message='DISM repair encountered errors',
                         details=(out + err)[-600:])

    def fix_windows_update(self) -> FixResult:
        try:
            subprocess.Popen('start ms-settings:windowsupdate', shell=True)
            return FixResult(success=True, message='Windows Update opened',
                             details='Install all available updates, then restart.')
        except Exception as e:
            return FixResult(success=False, message='Could not open Windows Update',
                             details=str(e))

    def fix_enable_defender(self) -> FixResult:
        if not is_admin():
            return FixResult(success=False, message='Administrator privileges required')
        ok, _, err = _run(
            ['powershell', '-NoProfile', '-Command',
             'Set-MpPreference -DisableRealtimeMonitoring $false'], timeout=20)
        if ok:
            return FixResult(success=True, message='Defender real-time protection enabled')
        return FixResult(success=False, message='Could not enable Defender',
                         details='May be controlled by Group Policy.')

    def fix_check_disk(self, drive: str = 'C:') -> FixResult:
        if not is_admin():
            return FixResult(success=False, message='Administrator privileges required')
        # Schedule via fsutil dirty flag (always works on NTFS)
        _run(['fsutil', 'dirty', 'set', drive], timeout=10)
        return FixResult(success=True,
                         message=f'CHKDSK scheduled for {drive} on next restart',
                         details='Restart your computer to run the disk check.',
                         requires_reboot=True)

    def fix_clear_prefetch(self) -> FixResult:
        if not is_admin():
            return FixResult(success=False, message='Administrator privileges required')
        pf = r'C:\Windows\Prefetch'
        count = 0
        if os.path.isdir(pf):
            for f in os.listdir(pf):
                try:
                    os.remove(os.path.join(pf, f))
                    count += 1
                except OSError:
                    pass
        return FixResult(success=True, message=f'Cleared {count} prefetch files')

    def fix_start_service(self, svc: str) -> FixResult:
        if not is_admin():
            return FixResult(success=False, message='Administrator privileges required')
        ok, out, err = _run(['net', 'start', svc], timeout=30)
        if ok or 'started successfully' in out:
            return FixResult(success=True, message=f"Service '{svc}' started")
        if 'already been started' in out or 'already running' in (out + err):
            return FixResult(success=True, message=f"Service '{svc}' is already running")
        return FixResult(success=False, message=f"Failed to start '{svc}'",
                         details=(out + err)[:300])

    def fix_sync_time(self) -> FixResult:
        if not is_admin():
            return FixResult(success=False, message='Administrator privileges required')
        steps = [
            (['net', 'start', 'W32Time'],            'Start W32Time service'),
            (['w32tm', '/config', '/syncfromflags:auto', '/update'], 'Configure NTP'),
            (['w32tm', '/resync', '/force'],          'Force time sync'),
        ]
        log = []
        for cmd, label in steps:
            ok, _, _ = _run(cmd, timeout=15)
            log.append(f'{"✓" if ok else "~"} {label}')
        return FixResult(success=True, message='Time sync forced',
                         details='\n'.join(log))

    def fix_enable_firewall(self) -> FixResult:
        if not is_admin():
            return FixResult(success=False, message='Administrator privileges required')
        ok, out, err = _run(
            ['netsh', 'advfirewall', 'set', 'allprofiles', 'state', 'on'],
            timeout=15)
        if ok or 'ok' in out.lower():
            return FixResult(success=True, message='Windows Firewall enabled for all profiles')
        return FixResult(success=False, message='Could not enable firewall', details=err)

    def fix_enable_uac(self) -> FixResult:
        if not is_admin():
            return FixResult(success=False, message='Administrator privileges required')
        ok, _, err = _run(
            ['reg', 'add',
             r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
             '/v', 'EnableLUA', '/t', 'REG_DWORD', '/d', '1', '/f'],
            timeout=10)
        if ok:
            return FixResult(success=True,
                             message='UAC re-enabled — restart required',
                             requires_reboot=True)
        return FixResult(success=False, message='Failed to enable UAC', details=err)

    def fix_enable_system_restore(self) -> FixResult:
        if not is_admin():
            return FixResult(success=False, message='Administrator privileges required')
        # Enable VSS service and create a restore point via PowerShell
        ok, out, err = _run(
            ['powershell', '-NoProfile', '-Command',
             'Enable-ComputerRestore -Drive "C:\\"; '
             'Checkpoint-Computer -Description "WinDiag restore point" '
             '-RestorePointType MODIFY_SETTINGS'],
            timeout=60)
        if ok:
            return FixResult(success=True, message='System Restore enabled and restore point created')
        return FixResult(success=False,
                         message='Could not enable System Restore',
                         details='May require Group Policy changes.')

    def fix_clear_minidumps(self) -> FixResult:
        if not is_admin():
            return FixResult(success=False, message='Administrator privileges required')
        import glob as _glob
        minidump = r'C:\Windows\Minidump'
        count = 0
        if os.path.isdir(minidump):
            for f in _glob.glob(os.path.join(minidump, '*.dmp')):
                try:
                    os.remove(f)
                    count += 1
                except OSError:
                    pass
        full = r'C:\Windows\MEMORY.DMP'
        if os.path.isfile(full):
            try:
                os.remove(full)
                count += 1
            except OSError:
                pass
        return FixResult(success=True, message=f'Removed {count} crash dump file(s)')

    def fix_disable_hibernate(self) -> FixResult:
        if not is_admin():
            return FixResult(success=False, message='Administrator privileges required')
        ok, out, err = _run(['powercfg', '/h', 'off'], timeout=15)
        if ok:
            return FixResult(success=True,
                             message='Hibernation disabled — hiberfil.sys deleted',
                             details='Fast Startup is also now disabled.')
        return FixResult(success=False, message='Could not disable hibernation', details=err)

    def fix_rebuild_wmi(self) -> FixResult:
        if not is_admin():
            return FixResult(success=False, message='Administrator privileges required')
        self._progress('Stopping WMI service…', 10)
        cmds = [
            (['net', 'stop', 'winmgmt', '/y'],          'Stop WMI'),
            (['winmgmt', '/resetrepository'],             'Reset repository'),
            (['net', 'start', 'winmgmt'],                'Start WMI'),
            (['winmgmt', '/verifyrepository'],            'Verify repository'),
        ]
        log = []
        for cmd, label in cmds:
            ok, _, _ = _run(cmd, timeout=60)
            log.append(f'{"✓" if ok else "~"} {label}')
        return FixResult(success=True, message='WMI repository rebuilt',
                         details='\n'.join(log))

    def fix_open_device_manager(self) -> FixResult:
        try:
            subprocess.Popen(['devmgmt.msc'])
            return FixResult(success=True,
                             message='Device Manager opened',
                             details='Look for devices with yellow warning icons.')
        except Exception as e:
            return FixResult(success=False, message='Could not open Device Manager', details=str(e))

    def fix_open_startup(self) -> FixResult:
        try:
            subprocess.Popen(['taskmgr', '/0', '/startup'])
            return FixResult(success=True,
                             message='Task Manager Startup tab opened',
                             details='Right-click programs and choose Disable to speed up boot.')
        except Exception:
            try:
                subprocess.Popen('start ms-settings:startupapps', shell=True)
                return FixResult(success=True, message='Startup Apps settings opened')
            except Exception as e:
                return FixResult(success=False, message='Could not open startup manager', details=str(e))

    def fix_repair_vcredist(self) -> FixResult:
        try:
            subprocess.Popen('start ms-settings:appsfeatures', shell=True)
            return FixResult(success=True,
                             message='Apps & Features opened',
                             details='Search for "Visual C++" and click Modify/Repair on each.')
        except Exception as e:
            return FixResult(success=False, message='Could not open Apps & Features', details=str(e))

    def fix_reset_store(self) -> FixResult:
        try:
            subprocess.Popen(['wsreset.exe'])
            return FixResult(success=True,
                             message='Microsoft Store cache reset started',
                             details='Store will open automatically when done.')
        except Exception as e:
            return FixResult(success=False, message='Could not run wsreset', details=str(e))

    # -------------------------------------------------------------------
    # Dispatch
    # -------------------------------------------------------------------

    def apply_fix(self, fix_id: str, **kwargs) -> FixResult:
        dispatch = {
            'fix_temp_cleanup':          self.fix_temp_cleanup,
            'fix_disk_cleanup':          self.fix_disk_cleanup,
            'fix_flush_dns':             self.fix_flush_dns,
            'fix_network_reset':         self.fix_network_reset,
            'fix_reset_winsock':         self.fix_reset_winsock,
            'fix_sfc_dism':              self.fix_sfc_dism,
            'fix_dism_only':             self.fix_dism_only,
            'fix_windows_update':        self.fix_windows_update,
            'fix_enable_defender':       self.fix_enable_defender,
            'fix_check_disk':            lambda: self.fix_check_disk(kwargs.get('drive', 'C:')),
            'fix_clear_prefetch':        self.fix_clear_prefetch,
            'fix_sync_time':             self.fix_sync_time,
            'fix_enable_firewall':       self.fix_enable_firewall,
            'fix_enable_uac':            self.fix_enable_uac,
            'fix_enable_system_restore': self.fix_enable_system_restore,
            'fix_clear_minidumps':       self.fix_clear_minidumps,
            'fix_disable_hibernate':     self.fix_disable_hibernate,
            'fix_rebuild_wmi':           self.fix_rebuild_wmi,
            'fix_open_device_manager':   self.fix_open_device_manager,
            'fix_open_startup':          self.fix_open_startup,
            'fix_repair_vcredist':       self.fix_repair_vcredist,
            'fix_reset_store':           self.fix_reset_store,
        }

        if fix_id.startswith('fix_start_service_'):
            return self.fix_start_service(fix_id[len('fix_start_service_'):])

        fn = dispatch.get(fix_id)
        if fn:
            return fn()
        return FixResult(success=False, message=f'Unknown fix: {fix_id}')
