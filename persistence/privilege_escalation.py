"""
Privilege Escalation Module

Automated enumeration and exploitation for privilege escalation.
"""

import os
import subprocess
import platform
import re
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, asdict


@dataclass
class PrivescVector:
    """Represents a privilege escalation vector."""
    vector_type: str
    severity: str  # 'critical', 'high', 'medium', 'low'
    description: str
    command: Optional[str] = None
    file_path: Optional[str] = None
    details: Optional[str] = None

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return asdict(self)


class PrivilegeEscalation:
    """
    Privilege escalation enumeration and exploitation.

    Supports both Windows and Linux privilege escalation techniques.
    """

    def __init__(self):
        """Initialize privilege escalation module."""
        self.os_type = platform.system().lower()
        self.vectors = []

    def enumerate(self) -> List[PrivescVector]:
        """
        Perform comprehensive privilege escalation enumeration.

        Returns:
            List of discovered privilege escalation vectors
        """
        print(f"[*] Enumerating privilege escalation vectors on {self.os_type}...")

        if 'windows' in self.os_type:
            self._enumerate_windows()
        elif 'linux' in self.os_type:
            self._enumerate_linux()
        else:
            print(f"[-] Unsupported OS: {self.os_type}")

        return self.vectors

    def _enumerate_windows(self):
        """Enumerate Windows privilege escalation vectors."""
        print("[*] Enumerating Windows privilege escalation...")

        # Check user privileges
        self._check_windows_privileges()

        # Check unquoted service paths
        self._check_unquoted_service_paths()

        # Check weak service permissions
        self._check_weak_service_permissions()

        # Check AlwaysInstallElevated
        self._check_always_install_elevated()

        # Check scheduled tasks
        self._check_scheduled_tasks()

        # Check autologon credentials
        self._check_autologon()

    def _enumerate_linux(self):
        """Enumerate Linux privilege escalation vectors."""
        print("[*] Enumerating Linux privilege escalation...")

        # Check SUID binaries
        self._check_suid_binaries()

        # Check sudo permissions
        self._check_sudo()

        # Check writable /etc/passwd
        self._check_writable_etc_passwd()

        # Check cron jobs
        self._check_cron_jobs()

        # Check kernel version
        self._check_kernel_exploits()

        # Check capabilities
        self._check_capabilities()

    def _check_windows_privileges(self):
        """Check current Windows privileges."""
        try:
            result = subprocess.run(
                ['whoami', '/priv'],
                capture_output=True,
                text=True,
                timeout=10
            )

            # Check for dangerous privileges
            dangerous_privs = [
                'SeImpersonatePrivilege',
                'SeAssignPrimaryTokenPrivilege',
                'SeDebugPrivilege',
                'SeTcbPrivilege',
                'SeTakeOwnershipPrivilege',
                'SeLoadDriverPrivilege',
                'SeRestorePrivilege',
                'SeBackupPrivilege'
            ]

            for priv in dangerous_privs:
                if priv in result.stdout and 'Enabled' in result.stdout:
                    self.vectors.append(PrivescVector(
                        vector_type='windows_privilege',
                        severity='high',
                        description=f'Dangerous privilege enabled: {priv}',
                        details=f'Can potentially abuse {priv} for privilege escalation'
                    ))

        except Exception as e:
            print(f"[-] Error checking Windows privileges: {e}")

    def _check_unquoted_service_paths(self):
        """Check for unquoted service paths on Windows."""
        try:
            result = subprocess.run(
                ['wmic', 'service', 'get', 'name,pathname,displayname,startmode'],
                capture_output=True,
                text=True,
                timeout=30
            )

            lines = result.stdout.split('\n')

            for line in lines:
                # Look for paths with spaces but no quotes
                if '.exe' in line and 'C:\\' in line:
                    if not line.strip().startswith('"') and ' ' in line:
                        # Extract service name
                        parts = line.split()
                        if parts:
                            self.vectors.append(PrivescVector(
                                vector_type='unquoted_service_path',
                                severity='medium',
                                description='Unquoted service path vulnerability',
                                details=line.strip()
                            ))

        except Exception as e:
            print(f"[-] Error checking unquoted service paths: {e}")

    def _check_weak_service_permissions(self):
        """Check for weak service permissions."""
        try:
            # Get list of services
            result = subprocess.run(
                ['sc', 'query', 'state=', 'all'],
                capture_output=True,
                text=True,
                timeout=30
            )

            # Extract service names
            service_names = re.findall(r'SERVICE_NAME:\s+(\S+)', result.stdout)

            for service in service_names[:20]:  # Check first 20 services
                # Check service permissions with accesschk (if available)
                try:
                    perm_result = subprocess.run(
                        ['icacls', service],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )

                    # Look for weak permissions
                    if 'Everyone' in perm_result.stdout or 'BUILTIN\\Users' in perm_result.stdout:
                        self.vectors.append(PrivescVector(
                            vector_type='weak_service_permissions',
                            severity='high',
                            description=f'Weak permissions on service: {service}',
                            details=perm_result.stdout[:200]
                        ))

                except:
                    pass

        except Exception as e:
            print(f"[-] Error checking service permissions: {e}")

    def _check_always_install_elevated(self):
        """Check AlwaysInstallElevated registry keys."""
        try:
            reg_keys = [
                r'HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer',
                r'HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer'
            ]

            both_enabled = True

            for key in reg_keys:
                result = subprocess.run(
                    ['reg', 'query', key, '/v', 'AlwaysInstallElevated'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )

                if result.returncode != 0 or '0x1' not in result.stdout:
                    both_enabled = False
                    break

            if both_enabled:
                self.vectors.append(PrivescVector(
                    vector_type='always_install_elevated',
                    severity='critical',
                    description='AlwaysInstallElevated is enabled',
                    details='Can install MSI packages with SYSTEM privileges'
                ))

        except Exception as e:
            print(f"[-] Error checking AlwaysInstallElevated: {e}")

    def _check_scheduled_tasks(self):
        """Check for modifiable scheduled tasks."""
        try:
            result = subprocess.run(
                ['schtasks', '/query', '/fo', 'LIST', '/v'],
                capture_output=True,
                text=True,
                timeout=30
            )

            # Look for tasks running as SYSTEM
            if 'SYSTEM' in result.stdout:
                self.vectors.append(PrivescVector(
                    vector_type='scheduled_task',
                    severity='medium',
                    description='Scheduled tasks running as SYSTEM found',
                    details='Check if task files/scripts are writable'
                ))

        except Exception as e:
            print(f"[-] Error checking scheduled tasks: {e}")

    def _check_autologon(self):
        """Check for autologon credentials in registry."""
        try:
            result = subprocess.run(
                ['reg', 'query', r'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'],
                capture_output=True,
                text=True,
                timeout=10
            )

            if 'DefaultPassword' in result.stdout:
                # Extract password
                password = re.search(r'DefaultPassword\s+REG_SZ\s+(.+)', result.stdout)
                if password:
                    self.vectors.append(PrivescVector(
                        vector_type='autologon_credentials',
                        severity='high',
                        description='Autologon credentials found in registry',
                        details='Credentials may provide privilege escalation'
                    ))

        except Exception as e:
            print(f"[-] Error checking autologon: {e}")

    def _check_suid_binaries(self):
        """Check for SUID binaries on Linux."""
        try:
            result = subprocess.run(
                ['find', '/', '-perm', '-4000', '-type', 'f', '2>/dev/null'],
                capture_output=True,
                text=True,
                timeout=60,
                shell=True
            )

            suid_binaries = result.stdout.strip().split('\n')

            # Known exploitable SUID binaries
            dangerous_bins = [
                'nmap', 'vim', 'nano', 'find', 'bash', 'more', 'less',
                'python', 'perl', 'ruby', 'php', 'gdb', 'cp', 'mv'
            ]

            for binary in suid_binaries:
                binary_name = os.path.basename(binary)

                if binary_name in dangerous_bins:
                    self.vectors.append(PrivescVector(
                        vector_type='suid_binary',
                        severity='critical',
                        description=f'Dangerous SUID binary: {binary_name}',
                        file_path=binary,
                        details=f'Can be exploited for privilege escalation via GTFOBins'
                    ))

        except Exception as e:
            print(f"[-] Error checking SUID binaries: {e}")

    def _check_sudo(self):
        """Check sudo permissions."""
        try:
            result = subprocess.run(
                ['sudo', '-l'],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                sudo_output = result.stdout

                # Check for NOPASSWD
                if 'NOPASSWD' in sudo_output:
                    self.vectors.append(PrivescVector(
                        vector_type='sudo_nopasswd',
                        severity='high',
                        description='NOPASSWD sudo permissions found',
                        details=sudo_output[:200]
                    ))

                # Check for dangerous sudo commands
                dangerous_cmds = ['ALL', 'vim', 'nano', 'python', 'perl', 'find', 'nmap']

                for cmd in dangerous_cmds:
                    if cmd in sudo_output:
                        self.vectors.append(PrivescVector(
                            vector_type='sudo_permissions',
                            severity='high',
                            description=f'Sudo permission for: {cmd}',
                            details='Can be exploited for privilege escalation'
                        ))

        except Exception as e:
            # sudo -l might fail without password
            pass

    def _check_writable_etc_passwd(self):
        """Check if /etc/passwd is writable."""
        try:
            if os.access('/etc/passwd', os.W_OK):
                self.vectors.append(PrivescVector(
                    vector_type='writable_etc_passwd',
                    severity='critical',
                    description='/etc/passwd is writable',
                    file_path='/etc/passwd',
                    details='Can add root user or modify existing users'
                ))

        except Exception as e:
            print(f"[-] Error checking /etc/passwd: {e}")

    def _check_cron_jobs(self):
        """Check for modifiable cron jobs."""
        cron_paths = [
            '/etc/crontab',
            '/etc/cron.d',
            '/var/spool/cron',
            '/var/spool/cron/crontabs'
        ]

        for path in cron_paths:
            try:
                if os.path.exists(path):
                    if os.path.isdir(path):
                        # Check directory permissions
                        if os.access(path, os.W_OK):
                            self.vectors.append(PrivescVector(
                                vector_type='writable_cron_directory',
                                severity='high',
                                description=f'Writable cron directory: {path}',
                                file_path=path
                            ))
                    else:
                        # Check file permissions
                        if os.access(path, os.W_OK):
                            self.vectors.append(PrivescVector(
                                vector_type='writable_cron_file',
                                severity='high',
                                description=f'Writable cron file: {path}',
                                file_path=path
                            ))

            except Exception as e:
                pass

    def _check_kernel_exploits(self):
        """Check for known kernel vulnerabilities."""
        try:
            result = subprocess.run(
                ['uname', '-r'],
                capture_output=True,
                text=True,
                timeout=5
            )

            kernel_version = result.stdout.strip()

            # Known vulnerable kernel versions (simplified)
            vulnerable_versions = {
                '2.6.': 'DirtyCow (CVE-2016-5195)',
                '3.': 'Potential kernel exploits available',
                '4.4': 'Double-Free (CVE-2017-6074)',
            }

            for vuln_ver, exploit in vulnerable_versions.items():
                if vuln_ver in kernel_version:
                    self.vectors.append(PrivescVector(
                        vector_type='kernel_exploit',
                        severity='critical',
                        description=f'Potentially vulnerable kernel: {kernel_version}',
                        details=exploit
                    ))

        except Exception as e:
            print(f"[-] Error checking kernel version: {e}")

    def _check_capabilities(self):
        """Check for dangerous Linux capabilities."""
        try:
            result = subprocess.run(
                ['getcap', '-r', '/', '2>/dev/null'],
                capture_output=True,
                text=True,
                timeout=60,
                shell=True
            )

            dangerous_caps = ['cap_setuid', 'cap_dac_override', 'cap_sys_admin']

            for line in result.stdout.split('\n'):
                for cap in dangerous_caps:
                    if cap in line.lower():
                        self.vectors.append(PrivescVector(
                            vector_type='dangerous_capability',
                            severity='high',
                            description=f'Dangerous capability found',
                            details=line.strip()
                        ))

        except Exception as e:
            print(f"[-] Error checking capabilities: {e}")

    def generate_report(self) -> str:
        """
        Generate privilege escalation report.

        Returns:
            Formatted report string
        """
        if not self.vectors:
            return "[+] No privilege escalation vectors found."

        report = []
        report.append("=" * 80)
        report.append("PRIVILEGE ESCALATION ENUMERATION REPORT")
        report.append("=" * 80)
        report.append("")

        # Group by severity
        critical = [v for v in self.vectors if v.severity == 'critical']
        high = [v for v in self.vectors if v.severity == 'high']
        medium = [v for v in self.vectors if v.severity == 'medium']
        low = [v for v in self.vectors if v.severity == 'low']

        report.append(f"SUMMARY:")
        report.append(f"  Critical: {len(critical)}")
        report.append(f"  High:     {len(high)}")
        report.append(f"  Medium:   {len(medium)}")
        report.append(f"  Low:      {len(low)}")
        report.append("")

        # List all vectors
        for i, vector in enumerate(self.vectors, 1):
            report.append(f"[{i}] {vector.description} ({vector.severity.upper()})")
            report.append(f"    Type: {vector.vector_type}")

            if vector.file_path:
                report.append(f"    Path: {vector.file_path}")

            if vector.command:
                report.append(f"    Command: {vector.command}")

            if vector.details:
                # Truncate long details
                details = vector.details[:200] + "..." if len(vector.details) > 200 else vector.details
                report.append(f"    Details: {details}")

            report.append("")

        report.append("=" * 80)
        return "\n".join(report)

    def export_json(self, filename: str):
        """
        Export vectors to JSON file.

        Args:
            filename: Output filename
        """
        import json

        with open(filename, 'w') as f:
            json.dump([v.to_dict() for v in self.vectors], f, indent=2)

        print(f"[+] Exported {len(self.vectors)} vectors to {filename}")


def main():
    """Main function for standalone usage."""
    import argparse

    parser = argparse.ArgumentParser(description='RedCell Privilege Escalation Enumeration')
    parser.add_argument('--export', help='Export results to JSON file')
    parser.add_argument('--verbose', action='store_true', help='Verbose output')

    args = parser.parse_args()

    privesc = PrivilegeEscalation()

    # Enumerate privilege escalation vectors
    vectors = privesc.enumerate()

    # Generate and print report
    print("\n" + privesc.generate_report())

    # Export if requested
    if args.export:
        privesc.export_json(args.export)


if __name__ == '__main__':
    main()
