"""
Cleanup & Anti-Forensics Module

Clean up artifacts left during penetration testing operations.
"""

import os
import platform
import subprocess
from typing import List, Dict
from pathlib import Path
import time


class Cleanup:
    """
    Clean up artifacts from penetration testing.

    Features:
    - File deletion (secure and standard)
    - Log cleaning (Windows Event Logs, syslog)
    - Registry cleanup (Windows)
    - Persistence removal
    - Process termination
    - Network artifact cleanup
    """

    def __init__(self, verbose: bool = True):
        """
        Initialize cleanup.

        Args:
            verbose: Verbose output
        """
        self.verbose = verbose
        self.os_type = platform.system().lower()
        self.cleaned_items = []
        self.failed_items = []

    def log(self, message: str):
        """Log message if verbose."""
        if self.verbose:
            print(message)

    def delete_file(self, file_path: str, secure: bool = False) -> bool:
        """
        Delete file.

        Args:
            file_path: Path to file
            secure: Use secure deletion (overwrite before delete)

        Returns:
            True if successful
        """
        try:
            if not os.path.exists(file_path):
                self.log(f"[!] File not found: {file_path}")
                return True  # Already gone

            if secure:
                # Secure delete: overwrite with random data
                file_size = os.path.getsize(file_path)

                with open(file_path, 'wb') as f:
                    f.write(os.urandom(file_size))

                self.log(f"[*] Securely overwritten: {file_path}")

            # Delete file
            os.remove(file_path)

            self.log(f"[+] Deleted file: {file_path}")
            self.cleaned_items.append(('file', file_path))
            return True

        except Exception as e:
            self.log(f"[-] Failed to delete {file_path}: {e}")
            self.failed_items.append(('file', file_path, str(e)))
            return False

    def delete_directory(self, dir_path: str, secure: bool = False) -> bool:
        """
        Delete directory and contents.

        Args:
            dir_path: Path to directory
            secure: Use secure deletion

        Returns:
            True if successful
        """
        try:
            if not os.path.exists(dir_path):
                self.log(f"[!] Directory not found: {dir_path}")
                return True

            # Delete all files
            for root, dirs, files in os.walk(dir_path, topdown=False):
                for name in files:
                    file_path = os.path.join(root, name)
                    self.delete_file(file_path, secure=secure)

                for name in dirs:
                    dir = os.path.join(root, name)
                    try:
                        os.rmdir(dir)
                    except:
                        pass

            # Delete directory itself
            os.rmdir(dir_path)

            self.log(f"[+] Deleted directory: {dir_path}")
            self.cleaned_items.append(('directory', dir_path))
            return True

        except Exception as e:
            self.log(f"[-] Failed to delete directory {dir_path}: {e}")
            self.failed_items.append(('directory', dir_path, str(e)))
            return False

    def clear_windows_event_log(self, log_name: str = "Security") -> bool:
        """
        Clear Windows Event Log.

        Args:
            log_name: Log name (Security, System, Application)

        Returns:
            True if successful
        """
        if 'windows' not in self.os_type:
            return False

        try:
            cmd = ['wevtutil', 'cl', log_name]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                self.log(f"[+] Cleared Windows Event Log: {log_name}")
                self.cleaned_items.append(('event_log', log_name))
                return True
            else:
                self.log(f"[-] Failed to clear log {log_name}: {result.stderr}")
                return False

        except Exception as e:
            self.log(f"[-] Error clearing event log: {e}")
            self.failed_items.append(('event_log', log_name, str(e)))
            return False

    def clear_all_windows_event_logs(self) -> Dict:
        """
        Clear all major Windows Event Logs.

        Returns:
            Dictionary of results
        """
        logs = ['Security', 'System', 'Application']
        results = {}

        for log_name in logs:
            results[log_name] = self.clear_windows_event_log(log_name)

        return results

    def clear_linux_logs(self) -> bool:
        """
        Clear Linux system logs.

        Returns:
            True if successful
        """
        if 'linux' not in self.os_type:
            return False

        log_files = [
            '/var/log/auth.log',
            '/var/log/syslog',
            '/var/log/messages',
            '/var/log/secure',
            '~/.bash_history',
            '~/.zsh_history'
        ]

        success = True

        for log_file in log_files:
            log_path = os.path.expanduser(log_file)

            if os.path.exists(log_path):
                try:
                    # Clear file (don't delete to avoid detection)
                    with open(log_path, 'w') as f:
                        f.write('')

                    self.log(f"[+] Cleared log: {log_path}")
                    self.cleaned_items.append(('log_file', log_path))

                except Exception as e:
                    self.log(f"[-] Failed to clear {log_path}: {e}")
                    self.failed_items.append(('log_file', log_path, str(e)))
                    success = False

        return success

    def remove_registry_key(self, key_path: str) -> bool:
        """
        Remove Windows registry key.

        Args:
            key_path: Registry key path

        Returns:
            True if successful
        """
        if 'windows' not in self.os_type:
            return False

        try:
            cmd = ['reg', 'delete', key_path, '/f']

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                self.log(f"[+] Removed registry key: {key_path}")
                self.cleaned_items.append(('registry_key', key_path))
                return True
            else:
                # Key might not exist, which is fine
                if "cannot find" in result.stderr.lower():
                    return True
                self.log(f"[-] Failed to remove registry key: {result.stderr}")
                return False

        except Exception as e:
            self.log(f"[-] Error removing registry key: {e}")
            self.failed_items.append(('registry_key', key_path, str(e)))
            return False

    def remove_persistence_mechanisms(self) -> Dict:
        """
        Remove common persistence mechanisms.

        Returns:
            Dictionary of results
        """
        results = {}

        if 'windows' in self.os_type:
            # Registry Run keys
            run_keys = [
                r'HKCU\Software\Microsoft\Windows\CurrentVersion\Run',
                r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
            ]

            # Note: This would need specific value names
            # For now, just document the locations
            self.log("[*] Check these locations for persistence:")
            for key in run_keys:
                self.log(f"    {key}")

        elif 'linux' in self.os_type:
            # Cron jobs
            cron_files = [
                '/etc/crontab',
                '/var/spool/cron/crontabs/*'
            ]

            for cron_file in cron_files:
                if os.path.exists(cron_file):
                    self.log(f"[*] Check cron file: {cron_file}")

        return results

    def kill_process(self, process_name: str) -> bool:
        """
        Kill process by name.

        Args:
            process_name: Process name

        Returns:
            True if successful
        """
        try:
            if 'windows' in self.os_type:
                cmd = ['taskkill', '/F', '/IM', process_name]
            else:
                cmd = ['pkill', '-9', process_name]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                self.log(f"[+] Killed process: {process_name}")
                self.cleaned_items.append(('process', process_name))
                return True
            else:
                # Process might not be running
                return True

        except Exception as e:
            self.log(f"[-] Error killing process: {e}")
            self.failed_items.append(('process', process_name, str(e)))
            return False

    def clean_artifacts(self, artifact_list: List[str]) -> Dict:
        """
        Clean list of artifacts (files/directories).

        Args:
            artifact_list: List of file/directory paths

        Returns:
            Dictionary of results
        """
        results = {
            'success': [],
            'failed': []
        }

        for artifact in artifact_list:
            if os.path.isfile(artifact):
                if self.delete_file(artifact):
                    results['success'].append(artifact)
                else:
                    results['failed'].append(artifact)

            elif os.path.isdir(artifact):
                if self.delete_directory(artifact):
                    results['success'].append(artifact)
                else:
                    results['failed'].append(artifact)

        return results

    def generate_report(self) -> str:
        """
        Generate cleanup report.

        Returns:
            Formatted report
        """
        report = []
        report.append("=" * 80)
        report.append("CLEANUP REPORT")
        report.append("=" * 80)

        report.append(f"\nCleaned Items: {len(self.cleaned_items)}")
        report.append(f"Failed Items: {len(self.failed_items)}")

        # Cleaned items
        if self.cleaned_items:
            report.append("\n" + "=" * 80)
            report.append("SUCCESSFULLY CLEANED")
            report.append("=" * 80)

            # Group by type
            types = {}
            for item_type, item_value in self.cleaned_items:
                if item_type not in types:
                    types[item_type] = []
                types[item_type].append(item_value)

            for item_type, items in types.items():
                report.append(f"\n{item_type.upper()} ({len(items)}):")
                for item in items[:10]:  # Show first 10
                    report.append(f"  • {item}")
                if len(items) > 10:
                    report.append(f"  ... and {len(items) - 10} more")

        # Failed items
        if self.failed_items:
            report.append("\n" + "=" * 80)
            report.append("FAILED TO CLEAN")
            report.append("=" * 80)

            for item_type, item_value, error in self.failed_items:
                report.append(f"\n{item_type}: {item_value}")
                report.append(f"  Error: {error}")

        report.append("\n" + "=" * 80)
        return "\n".join(report)


def main():
    """Main function for standalone usage."""
    import argparse

    parser = argparse.ArgumentParser(description='RedCell Cleanup Module')

    parser.add_argument('--file', action='append', help='Delete file')
    parser.add_argument('--dir', action='append', help='Delete directory')
    parser.add_argument('--secure', action='store_true', help='Use secure deletion')

    parser.add_argument('--clear-logs', action='store_true', help='Clear system logs')
    parser.add_argument('--clear-event-logs', action='store_true',
                       help='Clear Windows Event Logs')

    parser.add_argument('--kill-process', action='append', help='Kill process by name')

    parser.add_argument('--quiet', action='store_true', help='Quiet mode')

    args = parser.parse_args()

    cleanup = Cleanup(verbose=not args.quiet)

    # Delete files
    if args.file:
        for file_path in args.file:
            cleanup.delete_file(file_path, secure=args.secure)

    # Delete directories
    if args.dir:
        for dir_path in args.dir:
            cleanup.delete_directory(dir_path, secure=args.secure)

    # Clear logs
    if args.clear_logs:
        if 'windows' in cleanup.os_type:
            cleanup.clear_all_windows_event_logs()
        else:
            cleanup.clear_linux_logs()

    # Clear Windows Event Logs
    if args.clear_event_logs:
        cleanup.clear_all_windows_event_logs()

    # Kill processes
    if args.kill_process:
        for process_name in args.kill_process:
            cleanup.kill_process(process_name)

    # Generate report
    print("\n")
    print(cleanup.generate_report())


if __name__ == '__main__':
    main()
