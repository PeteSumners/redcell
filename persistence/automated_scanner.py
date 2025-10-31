"""
Automated Post-Exploitation Scanner

Comprehensive post-exploitation enumeration and exploitation.
"""

import platform
from typing import Dict, List, Optional
import json
from datetime import datetime

from persistence.privilege_escalation import PrivilegeEscalation, PrivescVector
from persistence.credential_dumping import CredentialDumper, Credential


class AutomatedScanner:
    """
    Automated post-exploitation scanner.

    Combines:
    - Privilege escalation enumeration
    - Credential dumping
    - Automated exploitation
    - Comprehensive reporting
    """

    def __init__(self, aggressive: bool = False):
        """
        Initialize automated scanner.

        Args:
            aggressive: Enable aggressive scanning (may be detected)
        """
        self.os_type = platform.system().lower()
        self.aggressive = aggressive
        self.privesc_vectors = []
        self.credentials = []
        self.scan_results = {
            'start_time': datetime.now().isoformat(),
            'os_type': self.os_type,
            'hostname': platform.node(),
            'aggressive': aggressive
        }

    def run_full_scan(self) -> Dict:
        """
        Run comprehensive post-exploitation scan.

        Returns:
            Dictionary of scan results
        """
        print("=" * 80)
        print("REDCELL AUTOMATED POST-EXPLOITATION SCANNER")
        print("=" * 80)
        print(f"Target OS: {self.os_type}")
        print(f"Hostname: {platform.node()}")
        print(f"Aggressive mode: {self.aggressive}")
        print("=" * 80)

        # Phase 1: Privilege Escalation Enumeration
        print("\n[*] Phase 1: Privilege Escalation Enumeration")
        print("-" * 80)
        self._scan_privesc()

        # Phase 2: Credential Dumping
        if self.aggressive:
            print("\n[*] Phase 2: Credential Dumping (Aggressive)")
            print("-" * 80)
            self._scan_credentials()
        else:
            print("\n[!] Skipping credential dumping (not in aggressive mode)")

        # Phase 3: Analysis and Recommendations
        print("\n[*] Phase 3: Analysis")
        print("-" * 80)
        self._analyze_results()

        # Update scan results
        self.scan_results['end_time'] = datetime.now().isoformat()
        self.scan_results['privesc_vectors'] = len(self.privesc_vectors)
        self.scan_results['credentials_found'] = len(self.credentials)

        return self.scan_results

    def _scan_privesc(self):
        """Scan for privilege escalation vectors."""
        privesc_scanner = PrivilegeEscalation()
        self.privesc_vectors = privesc_scanner.enumerate()

        print(f"\n[+] Found {len(self.privesc_vectors)} privilege escalation vectors")

        # Categorize by severity
        critical = [v for v in self.privesc_vectors if v.severity == 'critical']
        high = [v for v in self.privesc_vectors if v.severity == 'high']

        if critical:
            print(f"[!] {len(critical)} CRITICAL vectors found:")
            for v in critical[:5]:  # Show first 5
                print(f"    - {v.description}")

        if high:
            print(f"[!] {len(high)} HIGH severity vectors found")

        # Store in results
        self.scan_results['privesc'] = {
            'total': len(self.privesc_vectors),
            'critical': len(critical),
            'high': len(high),
            'vectors': [v.to_dict() for v in self.privesc_vectors]
        }

    def _scan_credentials(self):
        """Scan for credentials."""
        cred_dumper = CredentialDumper()
        self.credentials = cred_dumper.dump_all()

        print(f"\n[+] Found {len(self.credentials)} credentials")

        # Categorize by type
        types = {}
        for cred in self.credentials:
            types[cred.credential_type] = types.get(cred.credential_type, 0) + 1

        for cred_type, count in types.items():
            print(f"    - {cred_type}: {count}")

        # Store in results
        self.scan_results['credentials'] = {
            'total': len(self.credentials),
            'by_type': types,
            'credentials': [c.to_dict() for c in self.credentials]
        }

    def _analyze_results(self):
        """Analyze scan results and provide recommendations."""
        print("\n[*] Analyzing results...")

        recommendations = []

        # Analyze privilege escalation vectors
        if self.privesc_vectors:
            critical_vectors = [v for v in self.privesc_vectors if v.severity == 'critical']

            if critical_vectors:
                recommendations.append({
                    'priority': 'CRITICAL',
                    'action': 'Exploit privilege escalation vectors',
                    'details': f'Found {len(critical_vectors)} critical vectors that should be exploited immediately'
                })

                # Specific recommendations based on vector types
                vector_types = set(v.vector_type for v in critical_vectors)

                if 'suid_binary' in vector_types:
                    recommendations.append({
                        'priority': 'HIGH',
                        'action': 'Exploit SUID binaries',
                        'details': 'Use GTFOBins to exploit SUID binaries for privilege escalation'
                    })

                if 'always_install_elevated' in vector_types:
                    recommendations.append({
                        'priority': 'CRITICAL',
                        'action': 'Create malicious MSI installer',
                        'details': 'AlwaysInstallElevated is enabled - create MSI for SYSTEM privileges'
                    })

                if 'writable_etc_passwd' in vector_types:
                    recommendations.append({
                        'priority': 'CRITICAL',
                        'action': 'Add root user to /etc/passwd',
                        'details': '/etc/passwd is writable - add new root user immediately'
                    })

        # Analyze credentials
        if self.credentials:
            hash_creds = [c for c in self.credentials if c.credential_type == 'hash']

            if hash_creds:
                recommendations.append({
                    'priority': 'HIGH',
                    'action': 'Crack password hashes',
                    'details': f'Found {len(hash_creds)} password hashes - use hashcat or john for cracking'
                })

            plaintext_creds = [c for c in self.credentials if c.credential_type == 'password']

            if plaintext_creds:
                recommendations.append({
                    'priority': 'HIGH',
                    'action': 'Test credential reuse',
                    'details': f'Found {len(plaintext_creds)} plaintext passwords - test for reuse across systems'
                })

        # Store recommendations
        self.scan_results['recommendations'] = recommendations

        # Print recommendations
        if recommendations:
            print(f"\n[+] Generated {len(recommendations)} recommendations:")
            for rec in recommendations:
                print(f"\n[{rec['priority']}] {rec['action']}")
                print(f"    {rec['details']}")
        else:
            print("\n[+] No specific recommendations generated")

    def generate_report(self, include_full_details: bool = True) -> str:
        """
        Generate comprehensive report.

        Args:
            include_full_details: Include full scan details

        Returns:
            Formatted report string
        """
        report = []
        report.append("=" * 80)
        report.append("AUTOMATED POST-EXPLOITATION SCAN REPORT")
        report.append("=" * 80)
        report.append(f"\nTarget Information:")
        report.append(f"  OS: {self.scan_results['os_type']}")
        report.append(f"  Hostname: {self.scan_results['hostname']}")
        report.append(f"  Scan Start: {self.scan_results['start_time']}")
        report.append(f"  Scan End: {self.scan_results.get('end_time', 'N/A')}")
        report.append(f"  Aggressive Mode: {self.aggressive}")

        # Executive Summary
        report.append("\n" + "=" * 80)
        report.append("EXECUTIVE SUMMARY")
        report.append("=" * 80)

        if 'privesc' in self.scan_results:
            privesc = self.scan_results['privesc']
            report.append(f"\nPrivilege Escalation Vectors: {privesc['total']}")
            report.append(f"  Critical: {privesc['critical']}")
            report.append(f"  High: {privesc['high']}")

        if 'credentials' in self.scan_results:
            creds = self.scan_results['credentials']
            report.append(f"\nCredentials Found: {creds['total']}")
            for cred_type, count in creds['by_type'].items():
                report.append(f"  {cred_type}: {count}")

        # Recommendations
        if 'recommendations' in self.scan_results:
            report.append("\n" + "=" * 80)
            report.append("RECOMMENDATIONS")
            report.append("=" * 80)

            for i, rec in enumerate(self.scan_results['recommendations'], 1):
                report.append(f"\n[{i}] [{rec['priority']}] {rec['action']}")
                report.append(f"    {rec['details']}")

        # Full details
        if include_full_details:
            if 'privesc' in self.scan_results and self.scan_results['privesc']['vectors']:
                report.append("\n" + "=" * 80)
                report.append("PRIVILEGE ESCALATION DETAILS")
                report.append("=" * 80)

                for i, vector in enumerate(self.scan_results['privesc']['vectors'], 1):
                    report.append(f"\n[{i}] {vector['description']} ({vector['severity'].upper()})")
                    report.append(f"    Type: {vector['vector_type']}")

                    if vector.get('file_path'):
                        report.append(f"    Path: {vector['file_path']}")

                    if vector.get('details'):
                        details = vector['details'][:200] + "..." if len(vector['details']) > 200 else vector['details']
                        report.append(f"    Details: {details}")

            if 'credentials' in self.scan_results and self.scan_results['credentials']['credentials']:
                report.append("\n" + "=" * 80)
                report.append("CREDENTIAL DETAILS")
                report.append("=" * 80)

                for i, cred in enumerate(self.scan_results['credentials']['credentials'][:20], 1):
                    report.append(f"\n[{i}] {cred['credential_type'].upper()}")
                    report.append(f"    Username: {cred['username']}")
                    value = cred['value'][:60] + "..." if len(cred['value']) > 60 else cred['value']
                    report.append(f"    Value: {value}")
                    report.append(f"    Source: {cred['source']}")

        report.append("\n" + "=" * 80)
        return "\n".join(report)

    def export_results(self, filename: str):
        """
        Export scan results to JSON file.

        Args:
            filename: Output filename
        """
        with open(filename, 'w') as f:
            json.dump(self.scan_results, f, indent=2)

        print(f"\n[+] Scan results exported to: {filename}")

    def auto_exploit(self) -> Dict:
        """
        Automatically attempt to exploit discovered vectors.

        Returns:
            Dictionary of exploitation results
        """
        print("\n[*] Auto-exploitation mode (NOT IMPLEMENTED)")
        print("[!] Manual exploitation recommended for safety")

        # This would be implemented with caution
        # Auto-exploitation can be dangerous and should require explicit user confirmation

        return {
            'status': 'not_implemented',
            'message': 'Auto-exploitation requires manual confirmation'
        }


def main():
    """Main function for standalone usage."""
    import argparse

    parser = argparse.ArgumentParser(description='RedCell Automated Post-Exploitation Scanner')
    parser.add_argument('--aggressive', action='store_true',
                       help='Enable aggressive scanning (includes credential dumping)')
    parser.add_argument('--export', help='Export results to JSON file')
    parser.add_argument('--brief', action='store_true',
                       help='Brief report (exclude full details)')

    args = parser.parse_args()

    scanner = AutomatedScanner(aggressive=args.aggressive)

    # Run scan
    results = scanner.run_full_scan()

    # Generate report
    print("\n")
    print(scanner.generate_report(include_full_details=not args.brief))

    # Export if requested
    if args.export:
        scanner.export_results(args.export)


if __name__ == '__main__':
    main()
