"""
Automated Comprehensive Reporter

Generate complete penetration testing reports automatically.
"""

import json
from typing import Dict, List
from datetime import datetime

from reporting.report_generator import ReportGenerator, Finding, Target
from reporting.ioc_extractor import IOCExtractor
from reporting.timeline import Timeline
from reporting.cleanup import Cleanup


class AutomatedReporter:
    """
    Comprehensive automated reporting.

    Integrates:
    - Report generation
    - IOC extraction
    - Timeline visualization
    - Cleanup tracking
    """

    def __init__(
        self,
        engagement_name: str,
        client_name: str,
        tester_name: str = "RedCell Security Team"
    ):
        """
        Initialize automated reporter.

        Args:
            engagement_name: Engagement name
            client_name: Client name
            tester_name: Tester name
        """
        self.report_gen = ReportGenerator(
            engagement_name=engagement_name,
            client_name=client_name,
            tester_name=tester_name
        )

        self.ioc_extractor = IOCExtractor()
        self.timeline = Timeline()
        self.cleanup = Cleanup(verbose=False)

    def import_phase_results(self, phase_file: str, phase_name: str):
        """
        Import results from a phase.

        Args:
            phase_file: JSON results file
            phase_name: Phase name
        """
        try:
            with open(phase_file) as f:
                data = json.load(f)

            # Extract findings, IOCs, timeline events based on phase
            # This is a simplified version - real implementation would
            # parse specific phase result formats

            print(f"[+] Imported results from: {phase_file}")

        except Exception as e:
            print(f"[-] Error importing {phase_file}: {e}")

    def add_phase1_results(self, targets_found: List[Dict]):
        """
        Add Phase 1 (Reconnaissance) results.

        Args:
            targets_found: List of discovered targets
        """
        # Add targets
        for target_data in targets_found:
            self.report_gen.add_target(
                hostname=target_data.get('hostname', 'Unknown'),
                ip_address=target_data['ip'],
                os_type=target_data.get('os_type'),
                services=target_data.get('services', [])
            )

            # Add IOCs
            self.ioc_extractor.add_ioc(
                ioc_type='ip_address',
                value=target_data['ip'],
                description='Target discovered during reconnaissance',
                source='Phase 1: Reconnaissance'
            )

            # Add timeline event
            self.timeline.add_event(
                phase='Phase 1',
                event_type='Target Discovery',
                description=f"Discovered target {target_data['ip']}",
                target=target_data['ip'],
                severity='info'
            )

    def add_phase2_results(self, vulnerabilities: List[Dict]):
        """
        Add Phase 2 (Initial Access) results.

        Args:
            vulnerabilities: List of vulnerabilities exploited
        """
        for vuln in vulnerabilities:
            # Add finding
            self.report_gen.add_finding(
                title=vuln['title'],
                severity=vuln.get('severity', 'high'),
                phase='Phase 2: Initial Access',
                description=vuln['description'],
                evidence=vuln.get('evidence', ''),
                impact=vuln.get('impact', ''),
                remediation=vuln.get('remediation', ''),
                mitre_attack=vuln.get('mitre_attack', [])
            )

            # Add timeline event
            self.timeline.add_event(
                phase='Phase 2',
                event_type='Vulnerability Exploitation',
                description=vuln['title'],
                target=vuln.get('target'),
                severity=vuln.get('severity', 'high'),
                success=True
            )

    def add_phase3_results(self, persistence_mechanisms: List[Dict], privesc_vectors: List[Dict]):
        """
        Add Phase 3 (Persistence & Privilege Escalation) results.

        Args:
            persistence_mechanisms: List of persistence mechanisms
            privesc_vectors: List of privilege escalation vectors
        """
        for mechanism in persistence_mechanisms:
            # Add IOC
            self.ioc_extractor.add_persistence_mechanism(
                mechanism_type=mechanism['type'],
                value=mechanism['value'],
                description=mechanism['description']
            )

            # Add timeline event
            self.timeline.add_event(
                phase='Phase 3',
                event_type='Persistence Established',
                description=f"{mechanism['type']}: {mechanism['value']}",
                severity='high'
            )

        for vector in privesc_vectors:
            # Add finding
            self.report_gen.add_finding(
                title=f"Privilege Escalation: {vector['vector_type']}",
                severity=vector['severity'],
                phase='Phase 3: Persistence & Privilege Escalation',
                description=vector['description'],
                evidence=vector.get('details', ''),
                impact='Attacker can escalate to higher privileges',
                remediation='Review and remediate privilege escalation vectors',
                mitre_attack=['T1068']
            )

    def add_phase4_results(self, compromised_hosts: List[str]):
        """
        Add Phase 4 (Lateral Movement) results.

        Args:
            compromised_hosts: List of compromised host IPs
        """
        for host in compromised_hosts:
            # Update target as compromised
            for target in self.report_gen.targets:
                if target.ip_address == host:
                    target.compromised = True
                    target.access_level = 'SYSTEM/root'

            # Add finding
            self.report_gen.add_finding(
                title=f'Lateral Movement to {host}',
                severity='critical',
                phase='Phase 4: Lateral Movement',
                description=f'Successfully moved laterally to host {host}',
                evidence='SMB/WMI access achieved',
                impact='Multiple systems compromised',
                remediation='Implement network segmentation and monitoring',
                mitre_attack=['T1021.002', 'T1047']
            )

            # Add timeline event
            self.timeline.add_event(
                phase='Phase 4',
                event_type='Lateral Movement',
                description=f'Compromised host {host}',
                target=host,
                severity='critical'
            )

    def add_phase5_results(self, exfiltrated_data: Dict):
        """
        Add Phase 5 (Data Exfiltration) results.

        Args:
            exfiltrated_data: Exfiltration statistics
        """
        # Add finding
        self.report_gen.add_finding(
            title='Data Exfiltration',
            severity='critical',
            phase='Phase 5: Data Exfiltration',
            description=f"Exfiltrated {exfiltrated_data.get('files_exfiltrated', 0)} files "
                       f"({exfiltrated_data.get('bytes_exfiltrated', 0) / (1024*1024):.2f} MB)",
            evidence=f"Method: {exfiltrated_data.get('exfil_method', 'HTTP')}",
            impact='Sensitive data compromised',
            remediation='Implement DLP and egress filtering',
            mitre_attack=['T1020', 'T1041']
        )

        # Add IOC for C2/exfil server
        if 'exfil_url' in exfiltrated_data:
            self.ioc_extractor.add_c2_server(
                url=exfiltrated_data['exfil_url'],
                description='Data exfiltration server'
            )

        # Add timeline event
        self.timeline.add_event(
            phase='Phase 5',
            event_type='Data Exfiltration',
            description=f"Exfiltrated {exfiltrated_data.get('files_exfiltrated', 0)} files",
            severity='critical'
        )

    def generate_comprehensive_report(self) -> str:
        """
        Generate comprehensive penetration testing report.

        Returns:
            Complete report string
        """
        sections = []

        # Main report
        sections.append(self.report_gen.generate_text_report())

        # Timeline
        sections.append("\n\n")
        sections.append(self.timeline.generate_ascii_timeline())

        # Attack chain summary
        sections.append("\n\n")
        sections.append(self.timeline.generate_attack_chain_summary())

        # IOC Report
        sections.append("\n\n")
        sections.append(self.ioc_extractor.generate_report())

        return "\n".join(sections)

    def export_all(self, base_filename: str):
        """
        Export all reports to files.

        Args:
            base_filename: Base filename (without extension)
        """
        # Main report (text)
        report_file = f"{base_filename}_report.txt"
        comprehensive = self.generate_comprehensive_report()

        with open(report_file, 'w') as f:
            f.write(comprehensive)

        print(f"[+] Report written to: {report_file}")

        # JSON exports
        self.report_gen.export_json(f"{base_filename}_findings.json")
        self.ioc_extractor.export_json(f"{base_filename}_iocs.json")
        self.timeline.export_json(f"{base_filename}_timeline.json")

        # IOC exports
        self.ioc_extractor.export_csv(f"{base_filename}_iocs.csv")
        self.ioc_extractor.export_stix(f"{base_filename}_iocs_stix.json")

        print(f"[+] All reports exported with base name: {base_filename}")


def main():
    """Main function for standalone usage."""
    import argparse

    parser = argparse.ArgumentParser(description='RedCell Automated Reporter')

    parser.add_argument('--engagement', required=True, help='Engagement name')
    parser.add_argument('--client', required=True, help='Client name')
    parser.add_argument('--tester', default='RedCell Security Team', help='Tester name')

    parser.add_argument('--output', required=True, help='Output base filename')

    args = parser.parse_args()

    # Initialize reporter
    reporter = AutomatedReporter(
        engagement_name=args.engagement,
        client_name=args.client,
        tester_name=args.tester
    )

    # Set dates
    reporter.report_gen.set_dates(
        start_date=datetime.now().strftime('%Y-%m-%d'),
        end_date=datetime.now().strftime('%Y-%m-%d')
    )

    # Set scope and methodology
    reporter.report_gen.add_scope_item('Internal network assessment')
    reporter.report_gen.add_methodology_item('Black-box penetration testing')
    reporter.report_gen.add_tool('RedCell Advanced Red Team Operations Framework')

    # Generate and export all reports
    reporter.export_all(args.output)

    print("\n[+] Automated reporting complete!")


if __name__ == '__main__':
    main()
