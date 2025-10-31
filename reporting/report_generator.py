"""
Comprehensive Report Generator

Generate professional penetration testing reports from all phases.
"""

import json
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
import os


@dataclass
class Finding:
    """Represents a security finding."""

    title: str
    severity: str  # critical, high, medium, low, info
    phase: str
    description: str
    evidence: str
    impact: str
    remediation: str
    mitre_attack: List[str] = None
    cve: Optional[str] = None

    def __post_init__(self):
        if self.mitre_attack is None:
            self.mitre_attack = []

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class Target:
    """Represents a target system."""

    hostname: str
    ip_address: str
    os_type: Optional[str] = None
    services: List[str] = None
    compromised: bool = False
    access_level: Optional[str] = None

    def __post_init__(self):
        if self.services is None:
            self.services = []

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return asdict(self)


class ReportGenerator:
    """
    Comprehensive penetration testing report generator.

    Features:
    - Executive summary
    - Technical findings
    - Attack chain timeline
    - MITRE ATT&CK mapping
    - Remediation recommendations
    - Multiple output formats (text, HTML, JSON)
    """

    SEVERITY_ORDER = {
        'critical': 5,
        'high': 4,
        'medium': 3,
        'low': 2,
        'info': 1
    }

    def __init__(
        self,
        engagement_name: str,
        client_name: str,
        tester_name: str = "RedCell Security Team"
    ):
        """
        Initialize report generator.

        Args:
            engagement_name: Name of the engagement
            client_name: Client organization name
            tester_name: Name of tester/team
        """
        self.engagement_name = engagement_name
        self.client_name = client_name
        self.tester_name = tester_name

        self.start_date = datetime.now().strftime('%Y-%m-%d')
        self.end_date = datetime.now().strftime('%Y-%m-%d')

        self.findings: List[Finding] = []
        self.targets: List[Target] = []
        self.executive_summary = ""
        self.scope = []
        self.methodology = []
        self.tools_used = []

    def add_finding(
        self,
        title: str,
        severity: str,
        phase: str,
        description: str,
        evidence: str,
        impact: str,
        remediation: str,
        mitre_attack: List[str] = None,
        cve: str = None
    ):
        """
        Add a finding to the report.

        Args:
            title: Finding title
            severity: Severity level
            phase: RedCell phase
            description: Detailed description
            evidence: Evidence/proof
            impact: Business impact
            remediation: Remediation steps
            mitre_attack: MITRE ATT&CK technique IDs
            cve: CVE identifier (if applicable)
        """
        finding = Finding(
            title=title,
            severity=severity,
            phase=phase,
            description=description,
            evidence=evidence,
            impact=impact,
            remediation=remediation,
            mitre_attack=mitre_attack or [],
            cve=cve
        )

        self.findings.append(finding)

    def add_target(
        self,
        hostname: str,
        ip_address: str,
        os_type: str = None,
        services: List[str] = None,
        compromised: bool = False,
        access_level: str = None
    ):
        """
        Add a target system to the report.

        Args:
            hostname: Target hostname
            ip_address: Target IP address
            os_type: Operating system
            services: List of discovered services
            compromised: Whether target was compromised
            access_level: Level of access achieved
        """
        target = Target(
            hostname=hostname,
            ip_address=ip_address,
            os_type=os_type,
            services=services or [],
            compromised=compromised,
            access_level=access_level
        )

        self.targets.append(target)

    def set_executive_summary(self, summary: str):
        """Set executive summary text."""
        self.executive_summary = summary

    def set_dates(self, start_date: str, end_date: str):
        """Set engagement dates."""
        self.start_date = start_date
        self.end_date = end_date

    def add_scope_item(self, item: str):
        """Add item to engagement scope."""
        self.scope.append(item)

    def add_methodology_item(self, item: str):
        """Add item to testing methodology."""
        self.methodology.append(item)

    def add_tool(self, tool: str):
        """Add tool to tools used list."""
        if tool not in self.tools_used:
            self.tools_used.append(tool)

    def get_findings_by_severity(self, severity: str) -> List[Finding]:
        """Get findings by severity level."""
        return [f for f in self.findings if f.severity == severity]

    def get_compromised_targets(self) -> List[Target]:
        """Get list of compromised targets."""
        return [t for t in self.targets if t.compromised]

    def get_mitre_attack_coverage(self) -> Dict:
        """Get MITRE ATT&CK technique coverage."""
        techniques = {}

        for finding in self.findings:
            for technique in finding.mitre_attack:
                if technique not in techniques:
                    techniques[technique] = []
                techniques[technique].append(finding.title)

        return techniques

    def generate_text_report(self) -> str:
        """
        Generate text-based penetration testing report.

        Returns:
            Formatted text report
        """
        report = []

        # Header
        report.append("=" * 100)
        report.append(f"PENETRATION TESTING REPORT")
        report.append("=" * 100)
        report.append(f"\nEngagement: {self.engagement_name}")
        report.append(f"Client: {self.client_name}")
        report.append(f"Tester: {self.tester_name}")
        report.append(f"Date Range: {self.start_date} to {self.end_date}")
        report.append(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        # Table of Contents
        report.append("\n" + "=" * 100)
        report.append("TABLE OF CONTENTS")
        report.append("=" * 100)
        report.append("\n1. Executive Summary")
        report.append("2. Scope")
        report.append("3. Methodology")
        report.append("4. Targets")
        report.append("5. Findings Summary")
        report.append("6. Detailed Findings")
        report.append("7. MITRE ATT&CK Mapping")
        report.append("8. Recommendations")
        report.append("9. Tools Used")

        # Executive Summary
        report.append("\n" + "=" * 100)
        report.append("1. EXECUTIVE SUMMARY")
        report.append("=" * 100)

        if self.executive_summary:
            report.append(f"\n{self.executive_summary}")
        else:
            # Auto-generate summary
            critical = len(self.get_findings_by_severity('critical'))
            high = len(self.get_findings_by_severity('high'))
            medium = len(self.get_findings_by_severity('medium'))
            low = len(self.get_findings_by_severity('low'))

            compromised = len(self.get_compromised_targets())
            total_targets = len(self.targets)

            report.append(f"\nThis penetration test was conducted against {total_targets} target(s) ")
            report.append(f"for {self.client_name}. The assessment identified {len(self.findings)} ")
            report.append(f"security findings, including {critical} critical, {high} high, {medium} medium, ")
            report.append(f"and {low} low severity issues.")

            if compromised > 0:
                report.append(f"\n\n{compromised} of {total_targets} targets were successfully compromised ")
                report.append(f"during the assessment, demonstrating significant security weaknesses that ")
                report.append(f"require immediate attention.")

        # Scope
        report.append("\n" + "=" * 100)
        report.append("2. SCOPE")
        report.append("=" * 100)

        if self.scope:
            for item in self.scope:
                report.append(f"\n  • {item}")
        else:
            report.append("\n  [Scope not specified]")

        # Methodology
        report.append("\n" + "=" * 100)
        report.append("3. METHODOLOGY")
        report.append("=" * 100)

        if self.methodology:
            for item in self.methodology:
                report.append(f"\n  • {item}")
        else:
            # Default methodology
            report.append("\n  • Phase 1: Reconnaissance and Information Gathering")
            report.append("  • Phase 2: Vulnerability Identification and Exploitation")
            report.append("  • Phase 3: Post-Exploitation and Privilege Escalation")
            report.append("  • Phase 4: Lateral Movement")
            report.append("  • Phase 5: Data Exfiltration")
            report.append("  • Phase 6: Reporting and Cleanup")

        # Targets
        report.append("\n" + "=" * 100)
        report.append("4. TARGETS")
        report.append("=" * 100)

        if self.targets:
            for i, target in enumerate(self.targets, 1):
                report.append(f"\n[{i}] {target.hostname} ({target.ip_address})")
                if target.os_type:
                    report.append(f"    OS: {target.os_type}")
                if target.services:
                    report.append(f"    Services: {', '.join(target.services)}")
                if target.compromised:
                    report.append(f"    Status: COMPROMISED")
                    if target.access_level:
                        report.append(f"    Access Level: {target.access_level}")
                else:
                    report.append(f"    Status: Not compromised")
        else:
            report.append("\n  [No targets specified]")

        # Findings Summary
        report.append("\n" + "=" * 100)
        report.append("5. FINDINGS SUMMARY")
        report.append("=" * 100)

        critical = len(self.get_findings_by_severity('critical'))
        high = len(self.get_findings_by_severity('high'))
        medium = len(self.get_findings_by_severity('medium'))
        low = len(self.get_findings_by_severity('low'))
        info = len(self.get_findings_by_severity('info'))

        report.append(f"\nTotal Findings: {len(self.findings)}")
        report.append(f"\n  CRITICAL: {critical}")
        report.append(f"  HIGH:     {high}")
        report.append(f"  MEDIUM:   {medium}")
        report.append(f"  LOW:      {low}")
        report.append(f"  INFO:     {info}")

        # Detailed Findings
        report.append("\n" + "=" * 100)
        report.append("6. DETAILED FINDINGS")
        report.append("=" * 100)

        # Sort findings by severity
        sorted_findings = sorted(
            self.findings,
            key=lambda f: self.SEVERITY_ORDER.get(f.severity, 0),
            reverse=True
        )

        for i, finding in enumerate(sorted_findings, 1):
            report.append(f"\n{'-' * 100}")
            report.append(f"Finding {i}: {finding.title}")
            report.append(f"{'-' * 100}")
            report.append(f"\nSeverity: {finding.severity.upper()}")
            report.append(f"Phase: {finding.phase}")

            if finding.cve:
                report.append(f"CVE: {finding.cve}")

            report.append(f"\nDescription:")
            report.append(f"{finding.description}")

            report.append(f"\nEvidence:")
            report.append(f"{finding.evidence}")

            report.append(f"\nImpact:")
            report.append(f"{finding.impact}")

            report.append(f"\nRemediation:")
            report.append(f"{finding.remediation}")

            if finding.mitre_attack:
                report.append(f"\nMITRE ATT&CK Techniques:")
                for technique in finding.mitre_attack:
                    report.append(f"  • {technique}")

        # MITRE ATT&CK Mapping
        report.append("\n" + "=" * 100)
        report.append("7. MITRE ATT&CK MAPPING")
        report.append("=" * 100)

        mitre_coverage = self.get_mitre_attack_coverage()

        if mitre_coverage:
            report.append(f"\nTotal Techniques Used: {len(mitre_coverage)}")
            for technique, findings in sorted(mitre_coverage.items()):
                report.append(f"\n{technique}:")
                for finding_title in findings:
                    report.append(f"  • {finding_title}")
        else:
            report.append("\n  [No MITRE ATT&CK techniques mapped]")

        # Recommendations
        report.append("\n" + "=" * 100)
        report.append("8. RECOMMENDATIONS")
        report.append("=" * 100)

        report.append("\nPriority Recommendations:")
        report.append("\n1. Address all CRITICAL severity findings immediately")
        report.append("2. Implement defense-in-depth security controls")
        report.append("3. Conduct regular security assessments")
        report.append("4. Implement security awareness training")
        report.append("5. Deploy endpoint detection and response (EDR) solutions")
        report.append("6. Implement network segmentation")
        report.append("7. Enable multi-factor authentication (MFA)")
        report.append("8. Implement least-privilege access controls")

        # Tools Used
        report.append("\n" + "=" * 100)
        report.append("9. TOOLS USED")
        report.append("=" * 100)

        if self.tools_used:
            for tool in self.tools_used:
                report.append(f"\n  • {tool}")
        else:
            report.append("\n  • RedCell Advanced Red Team Operations Framework")

        report.append("\n" + "=" * 100)
        report.append("END OF REPORT")
        report.append("=" * 100)

        return "\n".join(report)

    def export_json(self, filename: str):
        """
        Export report data to JSON.

        Args:
            filename: Output filename
        """
        data = {
            'engagement_name': self.engagement_name,
            'client_name': self.client_name,
            'tester_name': self.tester_name,
            'start_date': self.start_date,
            'end_date': self.end_date,
            'executive_summary': self.executive_summary,
            'scope': self.scope,
            'methodology': self.methodology,
            'tools_used': self.tools_used,
            'targets': [t.to_dict() for t in self.targets],
            'findings': [f.to_dict() for f in self.findings],
            'statistics': {
                'total_findings': len(self.findings),
                'critical': len(self.get_findings_by_severity('critical')),
                'high': len(self.get_findings_by_severity('high')),
                'medium': len(self.get_findings_by_severity('medium')),
                'low': len(self.get_findings_by_severity('low')),
                'info': len(self.get_findings_by_severity('info')),
                'targets_compromised': len(self.get_compromised_targets()),
                'total_targets': len(self.targets)
            },
            'mitre_attack_coverage': self.get_mitre_attack_coverage()
        }

        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)

        print(f"[+] Report exported to JSON: {filename}")

    def import_json(self, filename: str):
        """
        Import report data from JSON.

        Args:
            filename: Input filename
        """
        with open(filename) as f:
            data = json.load(f)

        self.engagement_name = data.get('engagement_name', '')
        self.client_name = data.get('client_name', '')
        self.tester_name = data.get('tester_name', '')
        self.start_date = data.get('start_date', '')
        self.end_date = data.get('end_date', '')
        self.executive_summary = data.get('executive_summary', '')
        self.scope = data.get('scope', [])
        self.methodology = data.get('methodology', [])
        self.tools_used = data.get('tools_used', [])

        # Import targets
        for target_data in data.get('targets', []):
            self.targets.append(Target(**target_data))

        # Import findings
        for finding_data in data.get('findings', []):
            self.findings.append(Finding(**finding_data))

        print(f"[+] Report imported from JSON: {filename}")


def main():
    """Main function for standalone usage."""
    import argparse

    parser = argparse.ArgumentParser(description='RedCell Report Generator')

    parser.add_argument('--engagement', required=True, help='Engagement name')
    parser.add_argument('--client', required=True, help='Client name')
    parser.add_argument('--tester', default='RedCell Security Team', help='Tester name')

    parser.add_argument('--import-json', help='Import data from JSON file')
    parser.add_argument('--export-json', help='Export report to JSON')
    parser.add_argument('--output', help='Output text report file')

    parser.add_argument('--start-date', help='Start date (YYYY-MM-DD)')
    parser.add_argument('--end-date', help='End date (YYYY-MM-DD)')

    args = parser.parse_args()

    # Initialize report
    report = ReportGenerator(
        engagement_name=args.engagement,
        client_name=args.client,
        tester_name=args.tester
    )

    if args.start_date and args.end_date:
        report.set_dates(args.start_date, args.end_date)

    # Import data if specified
    if args.import_json:
        report.import_json(args.import_json)

    # Generate text report
    text_report = report.generate_text_report()

    # Output to file or stdout
    if args.output:
        with open(args.output, 'w') as f:
            f.write(text_report)
        print(f"[+] Report written to: {args.output}")
    else:
        print(text_report)

    # Export JSON if specified
    if args.export_json:
        report.export_json(args.export_json)


if __name__ == '__main__':
    main()
