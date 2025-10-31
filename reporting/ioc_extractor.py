"""
IOC (Indicator of Compromise) Extractor

Extract and document IOCs from operations for defensive analysis.
"""

import re
import json
from typing import Dict, List, Set
from dataclasses import dataclass, asdict
from pathlib import Path


@dataclass
class IOC:
    """Represents an Indicator of Compromise."""

    ioc_type: str  # ip, domain, hash, file_path, registry_key, etc.
    value: str
    description: str
    source: str  # Where this IOC came from
    severity: str = "medium"  # low, medium, high, critical

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return asdict(self)


class IOCExtractor:
    """
    Extract IOCs from penetration testing operations.

    IOC Types:
    - IP addresses
    - Domain names
    - File hashes (MD5, SHA1, SHA256)
    - File paths
    - Registry keys
    - URLs
    - Email addresses
    - User agents
    """

    # Regex patterns
    IP_PATTERN = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    DOMAIN_PATTERN = r'\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}\b'
    URL_PATTERN = r'https?://[^\s<>"{}|\\^`\[\]]+'
    EMAIL_PATTERN = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    MD5_PATTERN = r'\b[a-fA-F0-9]{32}\b'
    SHA1_PATTERN = r'\b[a-fA-F0-9]{40}\b'
    SHA256_PATTERN = r'\b[a-fA-F0-9]{64}\b'

    def __init__(self):
        """Initialize IOC extractor."""
        self.iocs: List[IOC] = []
        self.seen_values: Set[str] = set()

    def add_ioc(
        self,
        ioc_type: str,
        value: str,
        description: str,
        source: str,
        severity: str = "medium"
    ):
        """
        Add an IOC.

        Args:
            ioc_type: Type of IOC
            value: IOC value
            description: Description
            source: Source of IOC
            severity: Severity level
        """
        # Avoid duplicates
        if value in self.seen_values:
            return

        ioc = IOC(
            ioc_type=ioc_type,
            value=value,
            description=description,
            source=source,
            severity=severity
        )

        self.iocs.append(ioc)
        self.seen_values.add(value)

    def extract_from_text(self, text: str, source: str = "text_analysis"):
        """
        Extract IOCs from text.

        Args:
            text: Text to analyze
            source: Source identifier
        """
        # Extract IPs
        ips = re.findall(self.IP_PATTERN, text)
        for ip in ips:
            # Skip common non-routable IPs
            if not ip.startswith(('127.', '0.', '255.')):
                self.add_ioc(
                    ioc_type='ip_address',
                    value=ip,
                    description=f'IP address found in {source}',
                    source=source,
                    severity='medium'
                )

        # Extract domains
        domains = re.findall(self.DOMAIN_PATTERN, text)
        for domain in domains:
            # Skip common false positives
            if not domain.endswith(('.com', '.net', '.org', '.io', '.local', '.internal')):
                continue
            self.add_ioc(
                ioc_type='domain',
                value=domain,
                description=f'Domain found in {source}',
                source=source,
                severity='medium'
            )

        # Extract URLs
        urls = re.findall(self.URL_PATTERN, text)
        for url in urls:
            self.add_ioc(
                ioc_type='url',
                value=url,
                description=f'URL found in {source}',
                source=source,
                severity='low'
            )

        # Extract email addresses
        emails = re.findall(self.EMAIL_PATTERN, text)
        for email in emails:
            self.add_ioc(
                ioc_type='email',
                value=email,
                description=f'Email address found in {source}',
                source=source,
                severity='low'
            )

        # Extract hashes
        md5s = re.findall(self.MD5_PATTERN, text)
        for md5 in md5s:
            self.add_ioc(
                ioc_type='hash_md5',
                value=md5,
                description=f'MD5 hash found in {source}',
                source=source,
                severity='high'
            )

        sha1s = re.findall(self.SHA1_PATTERN, text)
        for sha1 in sha1s:
            self.add_ioc(
                ioc_type='hash_sha1',
                value=sha1,
                description=f'SHA1 hash found in {source}',
                source=source,
                severity='high'
            )

        sha256s = re.findall(self.SHA256_PATTERN, text)
        for sha256 in sha256s:
            self.add_ioc(
                ioc_type='hash_sha256',
                value=sha256,
                description=f'SHA256 hash found in {source}',
                source=source,
                severity='high'
            )

    def extract_from_file(self, file_path: str):
        """
        Extract IOCs from file.

        Args:
            file_path: Path to file
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            source = f"file:{Path(file_path).name}"
            self.extract_from_text(content, source=source)

        except Exception as e:
            print(f"[-] Error reading {file_path}: {e}")

    def add_c2_server(self, url: str, description: str = "C2 server"):
        """
        Add C2 server IOC.

        Args:
            url: C2 server URL
            description: Description
        """
        self.add_ioc(
            ioc_type='c2_server',
            value=url,
            description=description,
            source='c2_infrastructure',
            severity='critical'
        )

    def add_implant(
        self,
        file_path: str,
        file_hash: str = None,
        description: str = "Implant/payload"
    ):
        """
        Add implant IOC.

        Args:
            file_path: File path
            file_hash: File hash (if known)
            description: Description
        """
        self.add_ioc(
            ioc_type='file_path',
            value=file_path,
            description=description,
            source='implant_deployment',
            severity='critical'
        )

        if file_hash:
            self.add_ioc(
                ioc_type='hash_sha256',
                value=file_hash,
                description=f'Hash of {description}',
                source='implant_deployment',
                severity='critical'
            )

    def add_persistence_mechanism(
        self,
        mechanism_type: str,
        value: str,
        description: str
    ):
        """
        Add persistence mechanism IOC.

        Args:
            mechanism_type: Type (registry_key, scheduled_task, service, etc.)
            value: Value
            description: Description
        """
        self.add_ioc(
            ioc_type=mechanism_type,
            value=value,
            description=description,
            source='persistence',
            severity='high'
        )

    def add_credential(
        self,
        username: str,
        credential_type: str = "username",
        description: str = "Compromised credential"
    ):
        """
        Add credential IOC.

        Args:
            username: Username
            credential_type: Type of credential
            description: Description
        """
        self.add_ioc(
            ioc_type=credential_type,
            value=username,
            description=description,
            source='credential_harvesting',
            severity='high'
        )

    def add_network_activity(
        self,
        protocol: str,
        details: str,
        description: str
    ):
        """
        Add network activity IOC.

        Args:
            protocol: Protocol (SMB, WMI, DNS, HTTP, etc.)
            details: Activity details
            description: Description
        """
        self.add_ioc(
            ioc_type=f'network_{protocol.lower()}',
            value=details,
            description=description,
            source='network_activity',
            severity='medium'
        )

    def get_by_type(self, ioc_type: str) -> List[IOC]:
        """
        Get IOCs by type.

        Args:
            ioc_type: IOC type

        Returns:
            List of matching IOCs
        """
        return [ioc for ioc in self.iocs if ioc.ioc_type == ioc_type]

    def get_by_severity(self, severity: str) -> List[IOC]:
        """
        Get IOCs by severity.

        Args:
            severity: Severity level

        Returns:
            List of matching IOCs
        """
        return [ioc for ioc in self.iocs if ioc.severity == severity]

    def generate_report(self) -> str:
        """
        Generate IOC report.

        Returns:
            Formatted report
        """
        report = []
        report.append("=" * 80)
        report.append("INDICATORS OF COMPROMISE (IOC) REPORT")
        report.append("=" * 80)

        # Summary
        report.append(f"\nTotal IOCs: {len(self.iocs)}")

        # By type
        types = {}
        for ioc in self.iocs:
            types[ioc.ioc_type] = types.get(ioc.ioc_type, 0) + 1

        report.append("\nBy Type:")
        for ioc_type, count in sorted(types.items(), key=lambda x: x[1], reverse=True):
            report.append(f"  {ioc_type}: {count}")

        # By severity
        severities = {}
        for ioc in self.iocs:
            severities[ioc.severity] = severities.get(ioc.severity, 0) + 1

        report.append("\nBy Severity:")
        for severity in ['critical', 'high', 'medium', 'low']:
            count = severities.get(severity, 0)
            if count > 0:
                report.append(f"  {severity.upper()}: {count}")

        # Detailed IOCs
        report.append("\n" + "=" * 80)
        report.append("DETAILED IOCs")
        report.append("=" * 80)

        # Group by severity
        for severity in ['critical', 'high', 'medium', 'low']:
            iocs_by_severity = self.get_by_severity(severity)

            if iocs_by_severity:
                report.append(f"\n{severity.upper()} Severity:")
                report.append("-" * 80)

                for ioc in iocs_by_severity:
                    report.append(f"\nType: {ioc.ioc_type}")
                    report.append(f"Value: {ioc.value}")
                    report.append(f"Description: {ioc.description}")
                    report.append(f"Source: {ioc.source}")

        report.append("\n" + "=" * 80)
        return "\n".join(report)

    def export_json(self, filename: str):
        """
        Export IOCs to JSON.

        Args:
            filename: Output filename
        """
        data = {
            'total_iocs': len(self.iocs),
            'iocs': [ioc.to_dict() for ioc in self.iocs]
        }

        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)

        print(f"[+] IOCs exported to JSON: {filename}")

    def export_csv(self, filename: str):
        """
        Export IOCs to CSV.

        Args:
            filename: Output filename
        """
        import csv

        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)

            # Header
            writer.writerow(['Type', 'Value', 'Description', 'Source', 'Severity'])

            # Data
            for ioc in self.iocs:
                writer.writerow([
                    ioc.ioc_type,
                    ioc.value,
                    ioc.description,
                    ioc.source,
                    ioc.severity
                ])

        print(f"[+] IOCs exported to CSV: {filename}")

    def export_stix(self, filename: str):
        """
        Export IOCs to STIX format (simplified).

        Args:
            filename: Output filename
        """
        # Simplified STIX-like format
        stix_data = {
            'type': 'bundle',
            'id': 'bundle--' + 'redcell-iocs',
            'objects': []
        }

        for ioc in self.iocs:
            obj = {
                'type': 'indicator',
                'pattern': f"[{ioc.ioc_type}:value = '{ioc.value}']",
                'description': ioc.description,
                'labels': [ioc.severity, ioc.source]
            }
            stix_data['objects'].append(obj)

        with open(filename, 'w') as f:
            json.dump(stix_data, f, indent=2)

        print(f"[+] IOCs exported to STIX: {filename}")


def main():
    """Main function for standalone usage."""
    import argparse

    parser = argparse.ArgumentParser(description='RedCell IOC Extractor')

    parser.add_argument('--file', help='Extract IOCs from file')
    parser.add_argument('--text', help='Extract IOCs from text')

    parser.add_argument('--export-json', help='Export to JSON')
    parser.add_argument('--export-csv', help='Export to CSV')
    parser.add_argument('--export-stix', help='Export to STIX')

    args = parser.parse_args()

    extractor = IOCExtractor()

    # Extract from file
    if args.file:
        extractor.extract_from_file(args.file)

    # Extract from text
    if args.text:
        extractor.extract_from_text(args.text, source='command_line')

    # Generate report
    print(extractor.generate_report())

    # Export
    if args.export_json:
        extractor.export_json(args.export_json)

    if args.export_csv:
        extractor.export_csv(args.export_csv)

    if args.export_stix:
        extractor.export_stix(args.export_stix)


if __name__ == '__main__':
    main()
