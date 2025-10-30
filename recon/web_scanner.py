"""
Web Application Scanner Module

Automated vulnerability scanning for web applications.
"""

import requests
import re
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, asdict
from urllib.parse import urljoin, urlparse
import time


@dataclass
class Vulnerability:
    """Represents a discovered vulnerability."""
    vuln_type: str
    severity: str  # 'critical', 'high', 'medium', 'low', 'info'
    url: str
    parameter: Optional[str] = None
    payload: Optional[str] = None
    evidence: Optional[str] = None
    description: Optional[str] = None

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return asdict(self)


class WebScanner:
    """
    Web application vulnerability scanner.

    Detects:
    - SQL Injection indicators
    - Command Injection indicators
    - File Upload vulnerabilities
    - SSTI (Server-Side Template Injection)
    - XSS (Cross-Site Scripting)
    - Directory traversal
    """

    # SQL Injection test payloads
    SQLI_PAYLOADS = [
        "' OR '1'='1",
        "' OR 1=1--",
        "admin' --",
        "' UNION SELECT NULL--",
        "1' AND '1'='1",
    ]

    # SQL error patterns
    SQL_ERRORS = [
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_.*",
        r"MySQLSyntaxErrorException",
        r"valid MySQL result",
        r"PostgreSQL.*ERROR",
        r"Warning.*pg_.*",
        r"valid PostgreSQL result",
        r"SQLite.*error",
        r"ORA-[0-9][0-9][0-9][0-9]",
        r"Microsoft SQL Server",
    ]

    # Command injection payloads
    CMD_PAYLOADS = [
        "; ls",
        "| whoami",
        "`id`",
        "$(whoami)",
        "; ping -c 1 127.0.0.1",
    ]

    # Command execution patterns
    CMD_PATTERNS = [
        r"uid=\d+\(",  # Unix id output
        r"root:",       # /etc/passwd
        r"bin/bash",    # Shell paths
        r"Windows.*Version",  # Windows ver
    ]

    # SSTI payloads
    SSTI_PAYLOADS = [
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "#{7*7}",
    ]

    # XSS payloads
    XSS_PAYLOADS = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
    ]

    def __init__(self, timeout: int = 10, user_agent: Optional[str] = None):
        """
        Initialize web scanner.

        Args:
            timeout: Request timeout in seconds
            user_agent: Custom user agent string
        """
        self.timeout = timeout
        self.user_agent = user_agent or "RedCell-WebScanner/1.0"
        self.vulnerabilities = []
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': self.user_agent})

    def test_sqli(self, url: str, params: Optional[Dict] = None) -> List[Vulnerability]:
        """
        Test for SQL injection vulnerabilities.

        Args:
            url: Target URL
            params: GET/POST parameters to test

        Returns:
            List of discovered vulnerabilities
        """
        vulns = []

        if not params:
            params = {'id': '1'}  # Default test parameter

        for param_name in params.keys():
            for payload in self.SQLI_PAYLOADS:
                test_params = params.copy()
                test_params[param_name] = payload

                try:
                    # Test GET request
                    response = self.session.get(
                        url,
                        params=test_params,
                        timeout=self.timeout,
                        allow_redirects=False
                    )

                    # Check for SQL errors in response
                    for error_pattern in self.SQL_ERRORS:
                        if re.search(error_pattern, response.text, re.IGNORECASE):
                            vulns.append(Vulnerability(
                                vuln_type='SQL Injection',
                                severity='critical',
                                url=url,
                                parameter=param_name,
                                payload=payload,
                                evidence=f"SQL error pattern: {error_pattern}",
                                description=f"SQL injection vulnerability detected in parameter '{param_name}'"
                            ))
                            break

                except requests.exceptions.RequestException:
                    pass

                time.sleep(0.1)  # Rate limiting

        return vulns

    def test_command_injection(self, url: str, params: Optional[Dict] = None) -> List[Vulnerability]:
        """
        Test for command injection vulnerabilities.

        Args:
            url: Target URL
            params: GET/POST parameters to test

        Returns:
            List of discovered vulnerabilities
        """
        vulns = []

        if not params:
            params = {'cmd': 'test'}

        for param_name in params.keys():
            for payload in self.CMD_PAYLOADS:
                test_params = params.copy()
                test_params[param_name] = payload

                try:
                    response = self.session.post(
                        url,
                        data=test_params,
                        timeout=self.timeout
                    )

                    # Check for command execution evidence
                    for pattern in self.CMD_PATTERNS:
                        if re.search(pattern, response.text):
                            vulns.append(Vulnerability(
                                vuln_type='Command Injection',
                                severity='critical',
                                url=url,
                                parameter=param_name,
                                payload=payload,
                                evidence=f"Command output pattern: {pattern}",
                                description=f"Command injection vulnerability in parameter '{param_name}'"
                            ))
                            break

                except requests.exceptions.RequestException:
                    pass

                time.sleep(0.1)

        return vulns

    def test_ssti(self, url: str, params: Optional[Dict] = None) -> List[Vulnerability]:
        """
        Test for Server-Side Template Injection.

        Args:
            url: Target URL
            params: GET/POST parameters to test

        Returns:
            List of discovered vulnerabilities
        """
        vulns = []

        if not params:
            params = {'q': 'test'}

        for param_name in params.keys():
            for payload in self.SSTI_PAYLOADS:
                test_params = params.copy()
                test_params[param_name] = payload

                try:
                    response = self.session.get(
                        url,
                        params=test_params,
                        timeout=self.timeout
                    )

                    # Check if template was evaluated (7*7 = 49)
                    if '49' in response.text:
                        vulns.append(Vulnerability(
                            vuln_type='Server-Side Template Injection',
                            severity='critical',
                            url=url,
                            parameter=param_name,
                            payload=payload,
                            evidence="Template evaluated: 7*7 = 49",
                            description=f"SSTI vulnerability in parameter '{param_name}'"
                        ))
                        break

                except requests.exceptions.RequestException:
                    pass

                time.sleep(0.1)

        return vulns

    def test_file_upload(self, url: str, file_param: str = 'file') -> List[Vulnerability]:
        """
        Test file upload functionality.

        Args:
            url: Upload endpoint URL
            file_param: Name of file parameter

        Returns:
            List of discovered vulnerabilities
        """
        vulns = []

        # Test uploading a PHP file
        test_files = {
            file_param: ('test.php', '<?php echo "test"; ?>', 'application/x-php')
        }

        try:
            response = self.session.post(
                url,
                files=test_files,
                timeout=self.timeout
            )

            # Check if upload was successful
            if response.status_code == 200 and 'success' in response.text.lower():
                vulns.append(Vulnerability(
                    vuln_type='Unrestricted File Upload',
                    severity='high',
                    url=url,
                    parameter=file_param,
                    payload='test.php',
                    evidence=f"Status: {response.status_code}",
                    description="No file type validation on upload endpoint"
                ))

        except requests.exceptions.RequestException:
            pass

        return vulns

    def test_xss(self, url: str, params: Optional[Dict] = None) -> List[Vulnerability]:
        """
        Test for Cross-Site Scripting vulnerabilities.

        Args:
            url: Target URL
            params: GET/POST parameters to test

        Returns:
            List of discovered vulnerabilities
        """
        vulns = []

        if not params:
            params = {'q': 'test'}

        for param_name in params.keys():
            for payload in self.XSS_PAYLOADS:
                test_params = params.copy()
                test_params[param_name] = payload

                try:
                    response = self.session.get(
                        url,
                        params=test_params,
                        timeout=self.timeout
                    )

                    # Check if payload is reflected in response
                    if payload in response.text:
                        vulns.append(Vulnerability(
                            vuln_type='Cross-Site Scripting (XSS)',
                            severity='high',
                            url=url,
                            parameter=param_name,
                            payload=payload,
                            evidence="Payload reflected in response",
                            description=f"XSS vulnerability in parameter '{param_name}'"
                        ))
                        break

                except requests.exceptions.RequestException:
                    pass

                time.sleep(0.1)

        return vulns

    def scan_url(self, url: str, params: Optional[Dict] = None) -> List[Vulnerability]:
        """
        Perform comprehensive scan on a URL.

        Args:
            url: Target URL to scan
            params: Parameters to test (optional)

        Returns:
            List of all discovered vulnerabilities
        """
        all_vulns = []

        print(f"[*] Scanning {url}...")

        # Test for various vulnerabilities
        print("[*] Testing for SQL Injection...")
        all_vulns.extend(self.test_sqli(url, params))

        print("[*] Testing for Command Injection...")
        all_vulns.extend(self.test_command_injection(url, params))

        print("[*] Testing for SSTI...")
        all_vulns.extend(self.test_ssti(url, params))

        print("[*] Testing for XSS...")
        all_vulns.extend(self.test_xss(url, params))

        self.vulnerabilities = all_vulns
        return all_vulns

    def generate_report(self) -> str:
        """
        Generate vulnerability report.

        Returns:
            Formatted report string
        """
        if not self.vulnerabilities:
            return "[+] No vulnerabilities found."

        report = []
        report.append("=" * 80)
        report.append("WEB APPLICATION VULNERABILITY SCAN REPORT")
        report.append("=" * 80)
        report.append("")

        # Group by severity
        critical = [v for v in self.vulnerabilities if v.severity == 'critical']
        high = [v for v in self.vulnerabilities if v.severity == 'high']
        medium = [v for v in self.vulnerabilities if v.severity == 'medium']
        low = [v for v in self.vulnerabilities if v.severity == 'low']

        report.append(f"SUMMARY:")
        report.append(f"  Critical: {len(critical)}")
        report.append(f"  High:     {len(high)}")
        report.append(f"  Medium:   {len(medium)}")
        report.append(f"  Low:      {len(low)}")
        report.append("")

        # List all vulnerabilities
        for i, vuln in enumerate(self.vulnerabilities, 1):
            report.append(f"[{i}] {vuln.vuln_type} ({vuln.severity.upper()})")
            report.append(f"    URL: {vuln.url}")
            if vuln.parameter:
                report.append(f"    Parameter: {vuln.parameter}")
            if vuln.payload:
                report.append(f"    Payload: {vuln.payload}")
            if vuln.evidence:
                report.append(f"    Evidence: {vuln.evidence}")
            if vuln.description:
                report.append(f"    Description: {vuln.description}")
            report.append("")

        report.append("=" * 80)
        return "\n".join(report)


def main():
    """Main function for standalone usage."""
    import argparse

    parser = argparse.ArgumentParser(description='RedCell Web Application Scanner')
    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('--params', help='Parameters to test (format: key1=val1,key2=val2)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout')

    args = parser.parse_args()

    # Parse parameters
    params = None
    if args.params:
        params = {}
        for pair in args.params.split(','):
            key, val = pair.split('=')
            params[key.strip()] = val.strip()

    # Run scanner
    scanner = WebScanner(timeout=args.timeout)
    vulns = scanner.scan_url(args.url, params)

    # Display report
    print("\n" + scanner.generate_report())


if __name__ == '__main__':
    main()
