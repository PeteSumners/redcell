"""
Unit tests for Web Scanner module.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import requests
from recon.web_scanner import WebScanner, Vulnerability


class TestVulnerability:
    """Test Vulnerability dataclass."""

    def test_creation(self):
        """Test Vulnerability creation."""
        vuln = Vulnerability(
            vuln_type='SQL Injection',
            severity='critical',
            url='http://example.com/login',
            parameter='username',
            payload="' OR 1=1--",
            evidence='SQL error detected',
            description='SQL injection in login form'
        )

        assert vuln.vuln_type == 'SQL Injection'
        assert vuln.severity == 'critical'
        assert vuln.url == 'http://example.com/login'
        assert vuln.parameter == 'username'

    def test_to_dict(self):
        """Test conversion to dictionary."""
        vuln = Vulnerability(
            vuln_type='XSS',
            severity='high',
            url='http://example.com',
            parameter='search'
        )

        vuln_dict = vuln.to_dict()
        assert isinstance(vuln_dict, dict)
        assert vuln_dict['vuln_type'] == 'XSS'
        assert vuln_dict['severity'] == 'high'


class TestWebScanner:
    """Test WebScanner class."""

    def test_initialization(self):
        """Test WebScanner initialization."""
        scanner = WebScanner(timeout=15, user_agent='TestAgent')

        assert scanner.timeout == 15
        assert scanner.user_agent == 'TestAgent'
        assert scanner.vulnerabilities == []
        assert scanner.session is not None

    def test_default_user_agent(self):
        """Test default user agent is set."""
        scanner = WebScanner()

        assert 'RedCell-WebScanner' in scanner.user_agent

    def test_payloads_defined(self):
        """Test that payloads are defined."""
        assert len(WebScanner.SQLI_PAYLOADS) > 0
        assert len(WebScanner.SQL_ERRORS) > 0
        assert len(WebScanner.CMD_PAYLOADS) > 0
        assert len(WebScanner.SSTI_PAYLOADS) > 0
        assert len(WebScanner.XSS_PAYLOADS) > 0

    @patch('requests.Session.get')
    def test_sqli_detection_success(self, mock_get):
        """Test SQL injection detection when vulnerability found."""
        scanner = WebScanner()

        # Mock response with SQL error
        mock_response = Mock()
        mock_response.text = "MySQL syntax error near '1=1'"
        mock_get.return_value = mock_response

        vulns = scanner.test_sqli('http://example.com/page', {'id': '1'})

        assert len(vulns) > 0
        assert vulns[0].vuln_type == 'SQL Injection'
        assert vulns[0].severity == 'critical'

    @patch('requests.Session.get')
    def test_sqli_detection_no_vulnerability(self, mock_get):
        """Test SQL injection when no vulnerability exists."""
        scanner = WebScanner()

        # Mock response without SQL errors
        mock_response = Mock()
        mock_response.text = "Normal page content"
        mock_get.return_value = mock_response

        vulns = scanner.test_sqli('http://example.com/page', {'id': '1'})

        assert len(vulns) == 0

    @patch('requests.Session.post')
    def test_command_injection_detection(self, mock_post):
        """Test command injection detection."""
        scanner = WebScanner()

        # Mock response with command output
        mock_response = Mock()
        mock_response.text = "uid=33(www-data) gid=33(www-data)"
        mock_post.return_value = mock_response

        vulns = scanner.test_command_injection(
            'http://example.com/exec',
            {'cmd': 'test'}
        )

        assert len(vulns) > 0
        assert vulns[0].vuln_type == 'Command Injection'
        assert vulns[0].severity == 'critical'

    @patch('requests.Session.get')
    def test_ssti_detection(self, mock_get):
        """Test SSTI detection."""
        scanner = WebScanner()

        # Mock response with template evaluation
        mock_response = Mock()
        mock_response.text = "Result: 49"
        mock_get.return_value = mock_response

        vulns = scanner.test_ssti('http://example.com/page', {'q': 'test'})

        assert len(vulns) > 0
        assert vulns[0].vuln_type == 'Server-Side Template Injection'
        assert vulns[0].severity == 'critical'

    @patch('requests.Session.post')
    def test_file_upload_detection(self, mock_post):
        """Test file upload vulnerability detection."""
        scanner = WebScanner()

        # Mock successful upload response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "File uploaded successfully"
        mock_post.return_value = mock_response

        vulns = scanner.test_file_upload('http://example.com/upload')

        assert len(vulns) > 0
        assert vulns[0].vuln_type == 'Unrestricted File Upload'
        assert vulns[0].severity == 'high'

    @patch('requests.Session.get')
    def test_xss_detection(self, mock_get):
        """Test XSS detection."""
        scanner = WebScanner()

        # Mock response with reflected payload
        mock_response = Mock()
        mock_response.text = "<script>alert(1)</script>"
        mock_get.return_value = mock_response

        vulns = scanner.test_xss('http://example.com/page', {'q': 'test'})

        assert len(vulns) > 0
        assert vulns[0].vuln_type == 'Cross-Site Scripting (XSS)'
        assert vulns[0].severity == 'high'

    @patch('requests.Session.get')
    def test_xss_no_reflection(self, mock_get):
        """Test XSS when payload is not reflected."""
        scanner = WebScanner()

        # Mock response without reflected payload
        mock_response = Mock()
        mock_response.text = "Normal page content"
        mock_get.return_value = mock_response

        vulns = scanner.test_xss('http://example.com/page', {'q': 'test'})

        assert len(vulns) == 0

    @patch.object(WebScanner, 'test_sqli')
    @patch.object(WebScanner, 'test_command_injection')
    @patch.object(WebScanner, 'test_ssti')
    @patch.object(WebScanner, 'test_xss')
    def test_scan_url(self, mock_xss, mock_ssti, mock_cmd, mock_sqli):
        """Test comprehensive URL scanning."""
        scanner = WebScanner()

        # Mock all test methods to return vulnerabilities
        mock_sqli.return_value = [
            Vulnerability('SQL Injection', 'critical', 'http://example.com',
                         'id', "'", 'SQL error')
        ]
        mock_cmd.return_value = []
        mock_ssti.return_value = []
        mock_xss.return_value = []

        vulns = scanner.scan_url('http://example.com', {'id': '1'})

        assert len(vulns) == 1
        assert scanner.vulnerabilities == vulns
        mock_sqli.assert_called_once()
        mock_cmd.assert_called_once()
        mock_ssti.assert_called_once()
        mock_xss.assert_called_once()

    def test_generate_report_no_vulnerabilities(self):
        """Test report generation with no vulnerabilities."""
        scanner = WebScanner()

        report = scanner.generate_report()

        assert 'No vulnerabilities found' in report

    def test_generate_report_with_vulnerabilities(self):
        """Test report generation with vulnerabilities."""
        scanner = WebScanner()

        scanner.vulnerabilities = [
            Vulnerability(
                vuln_type='SQL Injection',
                severity='critical',
                url='http://example.com/page',
                parameter='id',
                payload="' OR 1=1--",
                evidence='MySQL error',
                description='SQL injection found'
            ),
            Vulnerability(
                vuln_type='XSS',
                severity='high',
                url='http://example.com/search',
                parameter='q',
                payload='<script>alert(1)</script>',
                evidence='Reflected in response',
                description='XSS vulnerability'
            )
        ]

        report = scanner.generate_report()

        assert 'VULNERABILITY SCAN REPORT' in report
        assert 'Critical: 1' in report
        assert 'High: 1' in report
        assert 'SQL Injection' in report
        assert 'XSS' in report

    def test_severity_grouping(self):
        """Test that vulnerabilities are grouped by severity."""
        scanner = WebScanner()

        scanner.vulnerabilities = [
            Vulnerability('Test1', 'critical', 'http://example.com'),
            Vulnerability('Test2', 'critical', 'http://example.com'),
            Vulnerability('Test3', 'high', 'http://example.com'),
            Vulnerability('Test4', 'medium', 'http://example.com'),
            Vulnerability('Test5', 'low', 'http://example.com'),
        ]

        report = scanner.generate_report()

        assert 'Critical: 2' in report
        assert 'High:     1' in report
        assert 'Medium:   1' in report
        assert 'Low:      1' in report

    @patch('requests.Session.get')
    def test_request_exception_handling(self, mock_get):
        """Test handling of request exceptions."""
        scanner = WebScanner()

        # Mock exception during request
        mock_get.side_effect = requests.exceptions.RequestException("Connection error")

        vulns = scanner.test_sqli('http://example.com/page', {'id': '1'})

        # Should handle exception gracefully and return empty list
        assert vulns == []

    @patch('requests.Session.get')
    def test_default_params(self, mock_get):
        """Test scanning with default parameters."""
        scanner = WebScanner()

        mock_response = Mock()
        mock_response.text = "Normal response"
        mock_get.return_value = mock_response

        # Should use default params if none provided
        vulns = scanner.test_sqli('http://example.com/page')

        mock_get.assert_called()
        assert len(vulns) == 0


class TestWebScannerRateLimit:
    """Test rate limiting behavior."""

    @patch('requests.Session.get')
    @patch('time.sleep')
    def test_rate_limiting_applied(self, mock_sleep, mock_get):
        """Test that rate limiting is applied between requests."""
        scanner = WebScanner()

        mock_response = Mock()
        mock_response.text = "Normal response"
        mock_get.return_value = mock_response

        scanner.test_sqli('http://example.com', {'id': '1'})

        # Should have sleep calls for rate limiting
        assert mock_sleep.call_count > 0


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
