"""
Unit tests for Network Scanner module.
"""

import pytest
import socket
import threading
from unittest.mock import Mock, patch, MagicMock
from recon.network_scanner import NetworkScanner, PortScanResult


class TestPortScanResult:
    """Test PortScanResult dataclass."""

    def test_creation(self):
        """Test PortScanResult creation."""
        result = PortScanResult(
            host='192.168.1.1',
            port=80,
            state='open',
            service='HTTP',
            banner='Apache/2.4.41'
        )

        assert result.host == '192.168.1.1'
        assert result.port == 80
        assert result.state == 'open'
        assert result.service == 'HTTP'
        assert result.banner == 'Apache/2.4.41'

    def test_to_dict(self):
        """Test conversion to dictionary."""
        result = PortScanResult(
            host='192.168.1.1',
            port=80,
            state='open'
        )

        result_dict = result.to_dict()
        assert isinstance(result_dict, dict)
        assert result_dict['host'] == '192.168.1.1'
        assert result_dict['port'] == 80


class TestNetworkScanner:
    """Test NetworkScanner class."""

    def test_initialization(self):
        """Test NetworkScanner initialization."""
        scanner = NetworkScanner(timeout=2.0, max_threads=10)

        assert scanner.timeout == 2.0
        assert scanner.max_threads == 10
        assert scanner.results == []
        assert scanner.lock is not None

    def test_common_ports_defined(self):
        """Test that common ports are defined."""
        assert len(NetworkScanner.COMMON_PORTS) > 0
        assert 80 in NetworkScanner.COMMON_PORTS
        assert 443 in NetworkScanner.COMMON_PORTS
        assert 22 in NetworkScanner.COMMON_PORTS

    def test_service_signatures_defined(self):
        """Test that service signatures are defined."""
        assert len(NetworkScanner.SERVICE_SIGNATURES) > 0
        assert b'SSH' in NetworkScanner.SERVICE_SIGNATURES
        assert b'HTTP' in NetworkScanner.SERVICE_SIGNATURES

    @patch('socket.socket')
    def test_scan_port_open(self, mock_socket_class):
        """Test scanning an open port."""
        scanner = NetworkScanner()

        # Mock socket that connects successfully
        mock_socket = Mock()
        mock_socket.connect_ex.return_value = 0
        mock_socket.recv.return_value = b'SSH-2.0-OpenSSH_8.0'
        mock_socket_class.return_value = mock_socket

        result = scanner.scan_port('localhost', 22, grab_banner=True)

        assert result.state == 'open'
        assert result.port == 22
        assert result.host == 'localhost'
        assert result.service == 'SSH'
        assert 'SSH' in result.banner

    @patch('socket.socket')
    def test_scan_port_closed(self, mock_socket_class):
        """Test scanning a closed port."""
        scanner = NetworkScanner()

        # Mock socket that fails to connect
        mock_socket = Mock()
        mock_socket.connect_ex.return_value = 1  # Connection refused
        mock_socket_class.return_value = mock_socket

        result = scanner.scan_port('localhost', 9999)

        assert result.state == 'closed'
        assert result.port == 9999

    @patch('socket.socket')
    def test_scan_port_timeout(self, mock_socket_class):
        """Test scanning port with timeout."""
        scanner = NetworkScanner(timeout=0.1)

        # Mock socket that times out
        mock_socket = Mock()
        mock_socket.connect_ex.side_effect = socket.timeout()
        mock_socket_class.return_value = mock_socket

        result = scanner.scan_port('192.168.1.1', 80)

        assert result.state == 'filtered'

    def test_identify_service(self):
        """Test service identification by port."""
        scanner = NetworkScanner()

        assert scanner._identify_service(22) == 'SSH'
        assert scanner._identify_service(80) == 'HTTP'
        assert scanner._identify_service(443) == 'HTTPS'
        assert scanner._identify_service(3306) == 'MySQL'
        assert scanner._identify_service(99999) is None

    @patch('socket.socket')
    def test_scan_port_no_banner(self, mock_socket_class):
        """Test scanning port without banner grabbing."""
        scanner = NetworkScanner()

        mock_socket = Mock()
        mock_socket.connect_ex.return_value = 0
        mock_socket_class.return_value = mock_socket

        result = scanner.scan_port('localhost', 80, grab_banner=False)

        assert result.state == 'open'
        assert result.banner is None
        mock_socket.send.assert_not_called()

    @patch.object(NetworkScanner, 'scan_port')
    def test_scan_ports(self, mock_scan_port):
        """Test scanning multiple ports."""
        scanner = NetworkScanner()

        # Mock scan results
        mock_scan_port.side_effect = [
            PortScanResult('localhost', 22, 'open', 'SSH'),
            PortScanResult('localhost', 80, 'open', 'HTTP'),
            PortScanResult('localhost', 443, 'closed'),
        ]

        results = scanner.scan_ports('localhost', [22, 80, 443], grab_banner=False)

        assert len(results) == 3
        assert results[0].port == 22
        assert results[1].port == 80

    @patch.object(NetworkScanner, 'scan_ports')
    def test_scan_common_ports(self, mock_scan_ports):
        """Test scanning common ports."""
        scanner = NetworkScanner()

        mock_scan_ports.return_value = []

        scanner.scan_common_ports('localhost')

        # Verify scan_ports was called with common ports
        mock_scan_ports.assert_called_once()
        args = mock_scan_ports.call_args[0]
        assert args[0] == 'localhost'
        assert args[1] == NetworkScanner.COMMON_PORTS

    @patch.object(NetworkScanner, 'scan_ports')
    def test_scan_range(self, mock_scan_ports):
        """Test scanning port range."""
        scanner = NetworkScanner()

        scanner.scan_range('localhost', 80, 85)

        mock_scan_ports.assert_called_once()
        args = mock_scan_ports.call_args[0]
        assert args[1] == [80, 81, 82, 83, 84, 85]

    def test_get_open_ports(self):
        """Test getting only open ports."""
        scanner = NetworkScanner()

        scanner.results = [
            PortScanResult('localhost', 22, 'open', 'SSH'),
            PortScanResult('localhost', 80, 'open', 'HTTP'),
            PortScanResult('localhost', 443, 'closed'),
            PortScanResult('localhost', 8080, 'filtered'),
        ]

        open_ports = scanner.get_open_ports()

        assert len(open_ports) == 2
        assert all(p.state == 'open' for p in open_ports)

    def test_generate_report_no_ports(self):
        """Test report generation with no open ports."""
        scanner = NetworkScanner()
        scanner.results = []

        report = scanner.generate_report()

        assert 'No open ports' in report

    def test_generate_report_with_ports(self):
        """Test report generation with open ports."""
        scanner = NetworkScanner()

        scanner.results = [
            PortScanResult('192.168.1.1', 22, 'open', 'SSH', 'OpenSSH 8.0'),
            PortScanResult('192.168.1.1', 80, 'open', 'HTTP', 'Apache/2.4'),
        ]

        report = scanner.generate_report()

        assert '192.168.1.1' in report
        assert '22' in report
        assert 'SSH' in report
        assert 'Total open ports: 2' in report


class TestNetworkScannerIntegration:
    """Integration tests using actual network operations."""

    def test_scan_localhost_ssh(self):
        """Test scanning localhost for common services."""
        scanner = NetworkScanner(timeout=0.5)

        # Scan a few safe ports on localhost
        results = scanner.scan_ports('127.0.0.1', [22, 80, 443], grab_banner=False)

        assert len(results) == 3
        assert all(isinstance(r, PortScanResult) for r in results)

    def test_multithreaded_scan(self):
        """Test that multithreaded scanning completes."""
        scanner = NetworkScanner(timeout=0.5, max_threads=10)

        # Scan a range of ports
        results = scanner.scan_range('127.0.0.1', 1, 20, grab_banner=False)

        # Should get results for all ports
        assert len(results) == 20


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
