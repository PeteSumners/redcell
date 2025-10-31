"""
Unit tests for Lateral Movement modules.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock, call
from lateral_movement.smb_wmi import SMBExecution, WMIExecution
from lateral_movement.automated_lateral import (
    AutomatedLateralMovement,
    LateralTarget,
    MovementResult
)


class TestLateralTarget:
    """Test LateralTarget dataclass."""

    def test_creation(self):
        """Test LateralTarget creation."""
        target = LateralTarget(
            ip='192.168.1.100',
            hostname='WORKSTATION01',
            os_type='Windows 10',
            shares=['C$', 'ADMIN$']
        )

        assert target.ip == '192.168.1.100'
        assert target.hostname == 'WORKSTATION01'
        assert 'C$' in target.shares

    def test_default_lists(self):
        """Test default empty lists."""
        target = LateralTarget(ip='192.168.1.100')

        assert target.shares == []
        assert target.services == []

    def test_to_dict(self):
        """Test conversion to dictionary."""
        target = LateralTarget(
            ip='192.168.1.100',
            compromised=True
        )

        target_dict = target.to_dict()
        assert isinstance(target_dict, dict)
        assert target_dict['ip'] == '192.168.1.100'
        assert target_dict['compromised'] is True


class TestMovementResult:
    """Test MovementResult dataclass."""

    def test_creation(self):
        """Test MovementResult creation."""
        result = MovementResult(
            target='192.168.1.100',
            success=True,
            method='SMB',
            credentials='DOMAIN\\user',
            timestamp='2024-01-01T12:00:00',
            details='Successfully connected via SMB'
        )

        assert result.success is True
        assert result.method == 'SMB'

    def test_to_dict(self):
        """Test conversion to dictionary."""
        result = MovementResult(
            target='192.168.1.100',
            success=False,
            method='WMI',
            credentials='DOMAIN\\user',
            timestamp='2024-01-01T12:00:00',
            error='Connection timeout'
        )

        result_dict = result.to_dict()
        assert isinstance(result_dict, dict)
        assert result_dict['error'] == 'Connection timeout'


class TestSMBExecution:
    """Test SMBExecution class."""

    def test_initialization(self):
        """Test SMB initialization."""
        smb = SMBExecution(
            target='192.168.1.100',
            username='admin',
            password='Password123',
            domain='CORP'
        )

        assert smb.target == '192.168.1.100'
        assert smb.username == 'admin'
        assert smb.domain == 'CORP'

    def test_initialization_with_hash(self):
        """Test SMB initialization with NTLM hash."""
        smb = SMBExecution(
            target='192.168.1.100',
            username='admin',
            hash='aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c',
            domain='CORP'
        )

        assert smb.hash is not None
        assert smb.password is None

    @patch('subprocess.run')
    def test_connection_success_windows(self, mock_run):
        """Test successful SMB connection on Windows."""
        mock_run.return_value = Mock(returncode=0, stderr='', stdout='')

        smb = SMBExecution('192.168.1.100', 'admin', 'Password123')

        with patch('platform.system', return_value='Windows'):
            smb.os_type = 'windows'
            result = smb.test_connection()

        assert result is True
        assert mock_run.call_count >= 2  # Connect and cleanup

    @patch('subprocess.run')
    def test_connection_failure(self, mock_run):
        """Test failed SMB connection."""
        mock_run.return_value = Mock(
            returncode=1,
            stderr='Access denied',
            stdout=''
        )

        smb = SMBExecution('192.168.1.100', 'admin', 'WrongPassword')

        with patch('platform.system', return_value='Windows'):
            smb.os_type = 'windows'
            result = smb.test_connection()

        assert result is False

    @patch('subprocess.run')
    def test_enumerate_shares_windows(self, mock_run):
        """Test share enumeration on Windows."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout='C$    Disk    Default share\nADMIN$  Disk    Remote Admin\n',
            stderr=''
        )

        smb = SMBExecution('192.168.1.100', 'admin', 'Password123')

        with patch('platform.system', return_value='Windows'):
            smb.os_type = 'windows'
            shares = smb.enumerate_shares()

        assert len(shares) >= 1

    @patch('subprocess.run')
    def test_upload_file_windows(self, mock_run):
        """Test file upload via SMB on Windows."""
        mock_run.return_value = Mock(returncode=0, stdout='', stderr='')

        smb = SMBExecution('192.168.1.100', 'admin', 'Password123')

        with patch('platform.system', return_value='Windows'):
            smb.os_type = 'windows'
            result = smb.upload_file('C:\\local\\file.exe', 'C$\\temp\\file.exe')

        assert result is True

    @patch('subprocess.run')
    def test_psexec_execute_with_psexec(self, mock_run):
        """Test PSExec-style execution with PsExec.exe."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout='Process started successfully',
            stderr=''
        )

        smb = SMBExecution('192.168.1.100', 'admin', 'Password123')

        result = smb.psexec_execute('whoami')

        assert result is True

    @patch('subprocess.run')
    def test_psexec_execute_manual_service(self, mock_run):
        """Test PSExec-style execution via manual service creation."""
        # First call (PsExec) fails with FileNotFoundError
        # Second call (sc create) succeeds
        # Third call (sc start) succeeds
        # Fourth call (sc delete) for cleanup

        def side_effect(*args, **kwargs):
            cmd = args[0]
            if 'psexec' in str(cmd).lower():
                raise FileNotFoundError("PsExec not found")
            return Mock(returncode=0, stdout='', stderr='')

        mock_run.side_effect = side_effect

        smb = SMBExecution('192.168.1.100', 'admin', 'Password123')

        result = smb.psexec_execute('whoami', service_name='TestService')

        assert result is True


class TestWMIExecution:
    """Test WMIExecution class."""

    def test_initialization(self):
        """Test WMI initialization."""
        wmi = WMIExecution(
            target='192.168.1.100',
            username='admin',
            password='Password123',
            domain='CORP'
        )

        assert wmi.target == '192.168.1.100'
        assert wmi.username == 'admin'
        assert wmi.domain == 'CORP'

    @patch('subprocess.run')
    def test_execute_command_success(self, mock_run):
        """Test successful WMI command execution."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout='Executing (Win32_Process)->Create()\nProcessId = 1234\n',
            stderr=''
        )

        wmi = WMIExecution('192.168.1.100', 'admin', 'Password123')

        result = wmi.execute_command('whoami')

        assert result is not None
        assert 'ProcessId' in result

    @patch('subprocess.run')
    def test_execute_command_failure(self, mock_run):
        """Test failed WMI command execution."""
        mock_run.return_value = Mock(
            returncode=1,
            stdout='',
            stderr='Access denied'
        )

        wmi = WMIExecution('192.168.1.100', 'admin', 'WrongPassword')

        result = wmi.execute_command('whoami')

        assert result is None

    @patch('subprocess.run')
    def test_execute_powershell(self, mock_run):
        """Test PowerShell execution via WMI."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout='ProcessId = 5678',
            stderr=''
        )

        wmi = WMIExecution('192.168.1.100', 'admin', 'Password123')

        ps_script = 'Get-Process'
        result = wmi.execute_powershell(ps_script)

        assert result is not None

        # Check that the command was base64 encoded
        call_args = mock_run.call_args[0][0]
        assert 'powershell.exe' in ' '.join(call_args)
        assert '-EncodedCommand' in ' '.join(call_args)

    @patch('subprocess.run')
    def test_query_remote(self, mock_run):
        """Test WMI query execution."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout='Caption=Microsoft Windows 10 Pro\nVersion=10.0.19042\n',
            stderr=''
        )

        wmi = WMIExecution('192.168.1.100', 'admin', 'Password123')

        result = wmi.query_remote('os get Caption,Version')

        assert result is not None
        assert 'Windows' in result

    @patch('subprocess.run')
    def test_get_system_info(self, mock_run):
        """Test system information gathering."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout='Test output',
            stderr=''
        )

        wmi = WMIExecution('192.168.1.100', 'admin', 'Password123')

        info = wmi.get_system_info()

        assert isinstance(info, dict)


class TestAutomatedLateralMovement:
    """Test AutomatedLateralMovement class."""

    def test_initialization(self):
        """Test initialization."""
        scanner = AutomatedLateralMovement()

        assert scanner.credentials == []
        assert scanner.targets == {}
        assert scanner.max_workers == 5

    def test_initialization_with_credentials(self):
        """Test initialization with credentials."""
        creds = [('admin', 'Password123', 'CORP')]
        scanner = AutomatedLateralMovement(credentials=creds)

        assert len(scanner.credentials) == 1

    def test_add_credential(self):
        """Test adding credentials."""
        scanner = AutomatedLateralMovement()

        scanner.add_credential('admin', 'Password123', 'CORP')

        assert len(scanner.credentials) == 1
        assert scanner.credentials[0] == ('admin', 'Password123', 'CORP')

    def test_add_target(self):
        """Test adding single target."""
        scanner = AutomatedLateralMovement()

        scanner.add_target('192.168.1.100', 'WORKSTATION01')

        assert '192.168.1.100' in scanner.targets
        assert scanner.targets['192.168.1.100'].hostname == 'WORKSTATION01'

    def test_add_target_range(self):
        """Test adding target range from CIDR."""
        scanner = AutomatedLateralMovement()

        scanner.add_target_range('192.168.1.0/30')

        # /30 should add 2 usable hosts (.1 and .2)
        assert len(scanner.targets) == 2

    def test_add_target_range_invalid(self):
        """Test adding invalid CIDR range."""
        scanner = AutomatedLateralMovement()

        scanner.add_target_range('invalid-cidr')

        # Should fail gracefully
        assert len(scanner.targets) == 0

    @patch('lateral_movement.automated_lateral.SMBExecution')
    def test_test_smb_access_success(self, mock_smb_class):
        """Test successful SMB access test."""
        mock_smb = Mock()
        mock_smb.test_connection.return_value = True
        mock_smb.enumerate_shares.return_value = ['C$', 'ADMIN$']
        mock_smb_class.return_value = mock_smb

        scanner = AutomatedLateralMovement()
        scanner.add_target('192.168.1.100')

        success, details = scanner.test_smb_access(
            '192.168.1.100',
            'admin',
            'Password123',
            'CORP'
        )

        assert success is True
        assert '2 shares' in details

    @patch('lateral_movement.automated_lateral.SMBExecution')
    def test_test_smb_access_failure(self, mock_smb_class):
        """Test failed SMB access test."""
        mock_smb = Mock()
        mock_smb.test_connection.return_value = False
        mock_smb_class.return_value = mock_smb

        scanner = AutomatedLateralMovement()

        success, details = scanner.test_smb_access(
            '192.168.1.100',
            'admin',
            'WrongPassword',
            'CORP'
        )

        assert success is False

    @patch('lateral_movement.automated_lateral.WMIExecution')
    def test_test_wmi_access_success(self, mock_wmi_class):
        """Test successful WMI access test."""
        mock_wmi = Mock()
        mock_wmi.get_system_info.return_value = {'os': 'Windows 10'}
        mock_wmi_class.return_value = mock_wmi

        scanner = AutomatedLateralMovement()
        scanner.add_target('192.168.1.100')

        success, details = scanner.test_wmi_access(
            '192.168.1.100',
            'admin',
            'Password123',
            'CORP'
        )

        assert success is True

    @patch('lateral_movement.automated_lateral.SMBExecution')
    @patch('lateral_movement.automated_lateral.WMIExecution')
    def test_attempt_lateral_movement_smb_success(self, mock_wmi_class, mock_smb_class):
        """Test successful lateral movement via SMB."""
        mock_smb = Mock()
        mock_smb.test_connection.return_value = True
        mock_smb.enumerate_shares.return_value = ['C$']
        mock_smb_class.return_value = mock_smb

        scanner = AutomatedLateralMovement()
        scanner.add_target('192.168.1.100')

        result = scanner.attempt_lateral_movement(
            '192.168.1.100',
            'admin',
            'Password123',
            'CORP'
        )

        assert result.success is True
        assert result.method == 'SMB'
        assert '192.168.1.100' in scanner.compromised_hosts

    @patch('lateral_movement.automated_lateral.SMBExecution')
    @patch('lateral_movement.automated_lateral.WMIExecution')
    def test_attempt_lateral_movement_wmi_fallback(self, mock_wmi_class, mock_smb_class):
        """Test lateral movement falls back to WMI when SMB fails."""
        # SMB fails
        mock_smb = Mock()
        mock_smb.test_connection.return_value = False
        mock_smb_class.return_value = mock_smb

        # WMI succeeds
        mock_wmi = Mock()
        mock_wmi.get_system_info.return_value = {'os': 'Windows 10'}
        mock_wmi_class.return_value = mock_wmi

        scanner = AutomatedLateralMovement()
        scanner.add_target('192.168.1.100')

        result = scanner.attempt_lateral_movement(
            '192.168.1.100',
            'admin',
            'Password123',
            'CORP'
        )

        assert result.success is True
        assert result.method == 'WMI'

    @patch('lateral_movement.automated_lateral.SMBExecution')
    @patch('lateral_movement.automated_lateral.WMIExecution')
    def test_spray_credentials(self, mock_wmi_class, mock_smb_class):
        """Test credential spraying."""
        mock_smb = Mock()
        mock_smb.test_connection.return_value = True
        mock_smb.enumerate_shares.return_value = ['C$']
        mock_smb_class.return_value = mock_smb

        scanner = AutomatedLateralMovement()
        scanner.add_target('192.168.1.100')
        scanner.add_target('192.168.1.101')
        scanner.add_credential('admin', 'Password123', 'CORP')
        scanner.add_credential('user', 'Password456', 'CORP')

        results = scanner.spray_credentials(stop_on_success=False)

        # Should have tested 2 targets × 2 credentials = 4 attempts
        assert scanner.scan_stats['credentials_tested'] == 4

    def test_calculate_success_rate(self):
        """Test credential success rate calculation."""
        scanner = AutomatedLateralMovement()

        # Add some results
        scanner.results = [
            MovementResult('192.168.1.100', True, 'SMB', 'CORP\\admin', '2024-01-01'),
            MovementResult('192.168.1.101', False, 'SMB', 'CORP\\admin', '2024-01-01'),
            MovementResult('192.168.1.102', True, 'SMB', 'CORP\\admin', '2024-01-01'),
        ]

        rates = scanner._calculate_success_rate()

        assert 'CORP\\admin' in rates
        assert rates['CORP\\admin']['attempts'] == 3
        assert rates['CORP\\admin']['successes'] == 2
        assert rates['CORP\\admin']['rate'] == pytest.approx(66.67, rel=0.01)

    def test_generate_results(self):
        """Test results generation."""
        scanner = AutomatedLateralMovement()
        scanner.add_target('192.168.1.100')
        scanner.scan_stats['start_time'] = '2024-01-01T12:00:00'
        scanner.scan_stats['end_time'] = '2024-01-01T12:05:00'

        results = scanner.generate_results()

        assert 'stats' in results
        assert 'targets' in results
        assert 'compromised_hosts' in results

    def test_generate_report(self):
        """Test report generation."""
        scanner = AutomatedLateralMovement()
        scanner.scan_stats['start_time'] = '2024-01-01T12:00:00'
        scanner.scan_stats['end_time'] = '2024-01-01T12:05:00'
        scanner.scan_stats['targets_scanned'] = 5
        scanner.scan_stats['hosts_compromised'] = 2

        report = scanner.generate_report()

        assert 'LATERAL MOVEMENT SCAN REPORT' in report
        assert 'Targets Scanned: 5' in report
        assert 'Hosts Compromised: 2' in report

    def test_export_results(self, tmp_path):
        """Test JSON export."""
        scanner = AutomatedLateralMovement()
        scanner.add_target('192.168.1.100')
        scanner.scan_stats['start_time'] = '2024-01-01T12:00:00'

        output_file = tmp_path / "results.json"
        scanner.export_results(str(output_file))

        assert output_file.exists()

        import json
        with open(output_file) as f:
            data = json.load(f)

        assert 'stats' in data
        assert 'targets' in data


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
