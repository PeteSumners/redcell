"""
Unit tests for Privilege Escalation module.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from persistence.privilege_escalation import PrivilegeEscalation, PrivescVector


class TestPrivescVector:
    """Test PrivescVector dataclass."""

    def test_creation(self):
        """Test PrivescVector creation."""
        vector = PrivescVector(
            vector_type='suid_binary',
            severity='critical',
            description='Dangerous SUID binary found',
            file_path='/usr/bin/vim',
            details='Can be exploited via GTFOBins'
        )

        assert vector.vector_type == 'suid_binary'
        assert vector.severity == 'critical'
        assert vector.file_path == '/usr/bin/vim'

    def test_to_dict(self):
        """Test conversion to dictionary."""
        vector = PrivescVector(
            vector_type='sudo_nopasswd',
            severity='high',
            description='NOPASSWD sudo found'
        )

        vector_dict = vector.to_dict()
        assert isinstance(vector_dict, dict)
        assert vector_dict['vector_type'] == 'sudo_nopasswd'


class TestPrivilegeEscalation:
    """Test PrivilegeEscalation class."""

    def test_initialization(self):
        """Test initialization."""
        privesc = PrivilegeEscalation()

        assert privesc.vectors == []
        assert privesc.os_type is not None

    @patch('platform.system')
    def test_enumerate_calls_correct_method(self, mock_system):
        """Test enumerate calls correct OS-specific method."""
        # Test Windows
        mock_system.return_value = 'Windows'
        privesc = PrivilegeEscalation()

        with patch.object(privesc, '_enumerate_windows') as mock_win:
            privesc.enumerate()
            mock_win.assert_called_once()

        # Test Linux
        mock_system.return_value = 'Linux'
        privesc = PrivilegeEscalation()

        with patch.object(privesc, '_enumerate_linux') as mock_linux:
            privesc.enumerate()
            mock_linux.assert_called_once()

    def test_generate_report_no_vectors(self):
        """Test report generation with no vectors."""
        privesc = PrivilegeEscalation()

        report = privesc.generate_report()

        assert 'No privilege escalation vectors found' in report

    def test_generate_report_with_vectors(self):
        """Test report generation with vectors."""
        privesc = PrivilegeEscalation()

        privesc.vectors = [
            PrivescVector('suid_binary', 'critical', 'SUID binary found'),
            PrivescVector('sudo_permissions', 'high', 'Dangerous sudo permissions')
        ]

        report = privesc.generate_report()

        assert 'PRIVILEGE ESCALATION' in report.upper()
        assert 'Critical: 1' in report
        assert 'High:     1' in report

    def test_export_json(self, tmp_path):
        """Test JSON export."""
        privesc = PrivilegeEscalation()

        privesc.vectors = [
            PrivescVector('test_vector', 'high', 'Test vector')
        ]

        output_file = tmp_path / "privesc.json"
        privesc.export_json(str(output_file))

        assert output_file.exists()

        import json
        with open(output_file) as f:
            data = json.load(f)

        assert len(data) == 1
        assert data[0]['vector_type'] == 'test_vector'


class TestWindowsEnumeration:
    """Test Windows-specific enumeration."""

    @patch('subprocess.run')
    def test_check_windows_privileges(self, mock_run):
        """Test Windows privilege checking."""
        privesc = PrivilegeEscalation()
        privesc.os_type = 'windows'

        # Mock whoami /priv output
        mock_run.return_value = Mock(
            returncode=0,
            stdout="SeDebugPrivilege    Enabled\nSeImpersonatePrivilege    Enabled"
        )

        privesc._check_windows_privileges()

        # Should find dangerous privileges
        assert len(privesc.vectors) > 0
        assert any('SeImpersonatePrivilege' in v.description for v in privesc.vectors)

    @patch('subprocess.run')
    def test_check_always_install_elevated(self, mock_run):
        """Test AlwaysInstallElevated check."""
        privesc = PrivilegeEscalation()
        privesc.os_type = 'windows'

        # Mock both registry keys enabled
        mock_run.return_value = Mock(
            returncode=0,
            stdout="AlwaysInstallElevated    REG_DWORD    0x1"
        )

        privesc._check_always_install_elevated()

        # Should find the vulnerability
        critical_vectors = [v for v in privesc.vectors if v.severity == 'critical']
        assert len(critical_vectors) > 0


class TestLinuxEnumeration:
    """Test Linux-specific enumeration."""

    @patch('subprocess.run')
    def test_check_suid_binaries(self, mock_run):
        """Test SUID binary enumeration."""
        privesc = PrivilegeEscalation()
        privesc.os_type = 'linux'

        # Mock find output
        mock_run.return_value = Mock(
            returncode=0,
            stdout="/usr/bin/vim\n/usr/bin/find\n/usr/bin/nmap"
        )

        privesc._check_suid_binaries()

        # Should find dangerous SUID binaries
        assert len(privesc.vectors) > 0
        assert any('vim' in (v.file_path or '') for v in privesc.vectors)

    @patch('subprocess.run')
    def test_check_sudo(self, mock_run):
        """Test sudo permission checking."""
        privesc = PrivilegeEscalation()
        privesc.os_type = 'linux'

        # Mock sudo -l output
        mock_run.return_value = Mock(
            returncode=0,
            stdout="(ALL) NOPASSWD: /usr/bin/python"
        )

        privesc._check_sudo()

        # Should find NOPASSWD sudo
        assert len(privesc.vectors) > 0
        assert any('NOPASSWD' in v.description for v in privesc.vectors)

    @patch('os.access')
    @patch('os.path.exists')
    def test_check_writable_etc_passwd(self, mock_exists, mock_access):
        """Test writable /etc/passwd check."""
        privesc = PrivilegeEscalation()
        privesc.os_type = 'linux'

        mock_exists.return_value = True
        mock_access.return_value = True

        privesc._check_writable_etc_passwd()

        # Should find critical vulnerability
        critical_vectors = [v for v in privesc.vectors if v.severity == 'critical']
        assert len(critical_vectors) > 0
        assert any('passwd' in v.description.lower() for v in critical_vectors)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
