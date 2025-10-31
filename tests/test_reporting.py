"""
Unit tests for Reporting modules.
"""

import pytest
import os
from unittest.mock import Mock, patch
from pathlib import Path

from reporting.report_generator import ReportGenerator, Finding, Target
from reporting.ioc_extractor import IOCExtractor, IOC
from reporting.timeline import Timeline, TimelineEvent
from reporting.cleanup import Cleanup


class TestFinding:
    """Test Finding dataclass."""

    def test_creation(self):
        """Test finding creation."""
        finding = Finding(
            title='SQL Injection',
            severity='critical',
            phase='Phase 2',
            description='SQL injection found',
            evidence='Payload: \' OR 1=1--',
            impact='Database compromise',
            remediation='Use parameterized queries',
            mitre_attack=['T1190']
        )

        assert finding.title == 'SQL Injection'
        assert finding.severity == 'critical'
        assert 'T1190' in finding.mitre_attack

    def test_to_dict(self):
        """Test conversion to dictionary."""
        finding = Finding(
            title='Test',
            severity='high',
            phase='Phase 1',
            description='Test description',
            evidence='Test evidence',
            impact='Test impact',
            remediation='Test remediation'
        )

        d = finding.to_dict()
        assert isinstance(d, dict)
        assert d['title'] == 'Test'


class TestTarget:
    """Test Target dataclass."""

    def test_creation(self):
        """Test target creation."""
        target = Target(
            hostname='web-server',
            ip_address='192.168.1.100',
            os_type='Linux',
            services=['HTTP', 'SSH'],
            compromised=True,
            access_level='root'
        )

        assert target.hostname == 'web-server'
        assert target.compromised is True
        assert 'HTTP' in target.services

    def test_to_dict(self):
        """Test conversion to dictionary."""
        target = Target(
            hostname='test',
            ip_address='192.168.1.1'
        )

        d = target.to_dict()
        assert isinstance(d, dict)
        assert d['ip_address'] == '192.168.1.1'


class TestReportGenerator:
    """Test ReportGenerator class."""

    def test_initialization(self):
        """Test initialization."""
        report = ReportGenerator(
            engagement_name='Test Engagement',
            client_name='Test Client'
        )

        assert report.engagement_name == 'Test Engagement'
        assert report.client_name == 'Test Client'
        assert report.findings == []
        assert report.targets == []

    def test_add_finding(self):
        """Test adding findings."""
        report = ReportGenerator('Test', 'Client')

        report.add_finding(
            title='XSS Vulnerability',
            severity='medium',
            phase='Phase 2',
            description='Reflected XSS found',
            evidence='Payload: <script>alert(1)</script>',
            impact='Session hijacking',
            remediation='Encode output',
            mitre_attack=['T1189']
        )

        assert len(report.findings) == 1
        assert report.findings[0].title == 'XSS Vulnerability'

    def test_add_target(self):
        """Test adding targets."""
        report = ReportGenerator('Test', 'Client')

        report.add_target(
            hostname='server1',
            ip_address='192.168.1.100',
            os_type='Windows',
            compromised=True
        )

        assert len(report.targets) == 1
        assert report.targets[0].compromised is True

    def test_get_findings_by_severity(self):
        """Test filtering findings by severity."""
        report = ReportGenerator('Test', 'Client')

        report.add_finding('Critical Finding', 'critical', 'Phase 1', 'desc', 'ev', 'imp', 'rem')
        report.add_finding('High Finding', 'high', 'Phase 1', 'desc', 'ev', 'imp', 'rem')
        report.add_finding('Medium Finding', 'medium', 'Phase 1', 'desc', 'ev', 'imp', 'rem')

        critical = report.get_findings_by_severity('critical')
        high = report.get_findings_by_severity('high')

        assert len(critical) == 1
        assert len(high) == 1

    def test_get_compromised_targets(self):
        """Test getting compromised targets."""
        report = ReportGenerator('Test', 'Client')

        report.add_target('server1', '192.168.1.100', compromised=True)
        report.add_target('server2', '192.168.1.101', compromised=False)
        report.add_target('server3', '192.168.1.102', compromised=True)

        compromised = report.get_compromised_targets()

        assert len(compromised) == 2

    def test_get_mitre_attack_coverage(self):
        """Test MITRE ATT&CK coverage."""
        report = ReportGenerator('Test', 'Client')

        report.add_finding('Finding 1', 'high', 'Phase 1', 'desc', 'ev', 'imp', 'rem', mitre_attack=['T1190'])
        report.add_finding('Finding 2', 'high', 'Phase 1', 'desc', 'ev', 'imp', 'rem', mitre_attack=['T1190', 'T1059'])

        coverage = report.get_mitre_attack_coverage()

        assert 'T1190' in coverage
        assert len(coverage['T1190']) == 2
        assert 'T1059' in coverage

    def test_generate_text_report(self):
        """Test text report generation."""
        report = ReportGenerator('Test Engagement', 'Test Client')

        report.add_finding('Test Finding', 'high', 'Phase 1', 'Description', 'Evidence', 'Impact', 'Remediation')
        report.add_target('server1', '192.168.1.100', compromised=True)

        text_report = report.generate_text_report()

        assert 'PENETRATION TESTING REPORT' in text_report
        assert 'Test Engagement' in text_report
        assert 'Test Finding' in text_report

    def test_export_import_json(self, tmp_path):
        """Test JSON export and import."""
        report = ReportGenerator('Test', 'Client')

        report.add_finding('Test', 'high', 'Phase 1', 'desc', 'ev', 'imp', 'rem')

        # Export
        output_file = tmp_path / "report.json"
        report.export_json(str(output_file))

        assert output_file.exists()

        # Import
        report2 = ReportGenerator('New', 'Client')
        report2.import_json(str(output_file))

        assert len(report2.findings) == 1
        assert report2.engagement_name == 'Test'


class TestIOC:
    """Test IOC dataclass."""

    def test_creation(self):
        """Test IOC creation."""
        ioc = IOC(
            ioc_type='ip_address',
            value='192.168.1.100',
            description='C2 server',
            source='network_analysis',
            severity='critical'
        )

        assert ioc.ioc_type == 'ip_address'
        assert ioc.severity == 'critical'

    def test_to_dict(self):
        """Test conversion to dictionary."""
        ioc = IOC('domain', 'evil.com', 'Malicious domain', 'dns_logs')

        d = ioc.to_dict()
        assert isinstance(d, dict)
        assert d['value'] == 'evil.com'


class TestIOCExtractor:
    """Test IOCExtractor class."""

    def test_initialization(self):
        """Test initialization."""
        extractor = IOCExtractor()

        assert extractor.iocs == []
        assert extractor.seen_values == set()

    def test_add_ioc(self):
        """Test adding IOCs."""
        extractor = IOCExtractor()

        extractor.add_ioc(
            ioc_type='ip_address',
            value='192.168.1.100',
            description='Attacker IP',
            source='firewall_logs'
        )

        assert len(extractor.iocs) == 1
        assert '192.168.1.100' in extractor.seen_values

    def test_add_ioc_duplicate(self):
        """Test duplicate IOC handling."""
        extractor = IOCExtractor()

        extractor.add_ioc('ip', '192.168.1.100', 'Test', 'source1')
        extractor.add_ioc('ip', '192.168.1.100', 'Test', 'source2')  # Duplicate

        assert len(extractor.iocs) == 1  # Should only have one

    def test_extract_from_text_ips(self):
        """Test extracting IP addresses from text."""
        extractor = IOCExtractor()

        text = "Connected to 192.168.1.100 and 10.0.0.5"

        extractor.extract_from_text(text, source='test')

        ips = extractor.get_by_type('ip_address')
        assert len(ips) >= 1

    def test_extract_from_text_domains(self):
        """Test extracting domains from text."""
        extractor = IOCExtractor()

        text = "Connected to evil.com and attacker.net"

        extractor.extract_from_text(text, source='test')

        domains = extractor.get_by_type('domain')
        assert len(domains) >= 1

    def test_extract_from_text_hashes(self):
        """Test extracting hashes from text."""
        extractor = IOCExtractor()

        text = "MD5: 5d41402abc4b2a76b9719d911017c592 SHA256: " + "a" * 64

        extractor.extract_from_text(text, source='test')

        md5s = extractor.get_by_type('hash_md5')
        sha256s = extractor.get_by_type('hash_sha256')

        assert len(md5s) == 1
        assert len(sha256s) == 1

    def test_add_c2_server(self):
        """Test adding C2 server IOC."""
        extractor = IOCExtractor()

        extractor.add_c2_server('http://evil.com:8443')

        assert len(extractor.iocs) == 1
        assert extractor.iocs[0].severity == 'critical'

    def test_get_by_type(self):
        """Test filtering by type."""
        extractor = IOCExtractor()

        extractor.add_ioc('ip_address', '192.168.1.1', 'Test', 'source')
        extractor.add_ioc('domain', 'evil.com', 'Test', 'source')
        extractor.add_ioc('ip_address', '192.168.1.2', 'Test', 'source')

        ips = extractor.get_by_type('ip_address')

        assert len(ips) == 2

    def test_get_by_severity(self):
        """Test filtering by severity."""
        extractor = IOCExtractor()

        extractor.add_ioc('ip', '1.1.1.1', 'Test', 'source', severity='critical')
        extractor.add_ioc('ip', '2.2.2.2', 'Test', 'source', severity='low')

        critical = extractor.get_by_severity('critical')

        assert len(critical) == 1

    def test_export_json(self, tmp_path):
        """Test JSON export."""
        extractor = IOCExtractor()

        extractor.add_ioc('ip', '192.168.1.1', 'Test', 'source')

        output_file = tmp_path / "iocs.json"
        extractor.export_json(str(output_file))

        assert output_file.exists()

    def test_export_csv(self, tmp_path):
        """Test CSV export."""
        extractor = IOCExtractor()

        extractor.add_ioc('ip', '192.168.1.1', 'Test', 'source')

        output_file = tmp_path / "iocs.csv"
        extractor.export_csv(str(output_file))

        assert output_file.exists()


class TestTimelineEvent:
    """Test TimelineEvent dataclass."""

    def test_creation(self):
        """Test timeline event creation."""
        event = TimelineEvent(
            timestamp='2024-01-01T12:00:00',
            phase='Phase 1',
            event_type='Port Scan',
            description='Scanned network',
            severity='info'
        )

        assert event.phase == 'Phase 1'
        assert event.success is True

    def test_to_dict(self):
        """Test conversion to dictionary."""
        event = TimelineEvent(
            timestamp='2024-01-01T12:00:00',
            phase='Phase 1',
            event_type='Test',
            description='Test event'
        )

        d = event.to_dict()
        assert isinstance(d, dict)
        assert d['phase'] == 'Phase 1'


class TestTimeline:
    """Test Timeline class."""

    def test_initialization(self):
        """Test initialization."""
        timeline = Timeline()

        assert timeline.events == []
        assert timeline.start_time is None

    def test_add_event(self):
        """Test adding events."""
        timeline = Timeline()

        timeline.add_event(
            phase='Phase 1',
            event_type='Discovery',
            description='Found target',
            severity='info'
        )

        assert len(timeline.events) == 1
        assert timeline.start_time is not None

    def test_get_events_by_phase(self):
        """Test filtering events by phase."""
        timeline = Timeline()

        timeline.add_event('Phase 1', 'Test', 'Desc')
        timeline.add_event('Phase 2', 'Test', 'Desc')
        timeline.add_event('Phase 1', 'Test', 'Desc')

        phase1_events = timeline.get_events_by_phase('Phase 1')

        assert len(phase1_events) == 2

    def test_get_successful_events(self):
        """Test getting successful events."""
        timeline = Timeline()

        timeline.add_event('Phase 1', 'Test', 'Success', success=True)
        timeline.add_event('Phase 1', 'Test', 'Failure', success=False)

        successful = timeline.get_successful_events()
        failed = timeline.get_failed_events()

        assert len(successful) == 1
        assert len(failed) == 1

    def test_sort_events(self):
        """Test sorting events chronologically."""
        timeline = Timeline()

        timeline.add_event('Phase 1', 'Event 3', 'Third', timestamp='2024-01-01T12:02:00')
        timeline.add_event('Phase 1', 'Event 1', 'First', timestamp='2024-01-01T12:00:00')
        timeline.add_event('Phase 1', 'Event 2', 'Second', timestamp='2024-01-01T12:01:00')

        timeline.sort_events()

        assert timeline.events[0].description == 'First'
        assert timeline.events[2].description == 'Third'

    def test_generate_ascii_timeline(self):
        """Test ASCII timeline generation."""
        timeline = Timeline()

        timeline.add_event('Phase 1', 'Test', 'Event 1')
        timeline.add_event('Phase 2', 'Test', 'Event 2')

        text = timeline.generate_ascii_timeline()

        assert 'ATTACK CHAIN TIMELINE' in text
        assert 'Event 1' in text

    def test_export_import_json(self, tmp_path):
        """Test JSON export and import."""
        timeline = Timeline()

        timeline.add_event('Phase 1', 'Test', 'Test event')

        # Export
        output_file = tmp_path / "timeline.json"
        timeline.export_json(str(output_file))

        assert output_file.exists()

        # Import
        timeline2 = Timeline()
        timeline2.import_json(str(output_file))

        assert len(timeline2.events) == 1


class TestCleanup:
    """Test Cleanup class."""

    def test_initialization(self):
        """Test initialization."""
        cleanup = Cleanup(verbose=False)

        assert cleanup.cleaned_items == []
        assert cleanup.failed_items == []

    def test_delete_file(self, tmp_path):
        """Test file deletion."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("test content")

        cleanup = Cleanup(verbose=False)
        success = cleanup.delete_file(str(test_file))

        assert success is True
        assert not test_file.exists()
        assert len(cleanup.cleaned_items) == 1

    def test_delete_nonexistent_file(self):
        """Test deleting non-existent file."""
        cleanup = Cleanup(verbose=False)
        success = cleanup.delete_file('/nonexistent/file.txt')

        assert success is True  # Already gone

    def test_delete_directory(self, tmp_path):
        """Test directory deletion."""
        test_dir = tmp_path / "test_dir"
        test_dir.mkdir()
        (test_dir / "file.txt").write_text("test")

        cleanup = Cleanup(verbose=False)
        success = cleanup.delete_directory(str(test_dir))

        assert success is True
        assert not test_dir.exists()

    def test_generate_report(self):
        """Test cleanup report generation."""
        cleanup = Cleanup(verbose=False)

        cleanup.cleaned_items = [('file', '/tmp/test.txt')]
        cleanup.failed_items = [('file', '/tmp/protected.txt', 'Permission denied')]

        report = cleanup.generate_report()

        assert 'CLEANUP REPORT' in report
        assert 'Cleaned Items: 1' in report
        assert 'Failed Items: 1' in report


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
