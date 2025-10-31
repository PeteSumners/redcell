"""
Attack Timeline Generator

Create chronological timeline of penetration testing activities.
"""

from datetime import datetime
from typing import List, Dict, Optional
from dataclasses import dataclass, asdict
import json


@dataclass
class TimelineEvent:
    """Represents a timeline event."""

    timestamp: str
    phase: str
    event_type: str
    description: str
    severity: str = "info"  # info, low, medium, high, critical
    details: str = ""
    target: Optional[str] = None
    success: bool = True

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return asdict(self)


class Timeline:
    """
    Attack chain timeline generator.

    Features:
    - Chronological event tracking
    - Phase-based organization
    - Attack chain visualization
    - Export to multiple formats
    """

    PHASES = [
        'Phase 1: Reconnaissance',
        'Phase 2: Initial Access',
        'Phase 3: Persistence & Privilege Escalation',
        'Phase 4: Lateral Movement',
        'Phase 5: Data Exfiltration',
        'Phase 6: Cleanup'
    ]

    def __init__(self):
        """Initialize timeline."""
        self.events: List[TimelineEvent] = []
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None

    def add_event(
        self,
        phase: str,
        event_type: str,
        description: str,
        severity: str = "info",
        details: str = "",
        target: str = None,
        success: bool = True,
        timestamp: str = None
    ):
        """
        Add event to timeline.

        Args:
            phase: Phase number or name
            event_type: Type of event
            description: Event description
            severity: Severity level
            details: Detailed information
            target: Target system
            success: Whether action was successful
            timestamp: Custom timestamp (ISO format)
        """
        if timestamp is None:
            timestamp = datetime.now().isoformat()

        event = TimelineEvent(
            timestamp=timestamp,
            phase=phase,
            event_type=event_type,
            description=description,
            severity=severity,
            details=details,
            target=target,
            success=success
        )

        self.events.append(event)

        # Update start/end times
        event_time = datetime.fromisoformat(timestamp)

        if self.start_time is None or event_time < self.start_time:
            self.start_time = event_time

        if self.end_time is None or event_time > self.end_time:
            self.end_time = event_time

    def get_events_by_phase(self, phase: str) -> List[TimelineEvent]:
        """Get events by phase."""
        return [e for e in self.events if e.phase == phase]

    def get_events_by_target(self, target: str) -> List[TimelineEvent]:
        """Get events by target."""
        return [e for e in self.events if e.target == target]

    def get_critical_events(self) -> List[TimelineEvent]:
        """Get critical severity events."""
        return [e for e in self.events if e.severity in ['critical', 'high']]

    def get_successful_events(self) -> List[TimelineEvent]:
        """Get successful events."""
        return [e for e in self.events if e.success]

    def get_failed_events(self) -> List[TimelineEvent]:
        """Get failed events."""
        return [e for e in self.events if not e.success]

    def sort_events(self):
        """Sort events chronologically."""
        self.events.sort(key=lambda e: e.timestamp)

    def generate_ascii_timeline(self) -> str:
        """
        Generate ASCII timeline visualization.

        Returns:
            Formatted timeline string
        """
        self.sort_events()

        report = []
        report.append("=" * 100)
        report.append("ATTACK CHAIN TIMELINE")
        report.append("=" * 100)

        if self.start_time and self.end_time:
            duration = self.end_time - self.start_time
            report.append(f"\nStart Time: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
            report.append(f"End Time: {self.end_time.strftime('%Y-%m-%d %H:%M:%S')}")
            report.append(f"Duration: {duration}")

        report.append(f"\nTotal Events: {len(self.events)}")
        report.append(f"Successful: {len(self.get_successful_events())}")
        report.append(f"Failed: {len(self.get_failed_events())}")

        # Events by phase
        report.append("\n" + "=" * 100)
        report.append("CHRONOLOGICAL EVENTS")
        report.append("=" * 100)

        current_phase = None

        for event in self.events:
            # Phase header
            if event.phase != current_phase:
                current_phase = event.phase
                report.append(f"\n{'─' * 100}")
                report.append(f"{current_phase}")
                report.append(f"{'─' * 100}")

            # Event
            time_str = datetime.fromisoformat(event.timestamp).strftime('%H:%M:%S')
            status = "✓" if event.success else "✗"
            severity_icon = {
                'critical': '!!!',
                'high': '!!',
                'medium': '!',
                'low': '·',
                'info': '·'
            }.get(event.severity, '·')

            report.append(f"\n[{time_str}] {status} {severity_icon} {event.event_type}: {event.description}")

            if event.target:
                report.append(f"         Target: {event.target}")

            if event.details:
                # Truncate details if too long
                details = event.details if len(event.details) <= 80 else event.details[:77] + "..."
                report.append(f"         {details}")

        report.append("\n" + "=" * 100)
        return "\n".join(report)

    def generate_attack_chain_summary(self) -> str:
        """
        Generate attack chain summary.

        Returns:
            Summary string
        """
        self.sort_events()

        report = []
        report.append("=" * 100)
        report.append("ATTACK CHAIN SUMMARY")
        report.append("=" * 100)

        # By phase
        for phase_name in self.PHASES:
            # Extract phase number
            phase_num = phase_name.split(':')[0]

            phase_events = self.get_events_by_phase(phase_num)

            if phase_events:
                report.append(f"\n{phase_name}")
                report.append("-" * 100)

                successful = [e for e in phase_events if e.success]
                failed = [e for e in phase_events if not e.success]

                report.append(f"Events: {len(phase_events)} (Success: {len(successful)}, Failed: {len(failed)})")

                # Key events
                critical_events = [e for e in phase_events if e.severity in ['critical', 'high']]

                if critical_events:
                    report.append(f"\nKey Events:")
                    for event in critical_events[:5]:
                        status = "✓" if event.success else "✗"
                        report.append(f"  {status} {event.description}")

        report.append("\n" + "=" * 100)
        return "\n".join(report)

    def export_json(self, filename: str):
        """
        Export timeline to JSON.

        Args:
            filename: Output filename
        """
        data = {
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'total_events': len(self.events),
            'events': [e.to_dict() for e in self.events]
        }

        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)

        print(f"[+] Timeline exported to JSON: {filename}")

    def import_json(self, filename: str):
        """
        Import timeline from JSON.

        Args:
            filename: Input filename
        """
        with open(filename) as f:
            data = json.load(f)

        for event_data in data.get('events', []):
            self.events.append(TimelineEvent(**event_data))

        # Sort and update times
        self.sort_events()

        if self.events:
            self.start_time = datetime.fromisoformat(self.events[0].timestamp)
            self.end_time = datetime.fromisoformat(self.events[-1].timestamp)

        print(f"[+] Timeline imported from JSON: {filename}")


def main():
    """Main function for standalone usage."""
    import argparse

    parser = argparse.ArgumentParser(description='RedCell Timeline Generator')

    parser.add_argument('--import-json', help='Import timeline from JSON')
    parser.add_argument('--export-json', help='Export timeline to JSON')
    parser.add_argument('--summary', action='store_true', help='Show attack chain summary')

    args = parser.parse_args()

    timeline = Timeline()

    # Import if specified
    if args.import_json:
        timeline.import_json(args.import_json)
    else:
        # Example timeline
        timeline.add_event(
            phase='Phase 1',
            event_type='Port Scan',
            description='Scanned target network 192.168.1.0/24',
            severity='info',
            success=True
        )

    # Generate timeline
    if args.summary:
        print(timeline.generate_attack_chain_summary())
    else:
        print(timeline.generate_ascii_timeline())

    # Export if specified
    if args.export_json:
        timeline.export_json(args.export_json)


if __name__ == '__main__':
    main()
