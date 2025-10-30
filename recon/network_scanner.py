"""
Network Scanner Module

Port scanning and service detection for reconnaissance.
"""

import socket
import threading
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass, asdict
import time


@dataclass
class PortScanResult:
    """Result from port scanning."""
    host: str
    port: int
    state: str  # 'open', 'closed', 'filtered'
    service: Optional[str] = None
    banner: Optional[str] = None

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return asdict(self)


class NetworkScanner:
    """
    Network scanner for port and service detection.

    Features:
    - TCP port scanning
    - Service detection via banner grabbing
    - Multi-threaded scanning
    - Common port presets
    """

    # Common ports for reconnaissance
    COMMON_PORTS = [
        21,    # FTP
        22,    # SSH
        23,    # Telnet
        25,    # SMTP
        53,    # DNS
        80,    # HTTP
        110,   # POP3
        143,   # IMAP
        443,   # HTTPS
        445,   # SMB
        3306,  # MySQL
        3389,  # RDP
        5432,  # PostgreSQL
        5900,  # VNC
        8000,  # HTTP Alt
        8080,  # HTTP Proxy
        8443,  # HTTPS Alt
    ]

    # Service signatures for banner matching
    SERVICE_SIGNATURES = {
        b'SSH': 'SSH',
        b'FTP': 'FTP',
        b'HTTP': 'HTTP',
        b'SMTP': 'SMTP',
        b'POP': 'POP3',
        b'IMAP': 'IMAP',
        b'MySQL': 'MySQL',
        b'PostgreSQL': 'PostgreSQL',
    }

    def __init__(self, timeout: float = 1.0, max_threads: int = 50):
        """
        Initialize network scanner.

        Args:
            timeout: Socket timeout in seconds
            max_threads: Maximum concurrent threads
        """
        self.timeout = timeout
        self.max_threads = max_threads
        self.results = []
        self.lock = threading.Lock()

    def scan_port(self, host: str, port: int, grab_banner: bool = True) -> PortScanResult:
        """
        Scan a single port on a host.

        Args:
            host: Target hostname or IP
            port: Port number to scan
            grab_banner: Attempt to grab service banner

        Returns:
            PortScanResult object
        """
        try:
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)

            # Attempt connection
            result = sock.connect_ex((host, port))

            if result == 0:
                # Port is open
                banner = None
                service = self._identify_service(port)

                # Try to grab banner
                if grab_banner:
                    try:
                        sock.send(b'\r\n')
                        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()

                        # Update service based on banner
                        for signature, svc in self.SERVICE_SIGNATURES.items():
                            if signature in banner.encode():
                                service = svc
                                break
                    except:
                        pass

                sock.close()
                return PortScanResult(
                    host=host,
                    port=port,
                    state='open',
                    service=service,
                    banner=banner
                )
            else:
                sock.close()
                return PortScanResult(host=host, port=port, state='closed')

        except socket.timeout:
            return PortScanResult(host=host, port=port, state='filtered')
        except Exception as e:
            return PortScanResult(host=host, port=port, state='filtered')

    def _identify_service(self, port: int) -> Optional[str]:
        """
        Identify common services by port number.

        Args:
            port: Port number

        Returns:
            Service name or None
        """
        services = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            445: 'SMB',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            5900: 'VNC',
            8000: 'HTTP',
            8080: 'HTTP',
            8443: 'HTTPS',
        }
        return services.get(port)

    def _scan_port_thread(self, host: str, port: int, grab_banner: bool):
        """Thread worker for scanning a single port."""
        result = self.scan_port(host, port, grab_banner)

        with self.lock:
            self.results.append(result)

    def scan_ports(
        self,
        host: str,
        ports: List[int],
        grab_banner: bool = True
    ) -> List[PortScanResult]:
        """
        Scan multiple ports on a host using multi-threading.

        Args:
            host: Target hostname or IP
            ports: List of port numbers to scan
            grab_banner: Attempt to grab service banners

        Returns:
            List of PortScanResult objects
        """
        self.results = []
        threads = []

        # Create threads for scanning
        for port in ports:
            while len([t for t in threads if t.is_alive()]) >= self.max_threads:
                time.sleep(0.01)

            thread = threading.Thread(
                target=self._scan_port_thread,
                args=(host, port, grab_banner)
            )
            thread.start()
            threads.append(thread)

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

        return sorted(self.results, key=lambda x: x.port)

    def scan_common_ports(self, host: str, grab_banner: bool = True) -> List[PortScanResult]:
        """
        Scan common ports on a host.

        Args:
            host: Target hostname or IP
            grab_banner: Attempt to grab service banners

        Returns:
            List of PortScanResult objects
        """
        return self.scan_ports(host, self.COMMON_PORTS, grab_banner)

    def scan_range(
        self,
        host: str,
        start_port: int,
        end_port: int,
        grab_banner: bool = False
    ) -> List[PortScanResult]:
        """
        Scan a range of ports.

        Args:
            host: Target hostname or IP
            start_port: Starting port number
            end_port: Ending port number (inclusive)
            grab_banner: Attempt to grab service banners

        Returns:
            List of PortScanResult objects
        """
        ports = list(range(start_port, end_port + 1))
        return self.scan_ports(host, ports, grab_banner)

    def get_open_ports(self) -> List[PortScanResult]:
        """
        Get only open ports from last scan.

        Returns:
            List of PortScanResult objects with state='open'
        """
        return [r for r in self.results if r.state == 'open']

    def generate_report(self) -> str:
        """
        Generate a text report of scan results.

        Returns:
            Formatted report string
        """
        open_ports = self.get_open_ports()

        if not open_ports:
            return "No open ports found."

        report = []
        report.append(f"Scan Results for {open_ports[0].host}")
        report.append("=" * 60)
        report.append(f"{'PORT':<10} {'STATE':<10} {'SERVICE':<15} {'BANNER'}")
        report.append("-" * 60)

        for result in open_ports:
            banner = result.banner[:40] + "..." if result.banner and len(result.banner) > 40 else (result.banner or "")
            report.append(
                f"{result.port:<10} {result.state:<10} {result.service or 'unknown':<15} {banner}"
            )

        report.append("=" * 60)
        report.append(f"Total open ports: {len(open_ports)}")

        return "\n".join(report)


def main():
    """Main function for standalone usage."""
    import argparse

    parser = argparse.ArgumentParser(description='RedCell Network Scanner')
    parser.add_argument('host', help='Target host to scan')
    parser.add_argument('--ports', help='Comma-separated ports (e.g., 80,443,8080)')
    parser.add_argument('--range', help='Port range (e.g., 1-1000)')
    parser.add_argument('--common', action='store_true', help='Scan common ports')
    parser.add_argument('--timeout', type=float, default=1.0, help='Timeout in seconds')
    parser.add_argument('--no-banner', action='store_true', help='Skip banner grabbing')
    parser.add_argument('--threads', type=int, default=50, help='Max concurrent threads')

    args = parser.parse_args()

    scanner = NetworkScanner(timeout=args.timeout, max_threads=args.threads)

    print(f"[*] Scanning {args.host}...")

    # Determine which ports to scan
    if args.common:
        results = scanner.scan_common_ports(args.host, grab_banner=not args.no_banner)
    elif args.ports:
        ports = [int(p.strip()) for p in args.ports.split(',')]
        results = scanner.scan_ports(args.host, ports, grab_banner=not args.no_banner)
    elif args.range:
        start, end = map(int, args.range.split('-'))
        results = scanner.scan_range(args.host, start, end, grab_banner=not args.no_banner)
    else:
        results = scanner.scan_common_ports(args.host, grab_banner=not args.no_banner)

    # Display results
    print(scanner.generate_report())


if __name__ == '__main__':
    main()
