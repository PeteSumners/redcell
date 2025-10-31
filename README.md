# RedCell - Advanced Red Team Operations Lab

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Tests](https://img.shields.io/badge/tests-39%20passing-brightgreen.svg)](tests/)
[![Phase](https://img.shields.io/badge/phase-6%2F6-brightgreen.svg)](ROADMAP.md)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)]()

**A comprehensive red team operations portfolio demonstrating advanced offensive security capabilities**

---

## ⚠️ EDUCATIONAL USE ONLY

This project is designed exclusively for:
- ✅ Educational purposes
- ✅ Authorized security testing
- ✅ Portfolio demonstration
- ✅ Isolated lab environments

**🚫 NEVER use these tools on systems you don't own or without explicit written authorization.**

Unauthorized access to computer systems is illegal under laws including the Computer Fraud and Abuse Act (CFAA) and similar international laws.

---

## 🚀 NEW TO CYBERSECURITY? START HERE!

**👉 [GETTING_STARTED.md](GETTING_STARTED.md) - Complete Beginner's Guide**

If you're new to red teaming, ethical hacking, or cybersecurity in general, start with our **ELI5 (Explain Like I'm 5) guide**. It explains:

- What RedCell actually does (in plain English)
- How real attackers work (step-by-step)
- How to set up a safe practice environment
- Legal and safety warnings you MUST understand
- Your first hands-on test walkthrough
- Learning resources and career guidance

**Everyone should read [GETTING_STARTED.md](GETTING_STARTED.md) first, regardless of experience level.**

---

## Overview

RedCell is an end-to-end red team operations lab environment that showcases the complete attack lifecycle. This educational project demonstrates:

- **Custom C2 Framework** - Built from scratch with AES-256-GCM encryption
- **Full Attack Chain** - Aligned with MITRE ATT&CK framework
- **Professional Tooling** - Production-quality code with comprehensive testing
- **Documented Methodology** - Detailed writeups and technical documentation

**Current Status:** ✅ **ALL 6 PHASES COMPLETE** - Full Red Team Operations Capability

**Purpose:** Comprehensive educational portfolio project demonstrating the complete attack lifecycle from reconnaissance through reporting and cleanup.

---

## Features (All Phases Complete)

### ✅ Phase 1: Command & Control Infrastructure
- Custom C2 server with encrypted communications (AES-256-GCM)
- RESTful API with 8 endpoints
- Thread-safe multi-implant management
- Python implant with beaconing and 7 built-in commands
- Interactive operator CLI with Rich formatting
- Vulnerable target environment with OWASP Top 10 vulnerabilities
- Comprehensive test suite (39 tests, 100% crypto coverage)

### ✅ Phase 2: Reconnaissance & Initial Access
- Network scanner with service detection and banner grabbing
- Web vulnerability scanner (SQLi, command injection, file upload)
- SQL injection exploit with automated credential extraction
- Command injection exploit framework
- Phishing server with Office 365, Gmail, and generic templates
- Credential harvester with password spraying and validation

### ✅ Phase 3: Persistence & Privilege Escalation
- Windows persistence (Registry, Scheduled Tasks, WMI, Services)
- Linux persistence (Cron, Systemd, SSH keys, profile injection)
- Privilege escalation enumeration for Windows and Linux
- Credential dumping (LSASS, SAM, Shadow files)
- Token manipulation for Windows privilege elevation
- Automated vulnerability scanning

### ✅ Phase 4: Lateral Movement & Pivoting
- SMB/WMI-based lateral movement
- Pass-the-hash authentication techniques
- Automated lateral movement scanning
- Network pivoting (SOCKS proxy, port forwarding, SSH tunneling)
- Multi-system exploitation chains

### ✅ Phase 5: Data Exfiltration
- Data discovery with file classification and sensitive data detection
- Browser data extraction (credentials, cookies, history)
- AES-256-GCM encryption for exfiltrated data
- DNS tunneling for covert exfiltration
- HTTP/HTTPS chunked exfiltration with resumable uploads
- Automated exfiltration workflow

### ✅ Phase 6: Reporting & Cleanup
- Professional penetration testing report generator
- IOC extraction in STIX, CSV, and JSON formats
- Attack timeline visualization
- MITRE ATT&CK framework mapping
- Cleanup and anti-forensics tools
- Automated reporter orchestrating all modules

---

## Quick Start

### Prerequisites

- Python 3.9+
- Docker & Docker Compose (for target environment)
- Git

### Installation

```bash
# Clone the repository
git clone https://github.com/PeteSumners/redcell.git
cd redcell

# Create and activate virtual environment
python -m venv venv

# Windows
venv\Scripts\activate

# macOS/Linux
source venv/bin/activate

# Install dependencies
pip install -r requirements_minimal.txt

# Verify installation
python -m pytest tests/ -v
```

Expected output: ✅ `39 passed`

### Basic Usage (3 Terminals)

**Terminal 1 - Start C2 Server:**
```bash
python c2/server/main.py
```

**Terminal 2 - Deploy Implant:**
```bash
python c2/implant/basic_implant.py --c2 http://127.0.0.1:8443
```

**Terminal 3 - Operator Interface:**
```bash
python c2/operator/cli.py
```

**📖 For detailed instructions, see [USER_GUIDE.md](USER_GUIDE.md)**

---

## Project Structure

```
redcell/
├── c2/                          # Phase 1: Command & Control infrastructure
│   ├── server/                  # C2 server (crypto, tasking, API)
│   ├── implant/                 # Python beacon implant
│   └── operator/                # CLI operator interface
├── recon/                       # Phase 2: Reconnaissance tools
│   ├── network_scanner.py       # Port scanning and service detection
│   └── web_scanner.py           # Web vulnerability scanning
├── initial_access/              # Phase 2: Initial access tools
│   ├── sqli_exploit.py          # SQL injection exploitation
│   ├── cmd_injection.py         # Command injection exploitation
│   ├── phishing_server.py       # Phishing infrastructure
│   └── credential_harvester.py  # Credential validation and spraying
├── persistence/                 # Phase 3: Persistence mechanisms
│   ├── windows_persist.py       # Windows persistence techniques
│   ├── linux_persist.py         # Linux persistence techniques
│   ├── privilege_escalation.py  # Privilege escalation enumeration
│   ├── credential_dumping.py    # Credential extraction
│   └── token_manipulation.py    # Windows token manipulation
├── lateral_movement/            # Phase 4: Lateral movement
│   ├── smb_wmi.py               # SMB/WMI execution
│   └── automated_lateral.py     # Automated lateral movement
├── exfiltration/                # Phase 5: Data exfiltration
│   ├── data_discovery.py        # Data discovery and classification
│   ├── data_prep.py             # Data encryption and preparation
│   ├── exfil_dns.py             # DNS tunneling exfiltration
│   ├── exfil_http.py            # HTTP exfiltration
│   └── automated_exfil.py       # Automated exfiltration workflow
├── reporting/                   # Phase 6: Reporting and cleanup
│   ├── report_generator.py      # Professional report generation
│   ├── ioc_extractor.py         # IOC extraction
│   ├── timeline.py              # Attack timeline visualization
│   ├── cleanup.py               # Cleanup and anti-forensics
│   └── automated_reporter.py    # Automated reporting workflow
├── utils/                       # Shared utilities
│   ├── logger.py                # Structured logging
│   ├── config.py                # Configuration management
│   ├── helpers.py               # Helper functions
│   └── obfuscation.py           # Payload obfuscation
├── targets/                     # Vulnerable target environments
│   └── docker/                  # Dockerized web app, DMZ, internal
├── tests/                       # Comprehensive test suite (15 files)
│   ├── unit/                    # Unit tests (crypto, tasking)
│   └── integration/             # Integration tests
├── docs/                        # Documentation
│   └── writeups/                # Technical writeups
├── requirements_minimal.txt     # Python dependencies
├── docker-compose.yml           # Target infrastructure
└── *.md                         # Comprehensive documentation (15 files)
```

---

## Documentation

### User Documentation
- **[GETTING_STARTED.md](GETTING_STARTED.md)** - 🌟 **START HERE!** Beginner-friendly ELI5 guide
- **[USER_GUIDE.md](USER_GUIDE.md)** - Complete user guide with examples
- **[ROADMAP.md](ROADMAP.md)** - 6-phase implementation plan

### Phase Documentation
- **[PHASE1_COMPLETE.md](PHASE1_COMPLETE.md)** - Phase 1: C2 Infrastructure
- **[PHASE2_GUIDE.md](PHASE2_GUIDE.md)** - Phase 2: Reconnaissance & Initial Access
- **[PHASE3_GUIDE.md](PHASE3_GUIDE.md)** - Phase 3: Persistence & Privilege Escalation
- **[PHASE4_GUIDE.md](PHASE4_GUIDE.md)** - Phase 4: Lateral Movement & Pivoting
- **[PHASE5_GUIDE.md](PHASE5_GUIDE.md)** - Phase 5: Data Exfiltration
- **[PHASE6_GUIDE.md](PHASE6_GUIDE.md)** - Phase 6: Reporting & Cleanup

### Technical Documentation
- **[docs/writeups/](docs/writeups/)** - Technical writeups for each phase
- **Code Documentation** - Comprehensive docstrings and comments throughout

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                     RED TEAM OPERATOR                        │
│                                                              │
│  ┌────────────────┐              ┌──────────────────┐      │
│  │  Operator CLI  │──────────────│   C2 Server      │      │
│  │  (cli.py)      │   REST API   │   :8443          │      │
│  └────────────────┘              └──────────┬───────┘      │
│                                              │              │
└──────────────────────────────────────────────┼──────────────┘
                                               │
                                  Encrypted Communications
                                    (AES-256-GCM)
                                               │
              ┌────────────────────────────────┼─────────────┐
              │                                │             │
    ┌─────────▼─────────┐          ┌──────────▼──────┐  ┌───▼────────┐
    │   Web App Target  │          │   DMZ Host      │  │  Internal  │
    │   (172.20.0.x)    │──────────│  (Pivot Point)  │──│  Server    │
    │   :8080           │   SSH    │  172.20.x.x     │  │ (172.21.x) │
    │                   │          │  172.21.x.x     │  │            │
    │ Vulnerabilities:  │          └─────────────────┘  │ Sensitive  │
    │ • SQLi            │                               │ Data       │
    │ • Command Inject  │                               └────────────┘
    │ • File Upload     │
    │ • SSTI            │
    └───────────────────┘
```

---

## Testing

Run the full test suite:

```bash
python -m pytest tests/ -v
```

**Test Coverage:**
- 13 crypto unit tests (100% coverage)
- 18 tasking unit tests (98% coverage)
- 8 integration tests

Run with coverage report:

```bash
python -m pytest tests/ -v --cov
```

---

## Roadmap - 100% COMPLETE! 🎉

RedCell was planned as a 6-phase project, now fully implemented:

- ✅ **Phase 1** - Foundation & Infrastructure (Complete)
- ✅ **Phase 2** - Reconnaissance & Initial Access (Complete)
- ✅ **Phase 3** - Persistence & Privilege Escalation (Complete)
- ✅ **Phase 4** - Lateral Movement & Pivoting (Complete)
- ✅ **Phase 5** - Data Exfiltration (Complete)
- ✅ **Phase 6** - Reporting & Cleanup (Complete)

See [ROADMAP.md](ROADMAP.md) for complete details and individual phase guides for implementation documentation.

---

## Technologies Used

| Component | Technology |
|-----------|-----------|
| Language | Python 3.9+ |
| C2 Server | Flask (REST API) |
| Encryption | AES-256-GCM (cryptography library) |
| Testing | pytest with coverage |
| CLI | Rich (terminal UI) |
| Containers | Docker & Docker Compose |
| Target App | Flask (vulnerable by design) |

---

## Security Implementation

### Encryption
- **Algorithm:** AES-256-GCM (Authenticated Encryption)
- **Key Size:** 256 bits (32 bytes)
- **Nonce:** 96 bits, randomly generated per message
- **Transport:** Base64 encoding for JSON compatibility

### OPSEC Features
- **Beacon Jitter:** ±20% randomization to avoid pattern detection
- **Per-Implant Keys:** Unique encryption keys for each implant
- **Authenticated Encryption:** Tamper detection with GCM mode
- **Thread Safety:** Concurrent multi-implant support

---

## Learning Resources

This project draws from industry-standard frameworks:

- [MITRE ATT&CK Framework](https://attack.mitre.org/) - Adversary tactics and techniques
- [OWASP Top 10](https://owasp.org/www-project-top-ten/) - Web application vulnerabilities
- [Red Team Field Manual (RTFM)](https://www.amazon.com/Rtfm-Red-Team-Field-Manual/dp/1494295504) - Red team operations
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework) - Security standards

---

## Contributing

This is a personal portfolio project, but suggestions and feedback are welcome!

- **Issues:** [GitHub Issues](https://github.com/PeteSumners/redcell/issues)
- **Discussions:** Feel free to open an issue for questions

---

## Ethical & Legal Notice

**⚠️ CRITICAL LEGAL WARNING ⚠️**

This project is designed **EXCLUSIVELY** for:
- Authorized security testing with **written permission**
- Educational purposes in **isolated lab environments**
- Portfolio demonstration
- CTF competitions and security training

**NEVER use these tools on:**
- ❌ Systems you don't own
- ❌ Systems without **explicit written authorization**
- ❌ Production environments without proper approval
- ❌ Any system where you lack legal permission

**Legal Consequences:**
Unauthorized access to computer systems is a **federal crime** under:
- Computer Fraud and Abuse Act (CFAA) - U.S.
- Computer Misuse Act - UK
- Similar laws in other jurisdictions

Violations can result in **criminal prosecution, fines, and imprisonment**.

**Use Responsibly. Stay Legal. Get Permission.**

---

## License

This project is licensed under the MIT License - see [LICENSE](LICENSE) for details.

**Educational Use Only.** The author assumes **NO LIABILITY** for misuse of this software.

---

## Author

**Pete Sumners**

- **Email:** petesumners@outlook.com
- **GitHub:** [@PeteSumners](https://github.com/PeteSumners)
- **Project:** Cybersecurity Portfolio

---

## Acknowledgments

- **MITRE Corporation** - ATT&CK Framework
- **OWASP Foundation** - Vulnerability patterns and testing guidelines
- **Cybersecurity Community** - Tools, techniques, and shared knowledge
- **Open Source Contributors** - Libraries and frameworks used in this project

---

## Project Statistics

- **Lines of Code:** ~18,636 (excluding tests and venv)
- **Python Files:** 59 modules across 6 phases
- **Test Files:** 15 comprehensive test modules
- **Test Coverage:** 100% (crypto), 98% (tasking), 70%+ overall target
- **Tests Passing:** 39/39 ✅
- **Phase Completion:** 6/6 (100%) ✅
- **Documentation Files:** 15 comprehensive markdown files
- **Tools Implemented:** 30+ red team tools and modules
- **Supported Platforms:** Windows, Linux, macOS

---

**⭐ If you found this project useful, please consider starring it on GitHub!**

**📖 For complete usage instructions, see [USER_GUIDE.md](USER_GUIDE.md)**

**🔒 Always practice responsible security research.**

---

*Last Updated: October 31, 2025*
*Version: 6.0.0 (All Phases Complete)*
