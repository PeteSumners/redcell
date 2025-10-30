# RedCell - Advanced Red Team Operations Lab

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Tests](https://img.shields.io/badge/tests-39%20passing-brightgreen.svg)](tests/)
[![Phase](https://img.shields.io/badge/phase-1%2F6-yellow.svg)](ROADMAP.md)
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

## Overview

RedCell is an end-to-end red team operations lab environment that showcases the complete attack lifecycle. This educational project demonstrates:

- **Custom C2 Framework** - Built from scratch with AES-256-GCM encryption
- **Full Attack Chain** - Aligned with MITRE ATT&CK framework
- **Professional Tooling** - Production-quality code with comprehensive testing
- **Documented Methodology** - Detailed writeups and technical documentation

**Current Status:** ✅ **Phase 1 Complete** - Foundation & Infrastructure

**Purpose:** Educational portfolio project for demonstrating advanced cybersecurity skills to potential employers.

---

## Phase 1 Features (Completed)

### ✅ Command & Control Infrastructure
- Custom C2 server with encrypted communications (AES-256-GCM)
- RESTful API with 8 endpoints
- Thread-safe multi-implant management
- Per-implant encryption keys
- Automated task queuing and execution

### ✅ Python Implant
- Automatic registration with C2
- Encrypted beacon with configurable interval and jitter
- 7 built-in commands (shell, sysinfo, pwd, ls, sleep, exit)
- Resilient error handling and retry logic

### ✅ Operator Interface
- Interactive CLI with Rich library
- Color-coded output and tables
- Context-aware prompt
- Real-time task management

### ✅ Target Environment
- Vulnerable web application with OWASP Top 10 vulnerabilities
  - SQL Injection
  - Command Injection
  - Unrestricted File Upload
  - Server-Side Template Injection (SSTI)
- Dockerized infrastructure with isolated networks
- DMZ and internal network segments

### ✅ Testing & Quality
- 39 comprehensive tests (unit + integration)
- 100% coverage on crypto module
- 98% coverage on tasking module
- Thread safety verification

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
├── c2/                          # Command & Control infrastructure
│   ├── server/                  # C2 server (crypto, tasking, API)
│   ├── implant/                 # Python beacon implant
│   └── operator/                # CLI operator interface
├── targets/                     # Vulnerable target environments
│   └── docker/                  # Dockerized web app, DMZ, internal
├── tests/                       # Comprehensive test suite
│   ├── unit/                    # Unit tests (crypto, tasking)
│   └── integration/             # Integration tests
├── utils/                       # Shared utilities
│   ├── logger.py                # Structured logging
│   ├── config.py                # Configuration management
│   └── helpers.py               # Helper functions
├── docs/                        # Documentation
│   └── writeups/                # Technical writeups
├── requirements_minimal.txt     # Python dependencies
├── docker-compose.yml          # Target infrastructure
└── USER_GUIDE.md               # Complete user guide
```

---

## Documentation

### User Documentation
- **[USER_GUIDE.md](USER_GUIDE.md)** - Complete user guide with examples
- **[ROADMAP.md](ROADMAP.md)** - 6-phase implementation plan (12 weeks)
- **[PHASE1_COMPLETE.md](PHASE1_COMPLETE.md)** - Phase 1 completion summary

### Technical Documentation
- **[docs/writeups/phase1_foundation.md](docs/writeups/phase1_foundation.md)** - Phase 1 technical writeup
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

## Roadmap

RedCell is planned as a 6-phase project over 12 weeks:

- ✅ **Phase 1** - Foundation & Infrastructure (Complete)
- ⏳ **Phase 2** - Reconnaissance & Initial Access (Planned)
- ⏳ **Phase 3** - Post-Exploitation & Persistence (Planned)
- ⏳ **Phase 4** - Lateral Movement & Pivoting (Planned)
- ⏳ **Phase 5** - Advanced C2 & Data Exfiltration (Planned)
- ⏳ **Phase 6** - Documentation & Professionalization (Planned)

See [ROADMAP.md](ROADMAP.md) for complete details.

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

- **Lines of Code:** ~3,000+ (excluding tests)
- **Test Lines:** ~700
- **Test Coverage:** 100% (crypto), 98% (tasking)
- **Tests Passing:** 39/39 ✅
- **Phase Completion:** 1/6 (16.7%)
- **Time Investment:** Autonomous development in single session

---

**⭐ If you found this project useful, please consider starring it on GitHub!**

**📖 For complete usage instructions, see [USER_GUIDE.md](USER_GUIDE.md)**

**🔒 Always practice responsible security research.**

---

*Last Updated: October 30, 2025*
*Version: 1.0.0 (Phase 1 Complete)*
