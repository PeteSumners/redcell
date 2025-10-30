# RedCell - Advanced Red Team Operations Lab

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

RedCell is an end-to-end red team operations lab environment that showcases the complete attack lifecycle from reconnaissance to data exfiltration. This project demonstrates:

- Full attack chain methodology (aligned with MITRE ATT&CK)
- Custom command & control (C2) infrastructure
- Advanced persistence and evasion techniques
- Network pivoting and lateral movement
- Professional red team documentation and reporting

**Purpose:** Educational portfolio project for demonstrating advanced cybersecurity skills to potential employers.

## Features

### Command & Control
- Custom C2 server with encrypted communications (AES)
- Multiple communication protocols (HTTP/HTTPS, DNS tunneling)
- Beacon implants with jitter and randomization
- Operator CLI interface

### Attack Capabilities
- Automated reconnaissance and enumeration
- Multiple initial access vectors (SQLi, file upload, command injection)
- Privilege escalation exploits
- 5+ persistence mechanisms
- Network pivoting through compromised hosts
- Covert data exfiltration channels

### Defensive Evasion
- Payload obfuscation
- Anti-forensics techniques
- Log tampering and timestomping
- Traffic obfuscation

### Testing & Quality
- Comprehensive test suite (pytest)
- 70%+ code coverage
- Integration tests for full attack chain
- Defensive validation (blue team perspective)

## Project Structure

```
redcell/
├── c2/                    # Command & Control infrastructure
├── recon/                 # Reconnaissance tools
├── initial_access/        # Exploitation tools
├── post_exploitation/     # Post-exploitation modules
├── lateral_movement/      # Pivoting and lateral movement
├── exfiltration/         # Data exfiltration tools
├── evasion/              # Defensive evasion techniques
├── targets/              # Vulnerable target environments
├── docs/                 # Documentation and writeups
└── tests/                # Test suite
```

## Quick Start

### Prerequisites

- Docker & Docker Compose
- Python 3.9+
- Git

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd cyber

# Create Python virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Start target infrastructure
docker-compose up -d

# Run tests
pytest
```

### Usage

```bash
# Start the C2 server
python c2/server/main.py

# In another terminal, start the operator interface
python c2/operator/cli.py

# Deploy an implant to a target (example)
python initial_access/sqli_exploit.py --target http://target-ip
```

## Roadmap

See [ROADMAP.md](ROADMAP.md) for the complete implementation plan broken down into 6 phases over 12 weeks.

**Current Status:** Phase 1 - Foundation & Infrastructure

## Documentation

- [ROADMAP.md](ROADMAP.md) - Complete project roadmap and implementation plan
- [docs/writeups/](docs/writeups/) - Technical writeups for each phase
- [docs/reports/](docs/reports/) - Professional red team reports

## Ethical & Legal Notice

**IMPORTANT:** This project is designed exclusively for:
- Authorized security testing
- Educational purposes
- Portfolio demonstration
- Isolated lab environments

**Never use these tools on:**
- Systems you don't own
- Systems without explicit written authorization
- Production environments without proper authorization

All testing must be conducted in isolated, controlled lab environments. Unauthorized access to computer systems is illegal.

## Testing Strategy

This project includes comprehensive testing:

- **Unit Tests:** Individual tool and function testing
- **Integration Tests:** End-to-end attack chain validation
- **Manual Testing:** Operational security testing
- **Defensive Validation:** Blue team perspective analysis

Run tests with: `pytest -v --cov`

## Technologies Used

- **Python 3.9+** - Core language for tooling
- **Flask** - C2 server framework
- **Docker/Docker Compose** - Target environment isolation
- **pytest** - Testing framework
- **cryptography** - Encryption for C2 communications
- **requests** - HTTP client for exploits

## Learning Resources

This project draws from industry-standard frameworks and methodologies:

- MITRE ATT&CK Framework
- OWASP Top 10
- Red Team Field Manual (RTFM)
- NIST Cybersecurity Framework

## Contributing

This is a personal portfolio project, but suggestions and feedback are welcome via issues.

## License

This project is for educational purposes only. See [LICENSE](LICENSE) for details.

## Author

**Pete Sumners**
Cybersecurity Portfolio Project
Contact: petesumners@outlook.com
GitHub: [Your GitHub Profile]

## Acknowledgments

- MITRE ATT&CK for tactical framework
- OWASP for vulnerability patterns
- The cybersecurity community for tools and techniques

---

**Disclaimer:** The tools and techniques in this repository are provided for educational purposes and authorized security testing only. The author assumes no liability for misuse of this software.
