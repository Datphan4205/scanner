# Network Vulnerability Scanner and Report Generator

A comprehensive bash script for performing network security assessments and generating detailed vulnerability reports.

## Overview

This project is a command-line network security scanner that performs live port scanning using nmap and generates structured security reports. The scanner identifies open ports, running services, and provides a foundation for vulnerability assessment and security recommendations.

## Purpose/Learning Objectives

This project was developed as part of a bash scripting course focusing on:
- Master fundamental Linux command-line operations
- Understand and apply text processing techniques in Linux
- Develop and implement shell scripts for automation
- Apply scripting to security hardening and auditing
- Integrate external tools and commands within scripts
- Demonstrate understanding of scripting security best practices

## Features

### Current Implementation
- **Live Port Scanning**: Uses nmap with service version detection (`-sV`)
- **Host Reachability Check**: Ping verification before scanning
- **Structured Reporting**: Professional report format with timestamps
- **Error Handling**: Graceful fallback if nmap is not available
- **Input Validation**: Proper argument checking and usage instructions
- **Multiple Target Support**: Works with IP addresses, hostnames, and localhost

### Report Sections
1. **Header**: Target information and scan timestamp
2. **Open Ports and Detected Services**: Live nmap scan results with service versions
3. **Potential Vulnerabilities**: Framework ready for vulnerability assessment
4. **Recommendations**: Security hardening suggestions
5. **Footer**: Report metadata and generation information

## Installation Requirements

### Prerequisites
- **Bash shell** (compatible with macOS, Linux)
- **nmap** - Network scanning tool
- **Standard Unix utilities**: ping, grep, etc.

### Installing nmap


**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install nmap
```

## Usage

### Basic Syntax
```bash
./netscan.sh <target_ip_or_hostname>
```

### Examples
```bash
# Scan a test server
./netscan.sh scanme.nmap.org

# Scan localhost
./netscan.sh 127.0.0.1

# Scan a specific IP address
./netscan.sh 192.168.1.1
```

### Help
```bash
./netscan.sh
# Displays usage information and examples
```

## Sample Output

```
===============================
 Network Security Scan Report
===============================

Target IP/Hostname: scanme.nmap.org
Scan Date: Fri  1 Aug 2025 21:42:07 PKT

--- Open Ports and Detected Services ---

[+] Running nmap scan on scanme.nmap.org...
[+] This may take a moment...

22/tcp    open  ssh        OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)
80/tcp    open  http       Apache httpd 2.4.7 ((Ubuntu))
9929/tcp  open  nping-echo Nping echo
31337/tcp open  tcpwrapped

--- Potential Vulnerabilities Identified ---

- Vulnerability assessment pending
- Manual review recommended
- Consider running additional security tools

--- Recommendations for Remediation ---

- Update all software packages to latest versions
- Apply available security patches
- Implement proper firewall rules
- Review and harden service configurations
- Consider implementing intrusion detection systems
```

## Technical Implementation

### Script Architecture
The scanner follows a modular function-based design:

- `main()` - Primary execution flow and argument validation
- `is_alive()` - Host reachability verification
- `write_header()` - Report header generation
- `write_ports_section()` - Live nmap scanning and port detection
- `write_vulns_section()` - Vulnerability assessment framework
- `write_recs_section()` - Security recommendations
- `write_footer()` - Report conclusion and metadata

#### Thank you