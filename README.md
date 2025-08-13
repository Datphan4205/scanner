# Network Security Scanner and Report Generator

## Overview

This project is a comprehensive Bash-based network security scanner that performs vulnerability assessment of target hosts and generates detailed security reports. The scanner combines local vulnerability detection with live data from the NIST National Vulnerability Database (NVD) to provide thorough security analysis.

## Features

### Core Functionality
- **Comprehensive Port Scanning**: Uses nmap with service version detection
- **Vulnerability Detection**: Employs NSE (Nmap Scripting Engine) vulnerability scripts
- **Local Vulnerability Database**: Built-in checks for known vulnerable service versions
- **NVD API Integration**: Live CVE data retrieval from NIST National Vulnerability Database
- **Detailed Reporting**: Well-formatted security reports with remediation recommendations
- **Command-line Interface**: Full argument parsing with help and version options

### Security Checks
The scanner identifies at least 8+ potential vulnerability categories:

1. **Outdated Service Versions**: Apache, nginx, OpenSSH, MySQL, PHP, etc.
2. **Known Backdoors**: vsftpd 2.3.4, etc.
3. **Insecure Protocols**: Telnet, unencrypted FTP, HTTP
4. **Default Configurations**: Default ports, weak authentication
5. **Legacy Software**: End-of-life applications
6. **Directory Traversal**: Apache path traversal vulnerabilities
7. **Remote Code Execution**: Samba, IIS vulnerabilities
8. **Information Disclosure**: SNMP, RPC services
9. **Authentication Bypass**: MySQL, SSH vulnerabilities
10. **Buffer Overflow**: Various service-specific vulnerabilities

## Requirements

### Required Dependencies
- **nmap**: Network scanning and service detection
  ```bash
  # Debian/Ubuntu
  sudo apt-get install nmap
  
  # RHEL/CentOS
  sudo yum install nmap
  
  # macOS
  brew install nmap
  ```

### Optional Dependencies (for enhanced features)
- **curl**: For NVD API integration
  ```bash
  # Debian/Ubuntu
  sudo apt-get install curl
  
  # RHEL/CentOS
  sudo yum install curl
  
  # macOS
  brew install curl
  ```

- **jq**: For JSON parsing of NVD API responses
  ```bash
  # Debian/Ubuntu
  sudo apt-get install jq
  
  # RHEL/CentOS
  sudo yum install jq
  
  # macOS
  brew install jq
  ```

## Installation

1. **Clone or Download**: Get the script files
   ```bash
   # Make the script executable
   chmod +x netscan.sh
   ```

2. **Verify Dependencies**: The script will automatically check for required tools
   ```bash
   ./netscan.sh --help
   ```

## Usage

### Basic Syntax
```bash
./netscan.sh [OPTIONS] <target_ip_or_hostname>
```

### Options
- `-h, --help`: Display help message and usage examples
- `-v, --version`: Show version information and feature list

### Examples

#### Scan a Test Target
```bash
./netscan.sh scanme.nmap.org
```

#### Scan Local Host
```bash
./netscan.sh 127.0.0.1
```

#### Scan Remote Host
```bash
./netscan.sh 192.168.1.1
```

#### Scan Domain
```bash
./netscan.sh www.example.com
```

### Output

The scanner generates:
1. **Console Output**: Real-time progress and summary
2. **Report File**: `security_scan_report.txt` with detailed findings

## nmap Commands Used

### Primary Scan Command
```bash
nmap -sV --script vuln -T4 --open <target>
```

**Explanation of flags:**
- `-sV`: Service version detection - identifies running services and their versions
- `--script vuln`: Runs all NSE vulnerability detection scripts
- `-T4`: Aggressive timing template for faster scanning
- `--open`: Only shows open ports to reduce noise

### Fallback Command
```bash
nmap -sV -T4 --open <target>
```
Used when the primary command fails, provides basic service detection without vulnerability scripts.

## Vulnerability Identification Process

### 1. NSE Script Analysis
- Executes nmap's built-in vulnerability scripts
- Searches for keywords: "VULNERABLE", "CVE-", "CRITICAL", "HIGH RISK"
- Provides immediate identification of known exploits

### 2. Service Version Analysis
- Parses nmap output for specific vulnerable versions
- Uses conditional logic (case statements) to match known vulnerable software
- Covers major services: Apache, nginx, OpenSSH, MySQL, PHP, Samba, IIS

### 3. Protocol Security Assessment
- Identifies insecure protocols (Telnet, unencrypted FTP)
- Flags potentially dangerous services (SNMP, RPC, VNC)
- Checks for services on default ports

### 4. NVD API Cross-Reference
- Queries NIST National Vulnerability Database for live CVE data
- Provides authoritative vulnerability information
- Includes CVSS scores and detailed descriptions

## Report Structure

### 1. Header Section
- Target information
- Scan timestamp
- Scanner version

### 2. Open Ports and Services
- Port numbers and protocols
- Service names and versions
- Service fingerprints

### 3. Vulnerability Analysis
- NSE vulnerability results
- Service version vulnerabilities
- Additional security concerns
- NVD API enriched data

### 4. Remediation Recommendations
- Immediate actions required
- Security hardening steps
- Ongoing security practices

### 5. Footer
- Report generation timestamp
- Tool version information
- Legal disclaimer

## Error Handling

### Dependency Checking
- Automatic verification of required tools
- Clear installation instructions for missing dependencies
- Graceful degradation when optional tools are unavailable

### Network Error Handling
- Ping connectivity testing with fallback
- nmap command failure recovery
- API timeout and error handling

### Input Validation
- Command-line argument validation
- Target format verification
- Error messages with usage instructions

## Ethical Considerations

### Legal Requirements
- **Authorization Required**: Only scan systems you own or have explicit permission to test
- **Responsible Disclosure**: Report vulnerabilities through proper channels
- **Compliance**: Follow local laws and regulations regarding network scanning

### Best Practices
- Use designated test targets (like scanme.nmap.org) for learning
- Avoid aggressive scanning of production systems
- Respect rate limits when using external APIs
- Document and report findings responsibly

### Rate Limiting
- NVD API integration includes built-in rate limiting
- Configurable result limits to avoid API blocking
- Defensive programming for API failures

## Technical Architecture

### Modular Design
- **Functions**: Separate functions for each major component
- **Error Handling**: Comprehensive error checking and recovery
- **Configuration**: Easy modification of scan parameters
- **Extensibility**: Simple addition of new vulnerability checks

### Key Functions
- `check_dependencies()`: Verify required tools
- `perform_nmap_scan()`: Execute network scanning
- `write_header()`: Generate report header
- `write_ports_section()`: Format port information
- `write_vulns_section()`: Analyze and report vulnerabilities
- `query_nvd()`: Interface with NVD API
- `write_recs_section()`: Generate recommendations
- `write_footer()`: Complete report formatting

## Development History

This project was developed through multiple iterations:

1. **Static Report Template**: Basic report structure and formatting
2. **Dynamic Framework**: Command-line arguments and function modularization
3. **Live Scanning**: Integration with nmap for real network data
4. **Version Control**: Git repository setup and management
5. **Vulnerability Analysis**: NSE scripts and local vulnerability database
6. **API Integration**: NVD database connectivity for live CVE data

## Contributing

### Adding New Vulnerability Checks
1. Edit the `write_vulns_section()` function
2. Add new case patterns for vulnerable services
3. Include CVE references and remediation advice
4. Test against known vulnerable targets

### Enhancing API Integration
1. Modify the `query_nvd()` function
2. Add error handling for new scenarios
3. Implement additional data sources
4. Ensure rate limiting compliance

## License

This project is developed for educational purposes. Use responsibly and in accordance with applicable laws and ethical guidelines.

## Version History

- **v3.0**: Full-featured scanner with NVD API integration
- **v2.0**: Added NSE vulnerability detection and local database
- **v1.0**: Basic port scanning and report generation

## Support

For issues or questions:
1. Check the built-in help: `./netscan.sh --help`
2. Verify dependencies are installed
3. Test with known targets like scanme.nmap.org
4. Review error messages for troubleshooting guidance

---

**Disclaimer**: This tool is intended for authorized security testing only. Users are responsible for ensuring they have proper authorization before scanning any network resources.



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

# Network Vulnerability Scanner and Report Generator

A comprehensive bash script for performing network security assessments and generating detailed vulnerability reports.

## Overview

This project is a command-line network security scanner that performs live port scanning using nmap and generates structured security reports. The scanner identifies open ports, running services, and provides a foundation for vulnerability assessment and security recommendations.

## Purpose / Learning Objectives

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

## Core Security Concepts in Practice

Once you’ve enumerated open ports and services, you need to translate that raw data into professional findings. This section defines the key terms your scanner will reference in its report.

### Attack Surface
The **attack surface** is the sum of all points where an attacker could try to enter or extract data.  
> In your script: each open port and service you discover expands the target’s attack surface.

### Enumeration
**Enumeration** is actively gathering information—live hosts, open ports, service versions, usernames, shares—to discover attack vectors.  
> In your script: `nmap -sV` service-version detection is your enumeration phase.

### Vulnerability
A **vulnerability** is a flaw in design, implementation, or configuration that can be exploited.  
> In your script: an open port alone isn’t a vulnerability, but **vsftpd 2.3.4** on port 21 is (because it has a known CVE backdoor).

### CVE (Common Vulnerabilities and Exposures)
A **CVE** ID (e.g. CVE-2021-44228) uniquely labels a publicly known vulnerability.  
> In your script: map service versions to their CVEs (e.g. “Apache httpd 2.4.48 → CVE-2021-40438”).

### Exploit
An **exploit** is code or a technique that actively leverages a vulnerability.  
> In your script: **do not** include exploit code—your role is reporting, not attacking.

### The Assessment Process
1. **Scan Target**: run your scanner against an IP.  
2. **Map Attack Surface**: list open ports/services.  
3. **Perform Enumeration**: gather service versions (`nmap -sV`).  
4. **Identify Vulnerabilities**: lookup associated CVEs.  
5. **Report Findings**: output “Port 80/tcp: Apache httpd 2.4.48 (CVE-2021-40438).”  
6. _(Out of scope)_ Exploitation: would be the attacker’s next step.


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