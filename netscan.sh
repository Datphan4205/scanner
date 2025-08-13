#!/bin/bash

#
# Network Security Scanner Script
# Enhanced with vulnerability analysis using NSE and version checking
#

# Function to write the report header
write_header() {
    local target="$1"
    echo "==============================="
    echo " Network Security Scan Report"
    echo "==============================="
    echo ""
    echo "Target IP/Hostname: $target"
    echo "Scan Date: $(date)"
    echo ""
}

# Function to check if target is alive
is_alive() {
    local target="$1"
    echo "[+] Checking if $target is reachable..."
    
    # Use -c 1 to send only one packet, timeout after 3 seconds
    ping -c 1 -W 3 "$target" > /dev/null 2>&1
    
    if [ "$?" -eq 0 ]; then
        echo "[+] Target is reachable. Proceeding with scan."
        return 0
    else
        echo "[-] Target appears to be unreachable. Continuing scan anyway..." >&2
        return 1
    fi
}

# Function to query NVD API for vulnerability information
query_nvd() {
    local product="$1"
    local version="$2"
    # The NVD API is public but has rate limits. We'll request a small number of results.
    local results_limit=3
    
    echo # Add a newline for formatting
    echo "Querying NVD for vulnerabilities in: $product $version..."
    
    # The API needs a URL-encoded string. A simple space-to-%20 works for many cases.
    local search_query
    search_query=$(echo "$product $version" | sed 's/ /%20/g')
    
    local nvd_api_url="https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${search_query}&resultsPerPage=${results_limit}"
    
    # Use curl to fetch the data (-s for silent) and jq to parse the JSON response.
    # We pipe the output of curl directly into jq.
    local vulnerabilities_json
    vulnerabilities_json=$(curl -s "$nvd_api_url")
    
    # --- Defensive Programming: Check for Errors ---
    if [[ -z "$vulnerabilities_json" ]]; then
        echo "  [!] Error: Failed to fetch data from NVD. The API might be down or unreachable."
        return
    fi
    if echo "$vulnerabilities_json" | jq -e '.message' > /dev/null 2>&1; then
        echo "  [!] NVD API Error: $(echo "$vulnerabilities_json" | jq -r '.message' 2>/dev/null)"
        return
    fi
    if ! echo "$vulnerabilities_json" | jq -e '.vulnerabilities[0]' > /dev/null 2>&1; then
        echo "  [+] No vulnerabilities found in NVD for this keyword search."
        return
    fi
    # --- End Error Checks ---
    
    # This jq command filters the JSON and formats it for our report.
    # It extracts the CVE ID, the English description, and the severity.
    if command -v jq &> /dev/null; then
        echo "$vulnerabilities_json" | jq -r \
            '.vulnerabilities[] |
            "  CVE ID: \(.cve.id)\n  Description: \((.cve.descriptions[] | select(.lang=="en")).value | gsub("\n"; " "))\n  Severity: \(.cve.metrics.cvssMetricV31[0].cvssData.baseSeverity // .cve.metrics.cvssMetricV2[0].cvssData.baseSeverity // "N/A")\n---"' 2>/dev/null
    else
        echo "  [!] jq not available - cannot parse JSON response"
    fi
}

# Function to perform comprehensive nmap scan with vulnerability detection
perform_nmap_scan() {
    local target="$1"
    
    # Check if nmap is installed
    if ! command -v nmap &> /dev/null; then
        echo "Error: nmap is not installed. Please install nmap to perform scanning."
        return 1
    fi
    
    echo "[+] Running comprehensive nmap scan with vulnerability detection on $target..."
    echo "[+] This may take several minutes due to NSE script execution..."
    echo ""
    
    # Run enhanced nmap scan with service version detection and vulnerability scripts
    # -sV: Version detection
    # --script vuln: Run vulnerability detection scripts
    # -T4: Aggressive timing template for faster scanning
    # --open: Only show open ports
    local scan_results
    scan_results=$(nmap -sV --script vuln -T4 --open "$target" 2>/dev/null)
    
    # Store results in global variable for use by other functions
    GLOBAL_SCAN_RESULTS="$scan_results"
    
    # Check if nmap command was successful
    if [ $? -ne 0 ]; then
        echo "Warning: nmap scan encountered an issue. Falling back to basic scan..."
        GLOBAL_SCAN_RESULTS=$(nmap -sV -T4 --open "$target" 2>/dev/null)
    fi
    
    return 0
}

# Function to write ports section using stored scan results
write_ports_section() {
    local target="$1"
    
    echo "--- Open Ports and Detected Services ---"
    echo ""
    
    if [ -z "$GLOBAL_SCAN_RESULTS" ]; then
        echo "Error: No scan results available. Please run scan first."
        echo "Falling back to placeholder data:"
        echo "Port 80/tcp - http"
        echo "Port 443/tcp - https" 
        echo "Port 22/tcp - ssh"
        echo ""
        return 1
    fi
    
    # Extract and display only the port/service lines
    echo "$GLOBAL_SCAN_RESULTS" | grep "open" | head -20
    echo ""
}

# Function to write vulnerabilities section with intelligent analysis
write_vulns_section() {
    echo "--- Potential Vulnerabilities Identified ---"
    echo ""
    
    if [ -z "$GLOBAL_SCAN_RESULTS" ]; then
        echo "- No scan results available for vulnerability analysis"
        echo "- Manual review recommended"
        echo ""
        return 1
    fi
    
    local vulnerabilities_found=0
    
    # Strategy A: Search for high-confidence NSE vulnerability results
    echo "[+] Analyzing NSE vulnerability script results..."
    local nse_vulns
    nse_vulns=$(echo "$GLOBAL_SCAN_RESULTS" | grep -i "VULNERABLE\|CVE-\|CRITICAL\|HIGH RISK")
    
    if [ -n "$nse_vulns" ]; then
        echo ""
        echo "=== NSE Vulnerability Detection Results ==="
        echo "$nse_vulns" | while IFS= read -r line; do
            if [ -n "$line" ]; then
                echo "[!!] $line"
                vulnerabilities_found=$((vulnerabilities_found + 1))
            fi
        done
        echo ""
    fi
    
    # Strategy B: Version-based vulnerability checking using conditional logic
    echo "[+] Analyzing service versions for known vulnerabilities..."
    echo ""
    echo "=== Service Version Analysis ==="
    
    local version_vulns_found=0
    
    # Process scan results line by line for version analysis
    echo "$GLOBAL_SCAN_RESULTS" | while IFS= read -r line; do
        case "$line" in
            *"vsftpd 2.3.4"*)
                echo "[!!] CRITICAL: vsftpd 2.3.4 detected - Contains backdoor vulnerability (CVE-2011-2523)"
                echo "    Description: This version has a malicious backdoor that can be triggered"
                echo "    Recommendation: Immediately upgrade to vsftpd 3.x or later"
                echo ""
                version_vulns_found=$((version_vulns_found + 1))
                # Query NVD for additional information
                if command -v curl &> /dev/null && command -v jq &> /dev/null; then
                    query_nvd "vsftpd" "2.3.4"
                fi
                ;;
            *"Apache httpd 2.4.49"* | *"Apache/2.4.49"*)
                echo "[!!] HIGH: Apache 2.4.49 detected - Path traversal vulnerability (CVE-2021-41773)"
                echo "    Description: Directory traversal allowing unauthorized file access"
                echo "    Recommendation: Upgrade to Apache 2.4.51 or apply security patches"
                echo ""
                version_vulns_found=$((version_vulns_found + 1))
                # Query NVD for additional information
                if command -v curl &> /dev/null && command -v jq &> /dev/null; then
                    query_nvd "Apache httpd" "2.4.49"
                fi
                ;;
            *"Apache httpd 2.4.7"* | *"Apache/2.4.7"*)
                echo "[!!] MEDIUM: Apache 2.4.7 detected - Multiple known vulnerabilities"
                echo "    Description: This version predates many security fixes"
                echo "    Recommendation: Upgrade to latest Apache 2.4.x version"
                echo ""
                version_vulns_found=$((version_vulns_found + 1))
                # Query NVD for additional information
                if command -v curl &> /dev/null && command -v jq &> /dev/null; then
                    query_nvd "Apache httpd" "2.4.7"
                fi
                ;;
            *"OpenSSH 6.6"*)
                echo "[!!] MEDIUM: OpenSSH 6.6.x detected - Known security issues"
                echo "    Description: This version has multiple CVEs including user enumeration"
                echo "    Recommendation: Upgrade to OpenSSH 8.x or later"
                echo ""
                version_vulns_found=$((version_vulns_found + 1))
                # Query NVD for additional information
                if command -v curl &> /dev/null && command -v jq &> /dev/null; then
                    query_nvd "OpenSSH" "6.6"
                fi
                ;;
            *"Microsoft-IIS/6.0"*)
                echo "[!!] CRITICAL: IIS 6.0 detected - Multiple critical vulnerabilities"
                echo "    Description: Extremely outdated web server with known exploits"
                echo "    Recommendation: Immediate upgrade to supported IIS version"
                echo ""
                version_vulns_found=$((version_vulns_found + 1))
                # Query NVD for additional information
                if command -v curl &> /dev/null && command -v jq &> /dev/null; then
                    query_nvd "Microsoft IIS" "6.0"
                fi
                ;;
            *"Samba smbd 3.X"*)
                echo "[!!] HIGH: Samba 3.x detected - Multiple vulnerabilities including RCE"
                echo "    Description: Legacy version with remote code execution vulnerabilities"
                echo "    Recommendation: Upgrade to Samba 4.x with latest patches"
                echo ""
                version_vulns_found=$((version_vulns_found + 1))
                # Query NVD for additional information
                if command -v curl &> /dev/null && command -v jq &> /dev/null; then
                    query_nvd "Samba" "3.0"
                fi
                ;;
            *"nginx/1.4"*)
                echo "[!!] MEDIUM: nginx 1.4.x detected - Multiple known vulnerabilities"
                echo "    Description: This version has several CVEs including buffer overflow"
                echo "    Recommendation: Upgrade to nginx 1.20.x or later"
                echo ""
                version_vulns_found=$((version_vulns_found + 1))
                ;;
            *"PHP/5.3"*)
                echo "[!!] HIGH: PHP 5.3.x detected - End of life with critical vulnerabilities"
                echo "    Description: No longer supported with multiple security flaws"
                echo "    Recommendation: Upgrade to PHP 8.x immediately"
                echo ""
                version_vulns_found=$((version_vulns_found + 1))
                ;;
            *"MySQL 5.0"*)
                echo "[!!] HIGH: MySQL 5.0.x detected - Multiple security vulnerabilities"
                echo "    Description: Legacy version with authentication bypass issues"
                echo "    Recommendation: Upgrade to MySQL 8.0 or MariaDB latest"
                echo ""
                version_vulns_found=$((version_vulns_found + 1))
                ;;
        esac
    done
    
    # Additional security analysis
    echo "=== Additional Security Analysis ==="
    
    # Check for potentially dangerous services
    if echo "$GLOBAL_SCAN_RESULTS" | grep -q "telnet"; then
        echo "[!] WARNING: Telnet service detected - Unencrypted protocol"
        echo "    Recommendation: Replace with SSH for secure remote access"
        echo ""
    fi
    
    if echo "$GLOBAL_SCAN_RESULTS" | grep -q "ftp.*21/tcp"; then
        echo "[!] WARNING: FTP service detected on standard port"
        echo "    Recommendation: Ensure FTP is properly secured or use SFTP/FTPS"
        echo ""
    fi
    
    if echo "$GLOBAL_SCAN_RESULTS" | grep -q "mysql.*3306"; then
        echo "[!] WARNING: MySQL detected on default port"
        echo "    Recommendation: Verify access controls and consider port change"
        echo ""
    fi
    
    if echo "$GLOBAL_SCAN_RESULTS" | grep -q "rpcbind\|portmapper"; then
        echo "[!] WARNING: RPC services detected"
        echo "    Recommendation: Disable if not needed, restrict access if required"
        echo ""
    fi
    
    if echo "$GLOBAL_SCAN_RESULTS" | grep -q "snmp"; then
        echo "[!] WARNING: SNMP service detected"
        echo "    Recommendation: Use SNMPv3 with encryption, change default community strings"
        echo ""
    fi
    
    if echo "$GLOBAL_SCAN_RESULTS" | grep -q "smtp.*25/tcp"; then
        echo "[!] WARNING: SMTP service detected on standard port"
        echo "    Recommendation: Ensure proper authentication and encryption (TLS)"
        echo ""
    fi
    
    if echo "$GLOBAL_SCAN_RESULTS" | grep -q "pop3\|imap"; then
        echo "[!] WARNING: Email services detected"
        echo "    Recommendation: Use encrypted variants (POP3S/IMAPS)"
        echo ""
    fi
    
    if echo "$GLOBAL_SCAN_RESULTS" | grep -q "vnc"; then
        echo "[!] WARNING: VNC service detected"
        echo "    Recommendation: Use strong authentication and tunnel through SSH"
        echo ""
    fi
    
    # Summary check
    local total_issues=$(echo "$GLOBAL_SCAN_RESULTS" | grep -c -i "VULNERABLE\|CVE-\|CRITICAL")
    
    if [ "$total_issues" -eq 0 ]; then
        echo "[+] No obvious vulnerabilities detected in service versions"
        echo "[+] However, manual security assessment is still recommended"
        echo ""
    else
        echo "=== Vulnerability Summary ==="
        echo "[!] Total potential issues identified: $total_issues"
        echo "[!] Immediate security review and remediation recommended"
        echo ""
    fi
}

# Function to write enhanced recommendations section  
write_recs_section() {
    echo "--- Recommendations for Remediation ---"
    echo ""
    
    echo "=== Immediate Actions ==="
    echo "- Review all identified vulnerabilities above"
    echo "- Prioritize critical and high-risk findings"
    echo "- Apply security patches for outdated software"
    echo "- Update all services to latest stable versions"
    echo ""
    
    echo "=== Security Hardening ==="
    echo "- Implement proper firewall rules to limit exposed services"
    echo "- Disable unnecessary services and close unused ports"
    echo "- Configure services to run with minimal privileges"
    echo "- Enable logging and monitoring for security events"
    echo "- Implement intrusion detection/prevention systems"
    echo ""
    
    echo "=== Ongoing Security Practices ==="
    echo "- Establish regular vulnerability scanning schedule"
    echo "- Subscribe to security advisories for installed software"
    echo "- Implement configuration management and change control"
    echo "- Conduct periodic security assessments"
    echo "- Maintain incident response procedures"
    echo ""
}

# Function to write footer
write_footer() {
    echo "--- End of Report ---"
    echo ""
    echo "Report generated on: $(date)"
    echo "Generated by: Network Security Scanner v3.0 (with vulnerability analysis)"
    echo ""
    echo "DISCLAIMER: This scan is for authorized security assessment only."
    echo "Always ensure you have permission before scanning network resources."
}

# Function to check dependencies
check_dependencies() {
    local missing_deps=0
    
    echo "[+] Checking dependencies..."
    
    # Check for nmap
    if ! command -v nmap &> /dev/null; then
        echo "[-] ERROR: nmap is not installed"
        echo "    Install with: sudo apt-get install nmap (Debian/Ubuntu)"
        echo "                 sudo yum install nmap (RHEL/CentOS)"
        echo "                 brew install nmap (macOS)"
        missing_deps=$((missing_deps + 1))
    else
        echo "[+] nmap found: $(nmap --version | head -1)"
    fi
    
    # Check for curl
    if ! command -v curl &> /dev/null; then
        echo "[-] WARNING: curl is not installed - NVD API integration will be disabled"
        echo "    Install with: sudo apt-get install curl (Debian/Ubuntu)"
        echo "                 sudo yum install curl (RHEL/CentOS)"
        echo "                 brew install curl (macOS)"
    else
        echo "[+] curl found: $(curl --version | head -1)"
    fi
    
    # Check for jq
    if ! command -v jq &> /dev/null; then
        echo "[-] WARNING: jq is not installed - JSON parsing for NVD API will be disabled"
        echo "    Install with: sudo apt-get install jq (Debian/Ubuntu)"
        echo "                 sudo yum install jq (RHEL/CentOS)"
        echo "                 brew install jq (macOS)"
    else
        echo "[+] jq found: $(jq --version)"
    fi
    
    if [ "$missing_deps" -gt 0 ]; then
        echo ""
        echo "ERROR: Required dependencies are missing. Please install them and try again."
        exit 1
    fi
    
    echo "[+] All critical dependencies satisfied"
    echo ""
}

# Display usage information
usage() {
    echo "Network Security Scanner v3.0 (Enhanced with NVD API)"
    echo "======================================================"
    echo ""
    echo "Usage: $0 [OPTIONS] <target_ip_or_hostname>"
    echo ""
    echo "OPTIONS:"
    echo "  -h, --help    Show this help message"
    echo "  -v, --version Show version information"
    echo ""
    echo "Examples:"
    echo "  $0 scanme.nmap.org"
    echo "  $0 127.0.0.1"
    echo "  $0 192.168.1.1"
    echo "  $0 www.example.com"
    echo ""
    echo "Features:"
    echo "  • Comprehensive port scanning with service detection"
    echo "  • NSE vulnerability script execution"
    echo "  • Local vulnerability database checking"
    echo "  • NVD API integration for CVE information"
    echo "  • Detailed security recommendations"
    echo ""
    echo "Requirements:"
    echo "  • nmap (required)"
    echo "  • curl (optional, for NVD API)"
    echo "  • jq (optional, for JSON parsing)"
    echo ""
    echo "Note: This script requires nmap to be installed for live scanning."
    echo "      Ensure you have permission before scanning network resources."
    exit 1
}

# Display version information
version() {
    echo "Network Security Scanner v3.0"
    echo "Enhanced with vulnerability analysis and NVD API integration"
    echo ""
    echo "Features:"
    echo "  - Port scanning and service detection"
    echo "  - Vulnerability identification using NSE scripts"
    echo "  - Local vulnerability database"
    echo "  - NVD API integration for live CVE data"
    echo "  - Comprehensive security reporting"
    echo ""
    echo "Author: Security Assessment Project"
    echo "License: Educational Use Only"
    exit 0
}

# Main function to control script flow
main() {
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                usage
                ;;
            -v|--version)
                version
                ;;
            -*)
                echo "Error: Unknown option $1" >&2
                usage
                ;;
            *)
                TARGET="$1"
                shift
                ;;
        esac
    done
    
    # Input validation
    if [ -z "$TARGET" ]; then
        echo "Error: You must provide a target." >&2
        usage
    fi
    
    if [ "$#" -gt 0 ]; then
        echo "Error: Too many arguments provided." >&2
        usage
    fi
    
    local REPORT_FILE="security_scan_report.txt"
    
    echo "========================================"
    echo " Network Security Scanner v3.0"
    echo "========================================"
    echo ""
    echo "[*] Target: $TARGET"
    echo "[*] Report will be saved to: $REPORT_FILE"
    echo "[*] Scan started at: $(date)"
    echo ""
    
    # Check dependencies
    check_dependencies
    
    # Check if target is alive (but continue even if not responsive to ping)
    is_alive "$TARGET"
    
    echo "[*] Performing comprehensive scan with vulnerability analysis..."
    echo "[*] This process may take several minutes..."
    echo ""
    
    # Perform the enhanced nmap scan
    if ! perform_nmap_scan "$TARGET"; then
        echo "Error: Failed to perform nmap scan. Exiting."
        exit 1
    fi
    
    echo "[*] Generating detailed security report..."
    echo ""
    
    # Generate the complete report
    write_header "$TARGET" > "$REPORT_FILE"
    write_ports_section "$TARGET" >> "$REPORT_FILE"
    write_vulns_section >> "$REPORT_FILE"
    write_recs_section >> "$REPORT_FILE"
    write_footer >> "$REPORT_FILE"
    
    echo "[*] Comprehensive scan complete! Report saved to: $REPORT_FILE"
    echo "[*] Scan completed at: $(date)"
    echo ""
    echo "--- Report Preview ---"
    cat "$REPORT_FILE"
}

# Global variable to store scan results
GLOBAL_SCAN_RESULTS=""
TARGET=""

# Start the script by passing all command-line arguments to main
main "$@"