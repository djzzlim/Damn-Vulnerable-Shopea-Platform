import requests
import socket
import ssl
import sys
import time
import subprocess
import json
import os
import re
from urllib.parse import urljoin

# --- CONFIGURATION ---
TARGET_IP = "192.168.100.132"
BASE_URL = f"http://{TARGET_IP}/"
SSH_PORT = 22
SSH_USER = "shopea"
SSH_PASS = "shopea"

# Admin credentials for authenticated testing
ADMIN_USER = "admin@technovation.local"  # Change this to your admin email
ADMIN_PASS = "Abcd1234"  # Change this to your admin password

# Session management
authenticated_session = None

# List of directories to check for Directory Listing
DIRECTORIES = [
    "assets/", "includes/", "api/", "cp/templates/", "cp/docs/", 
    "cp/img/", "cp/js/", "cp/library/", "cp/styles/"
]

# Version database for vulnerable/unsupported components
COMPONENT_VERSIONS = {
    "jQuery": {
        "vulnerable": "3.1.1",
        "current": "3.7.1",
        "severity": "Critical",
        "cve": "Multiple XSS vulnerabilities",
        "references": "https://security.snyk.io/package/npm/jquery/3.1.1"
    },
    "Bootstrap": {
        "vulnerable": "3.3.7",
        "current": "5.3.8",
        "severity": "Critical",
        "cve": "Multiple vulnerabilities",
        "references": "https://endoflife.date/bootstrap"
    },
    "WordPress": {
        "vulnerable": "2.8.6",
        "current": "6.9",
        "severity": "Critical",
        "cve": "Multiple critical vulnerabilities",
        "references": "https://endoflife.date/wordpress"
    },
    "phpMyAdmin": {
        "vulnerable": "3.5.2.2",
        "current": "5.2.3",
        "severity": "Critical",
        "cve": "Multiple vulnerabilities including RCE",
        "references": "https://endoflife.date/phpmyadmin"
    },
    "Webgrind": {
        "vulnerable": "1.0",
        "current": "1.9.4",
        "severity": "Critical",
        "cve": "CVE-2012-1790",
        "references": "https://nvd.nist.gov/vuln/detail/CVE-2012-1790"
    },
    "Apache": {
        "vulnerable": "2.2.22",
        "current": "2.4.66",
        "severity": "Critical",
        "cve": "End of Life, multiple vulnerabilities",
        "references": "https://endoflife.date/apache-http-server"
    },
    "PHP": {
        "vulnerable": "5.3.10",
        "current": "8.5",
        "severity": "Critical",
        "cve": "End of Life, multiple critical vulnerabilities",
        "references": "https://endoflife.date/php"
    },
    "MySQL": {
        "vulnerable": "5.5.62",
        "current": "9.6",
        "severity": "Critical",
        "cve": "End of Life, multiple vulnerabilities",
        "references": "https://endoflife.date/mysql"
    },
    "OpenSSH": {
        "vulnerable": "5.9p1",
        "current": "10.2",
        "severity": "Critical",
        "cve": "CVE-2016-6210 and others",
        "references": "https://ubuntu.com/security/CVE-2016-6210"
    },
    "Ubuntu": {
        "vulnerable": "12.04",
        "current": "24.04.3 LTS",
        "severity": "Critical",
        "cve": "End of Life, no security updates",
        "references": "https://endoflife.date/ubuntu"
    },
    "Python": {
        "vulnerable": "2.7.3",
        "current": "3.14.2",
        "severity": "Critical",
        "cve": "End of Life, no security updates",
        "references": "https://endoflife.date/python"
    },
    "Perl": {
        "vulnerable": "5.14.2",
        "current": "5.42.0",
        "severity": "Critical",
        "cve": "End of Life",
        "references": "https://endoflife.date/perl"
    }
}

# --- COLORS FOR OUTPUT ---
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    CRITICAL = '\033[91m\033[1m'  # Bold red

def print_result(vulnerability, status, detail=""):
    if status == "VULNERABLE":
        print(f"[{Colors.FAIL}VULNERABLE{Colors.ENDC}] {vulnerability}: {detail}")
    elif status == "CRITICAL":
        print(f"[{Colors.CRITICAL}CRITICAL{Colors.ENDC}] {vulnerability}: {detail}")
    elif status == "RESOLVED":
        print(f"[{Colors.OKGREEN}RESOLVED{Colors.ENDC}] {vulnerability}")
    elif status == "SKIPPED":
        print(f"[{Colors.WARNING}SKIPPED{Colors.ENDC}] {vulnerability}: {detail}")
    else:
        print(f"[{Colors.OKBLUE}INFO{Colors.ENDC}] {vulnerability}: {detail}")

# Helper function to login and get authenticated session
def get_authenticated_session():
    global authenticated_session
    if authenticated_session:
        return authenticated_session
    
    session = requests.Session()
    login_url = f"http://{TARGET_IP}/api/login.php"
    
    # Matching the hardcoded credentials from your source code
    login_data = {
        "email": "admin@technovation.local",
        "password": "Abcd1234"
    }
    
    try:
        # allow_redirects=True is default, which is good here
        response = session.post(login_url, data=login_data, timeout=5)
        
        # 1. Check if the session cookie was set
        if 'PHPSESSID' in session.cookies:
            # 2. Check if we successfully landed on the admin page
            if "admin.php" in response.url or response.status_code == 200:
                print("✓ Authentication successful (PHPSESSID obtained)")
                authenticated_session = session
                return session
        
        print("✗ Authentication failed: Check credentials or redirect logic")
        return None

    except Exception as e:
        print(f"✗ Error: {e}")
        return None

# 0. Vulnerable Component Detection
def check_vulnerable_components():
    print(f"\n{Colors.HEADER}--- Checking Vulnerable & Unsupported Components ---{Colors.ENDC}")
    
    vulnerabilities_found = []
    
    # Check web components
    print(f"\n{Colors.OKBLUE}Checking Web Components...{Colors.ENDC}")
    web_vulns = check_web_components()
    vulnerabilities_found.extend(web_vulns)
    
    # Check system components via SSH
    print(f"\n{Colors.OKBLUE}Checking System Components via SSH...{Colors.ENDC}")
    system_vulns = check_system_components()
    vulnerabilities_found.extend(system_vulns)
    
    # Summary
    if vulnerabilities_found:
        print(f"\n{Colors.CRITICAL}╔═════════════════════════════════════════════════════════╗{Colors.ENDC}")
        print(f"{Colors.CRITICAL}║  CRITICAL: {len(vulnerabilities_found)} Vulnerable/Unsupported Components Found  ║{Colors.ENDC}")
        print(f"{Colors.CRITICAL}╚═════════════════════════════════════════════════════════╝{Colors.ENDC}")
    else:
        print(f"\n{Colors.OKGREEN}✓ All components are up to date{Colors.ENDC}")

def check_web_components():
    """Check web-based components (jQuery, Bootstrap, WordPress, etc.)"""
    vulnerabilities = []
    
    try:
        # Check main page
        response = requests.get(BASE_URL, timeout=5)
        content = response.text
        
        # Check jQuery
        jquery_match = re.search(r'jquery[/-](\d+\.\d+\.\d+)', content, re.IGNORECASE)
        if jquery_match:
            version = jquery_match.group(1)
            if version == COMPONENT_VERSIONS["jQuery"]["vulnerable"]:
                print_result(
                    f"jQuery {version}",
                    "CRITICAL",
                    f"Outdated! Current: {COMPONENT_VERSIONS['jQuery']['current']}"
                )
                vulnerabilities.append("jQuery")
            else:
                print_result(f"jQuery {version}", "RESOLVED")
        
        # Check Bootstrap
        bootstrap_match = re.search(r'bootstrap[/-](\d+\.\d+\.\d+)', content, re.IGNORECASE)
        if bootstrap_match:
            version = bootstrap_match.group(1)
            if version == COMPONENT_VERSIONS["Bootstrap"]["vulnerable"]:
                print_result(
                    f"Bootstrap {version}",
                    "CRITICAL",
                    f"Outdated! Current: {COMPONENT_VERSIONS['Bootstrap']['current']}"
                )
                vulnerabilities.append("Bootstrap")
            else:
                print_result(f"Bootstrap {version}", "RESOLVED")
        
        # Check WordPress
        wp_paths = ["/wp/", "/wp-admin/", "/wordpress/"]
        for wp_path in wp_paths:
            try:
                wp_response = requests.get(f"http://{TARGET_IP}{wp_path}", timeout=3)
                wp_version_match = re.search(r'WordPress (\d+\.\d+\.\d+)', wp_response.text)
                if not wp_version_match:
                    wp_version_match = re.search(r'ver=(\d+\.\d+\.\d+)', wp_response.text)
                
                if wp_version_match:
                    version = wp_version_match.group(1)
                    if version.startswith("2."):
                        print_result(
                            f"WordPress {version}",
                            "CRITICAL",
                            f"Extremely outdated! Current: {COMPONENT_VERSIONS['WordPress']['current']}"
                        )
                        vulnerabilities.append("WordPress")
                        break
            except:
                pass
        
        # Check phpMyAdmin
        try:
            pma_response = requests.get(f"http://{TARGET_IP}/phpmyadmin/", timeout=3)
            pma_match = re.search(r'PMA_VERSION":"(\d+\.\d+\.\d+)', pma_response.text)
            if not pma_match:
                pma_match = re.search(r'phpMyAdmin (\d+\.\d+\.\d+)', pma_response.text)
            
            if pma_match:
                version = pma_match.group(1)
                if version == COMPONENT_VERSIONS["phpMyAdmin"]["vulnerable"]:
                    print_result(
                        f"phpMyAdmin {version}",
                        "CRITICAL",
                        f"Critical vulnerabilities! Current: {COMPONENT_VERSIONS['phpMyAdmin']['current']}"
                    )
                    vulnerabilities.append("phpMyAdmin")
                else:
                    print_result(f"phpMyAdmin {version}", "RESOLVED")
        except:
            pass
        
        # Check Webgrind
        try:
            wg_response = requests.get(f"http://{TARGET_IP}/webgrind/", timeout=3)
            if "webgrind" in wg_response.text.lower():
                wg_match = re.search(r'Webgrind (\d+\.\d+)', wg_response.text, re.IGNORECASE)
                if wg_match:
                    version = wg_match.group(1)
                    if version == COMPONENT_VERSIONS["Webgrind"]["vulnerable"]:
                        print_result(
                            f"Webgrind {version}",
                            "CRITICAL",
                            f"CVE-2012-1790! Current: {COMPONENT_VERSIONS['Webgrind']['current']}"
                        )
                        vulnerabilities.append("Webgrind")
        except:
            pass
        
        # Check Apache (from headers)
        server_header = response.headers.get('Server', '')
        apache_match = re.search(r'Apache/(\d+\.\d+\.\d+)', server_header)
        if apache_match:
            version = apache_match.group(1)
            if version == COMPONENT_VERSIONS["Apache"]["vulnerable"]:
                print_result(
                    f"Apache {version}",
                    "CRITICAL",
                    f"End of Life! Current: {COMPONENT_VERSIONS['Apache']['current']}"
                )
                vulnerabilities.append("Apache")
        
        # Check PHP (from headers)
        php_header = response.headers.get('X-Powered-By', '')
        php_match = re.search(r'PHP/(\d+\.\d+\.\d+)', php_header)
        if php_match:
            version = php_match.group(1)
            if version.startswith("5.3"):
                print_result(
                    f"PHP {version}",
                    "CRITICAL",
                    f"End of Life! Current: {COMPONENT_VERSIONS['PHP']['current']}"
                )
                vulnerabilities.append("PHP")
    
    except Exception as e:
        print_result("Web Components", "INFO", f"Error checking: {str(e)}")
    
    return vulnerabilities

def check_system_components():
    """Check system components via SSH"""
    vulnerabilities = []
    
    # Check if paramiko is available for SSH
    try:
        import paramiko
    except ImportError:
        print_result("System Components", "INFO", 
                    "Install paramiko for SSH checks: pip install paramiko")
        return vulnerabilities
    
    try:
        # Connect via SSH
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        print(f"{Colors.OKBLUE}Connecting to SSH ({SSH_USER}@{TARGET_IP})...{Colors.ENDC}")
        ssh.connect(TARGET_IP, port=SSH_PORT, username=SSH_USER, password=SSH_PASS, timeout=10)
        
        # Check OpenSSH version (already got from banner, but confirm)
        stdin, stdout, stderr = ssh.exec_command('ssh -V 2>&1')
        ssh_version = stdout.read().decode().strip()
        if "OpenSSH_5.9p1" in ssh_version:
            print_result(
                "OpenSSH 5.9p1",
                "CRITICAL",
                f"CVE-2016-6210! Current: {COMPONENT_VERSIONS['OpenSSH']['current']}"
            )
            vulnerabilities.append("OpenSSH")
        
        # Check Ubuntu version
        stdin, stdout, stderr = ssh.exec_command('lsb_release -a 2>/dev/null')
        ubuntu_info = stdout.read().decode()
        if "12.04" in ubuntu_info:
            print_result(
                "Ubuntu 12.04 LTS",
                "CRITICAL",
                f"End of Life! Current: {COMPONENT_VERSIONS['Ubuntu']['current']}"
            )
            vulnerabilities.append("Ubuntu")
        
        # Check Python version
        stdin, stdout, stderr = ssh.exec_command('python --version 2>&1')
        python_version = stdout.read().decode().strip()
        if "Python 2.7" in python_version:
            print_result(
                f"{python_version}",
                "CRITICAL",
                f"End of Life! Current: {COMPONENT_VERSIONS['Python']['current']}"
            )
            vulnerabilities.append("Python")
        
        # Check PHP version
        stdin, stdout, stderr = ssh.exec_command('php -v 2>&1 | head -1')
        php_version = stdout.read().decode().strip()
        if "PHP 5.3" in php_version:
            print_result(
                f"{php_version}",
                "CRITICAL",
                f"End of Life! Current: {COMPONENT_VERSIONS['PHP']['current']}"
            )
            vulnerabilities.append("PHP")
        
        # Check Perl version
        stdin, stdout, stderr = ssh.exec_command('perl -v 2>&1 | grep "This is perl"')
        perl_version = stdout.read().decode().strip()
        if "v5.14.2" in perl_version:
            print_result(
                "Perl 5.14.2",
                "CRITICAL",
                f"Outdated! Current: {COMPONENT_VERSIONS['Perl']['current']}"
            )
            vulnerabilities.append("Perl")
        
        # Check MySQL version
        stdin, stdout, stderr = ssh.exec_command('mysql --version 2>&1')
        mysql_version = stdout.read().decode().strip()
        if "5.5.62" in mysql_version or "Distrib 5.5" in mysql_version:
            print_result(
                "MySQL 5.5.62",
                "CRITICAL",
                f"End of Life! Current: {COMPONENT_VERSIONS['MySQL']['current']}"
            )
            vulnerabilities.append("MySQL")
        
        ssh.close()
        print(f"{Colors.OKGREEN}SSH connection closed{Colors.ENDC}")
    
    except paramiko.AuthenticationException:
        print_result("SSH Authentication", "INFO", f"Failed with {SSH_USER}:{SSH_PASS}")
    except Exception as e:
        print_result("System Components", "INFO", f"SSH check failed: {str(e)}")
    
    return vulnerabilities

# 1. Infrastructure Banner Grabbing
def check_banners():
    print(f"\n{Colors.HEADER}--- Checking Infrastructure Banners ---{Colors.ENDC}")
    
    # Check SSH Banner
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((TARGET_IP, SSH_PORT))
        banner = s.recv(1024).decode().strip()
        s.close()
        if "OpenSSH_5.9p1" in banner:
            print_result("OpenSSH Version", "VULNERABLE", f"Detected old version: {banner}")
        else:
            print_result("OpenSSH Version", "RESOLVED", f"Current: {banner}")
    except Exception as e:
        print_result("SSH Connection", "INFO", f"Could not connect: {e}")

    # Check Web Banners (Apache/PHP)
    try:
        response = requests.get(BASE_URL, timeout=5)
        server_header = response.headers.get('Server', '')
        powered_by = response.headers.get('X-Powered-By', '')
        
        if "Apache/2.2.22" in server_header:
            print_result("Apache Version", "VULNERABLE", f"Detected: {server_header}")
        else:
            print_result("Apache Version", "RESOLVED", f"Current: {server_header}")
            
        if "PHP/5.3.10" in powered_by:
            print_result("PHP Version", "VULNERABLE", f"Detected: {powered_by}")
        else:
            print_result("PHP Version", "RESOLVED", f"Current: {powered_by}")
    except Exception as e:
        print(f"Error checking web banners: {e}")

# 1b. SSH Configuration Audit
def check_ssh_configuration():
    print(f"\n{Colors.HEADER}--- Checking SSH Configuration (Weak Algorithms) ---{Colors.ENDC}")
    
    # Check if ssh-audit is installed
    ssh_audit_available = False
    try:
        result = subprocess.run(['ssh-audit', '--help'], capture_output=True, timeout=5)
        ssh_audit_available = True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    
    if ssh_audit_available:
        print(f"{Colors.OKBLUE}Running ssh-audit...{Colors.ENDC}")
        try:
            # Run ssh-audit with JSON output for easier parsing
            result = subprocess.run(
                ['ssh-audit', '-j', TARGET_IP],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            # Parse the output
            vulnerabilities = parse_ssh_audit_output(result.stdout)
            
            if vulnerabilities:
                total_issues = sum(len(v) for v in vulnerabilities.values())
                print_result(
                    "SSH Configuration",
                    "VULNERABLE",
                    f"Found {total_issues} weak algorithm(s)"
                )
                
                # Display by category
                if vulnerabilities.get('kex'):
                    print(f"\n  {Colors.FAIL}Weak Key Exchange Algorithms:{Colors.ENDC}")
                    for algo in vulnerabilities['kex']:
                        print(f"    • {algo}")
                
                if vulnerabilities.get('encryption'):
                    print(f"\n  {Colors.FAIL}Weak Encryption Algorithms:{Colors.ENDC}")
                    for algo in vulnerabilities['encryption']:
                        print(f"    • {algo}")
                
                if vulnerabilities.get('mac'):
                    print(f"\n  {Colors.FAIL}Weak MAC Algorithms:{Colors.ENDC}")
                    for algo in vulnerabilities['mac']:
                        print(f"    • {algo}")
                
                if vulnerabilities.get('key'):
                    print(f"\n  {Colors.FAIL}Weak Host Key Algorithms:{Colors.ENDC}")
                    for algo in vulnerabilities['key']:
                        print(f"    • {algo}")
            else:
                print_result("SSH Configuration", "RESOLVED", "No weak algorithms detected")
        
        except subprocess.TimeoutExpired:
            print_result("SSH Configuration", "INFO", "ssh-audit timed out")
        except Exception as e:
            print_result("SSH Configuration", "INFO", f"Error running ssh-audit: {str(e)}")
    else:
        # Fallback: Manual check for known weak algorithms
        print(f"{Colors.WARNING}ssh-audit not found. Using manual detection...{Colors.ENDC}")
        print(f"{Colors.OKBLUE}Install ssh-audit for comprehensive testing: pip install ssh-audit{Colors.ENDC}\n")
        
        manual_check_ssh()

def parse_ssh_audit_output(json_output):
    """Parse ssh-audit JSON output to extract weak algorithms"""
    vulnerabilities = {
        'kex': [],
        'encryption': [],
        'mac': [],
        'key': []
    }
    
    try:
        import json
        data = json.loads(json_output)
        
        # Check key exchange algorithms
        if 'kex' in data:
            for kex in data['kex']:
                if kex.get('algorithm'):
                    algo = kex['algorithm']
                    # Check for weak algorithms
                    if any(weak in algo.lower() for weak in [
                        'sha1', 'group1', 'group14-sha1', 'group-exchange-sha1'
                    ]):
                        vulnerabilities['kex'].append(algo)
        
        # Check encryption algorithms
        if 'encryption' in data:
            for enc in data['encryption']:
                if enc.get('algorithm'):
                    algo = enc['algorithm']
                    if any(weak in algo.lower() for weak in [
                        '3des', 'arcfour', 'blowfish', 'cast128', 
                        'rijndael', 'cbc'
                    ]):
                        vulnerabilities['encryption'].append(algo)
        
        # Check MAC algorithms
        if 'mac' in data:
            for mac in data['mac']:
                if mac.get('algorithm'):
                    algo = mac['algorithm']
                    if any(weak in algo.lower() for weak in [
                        'md5', 'sha1', 'ripemd', 'sha2-256-96', 'sha2-512-96'
                    ]):
                        vulnerabilities['mac'].append(algo)
        
        # Check host key algorithms
        if 'key' in data:
            for key in data['key']:
                if key.get('algorithm'):
                    algo = key['algorithm']
                    if any(weak in algo.lower() for weak in [
                        'ssh-dss', 'ssh-rsa', 'ecdsa-sha2-nistp256'
                    ]):
                        vulnerabilities['key'].append(algo)
    
    except Exception:
        # If JSON parsing fails, try text parsing
        vulnerabilities = parse_ssh_audit_text(json_output)
    
    # Remove empty categories
    return {k: v for k, v in vulnerabilities.items() if v}

def parse_ssh_audit_text(text_output):
    """Fallback parser for non-JSON output"""
    vulnerabilities = {
        'kex': [],
        'encryption': [],
        'mac': [],
        'key': []
    }
    
    # Known weak algorithms from your list
    weak_algorithms = {
        'kex': [
            'diffie-hellman-group-exchange-sha256',
            'diffie-hellman-group-exchange-sha1',
            'diffie-hellman-group1-sha1',
            'diffie-hellman-group14-sha1'
        ],
        'encryption': [
            '3des-cbc', 'arcfour', 'arcfour128', 'arcfour256',
            'blowfish-cbc', 'cast128-cbc', 'rijndael-cbc@lysator.liu.se',
            'aes128-cbc', 'aes192-cbc', 'aes256-cbc'
        ],
        'mac': [
            'hmac-md5', 'hmac-md5-96', 'hmac-ripemd160',
            'hmac-ripemd160@openssh.com', 'hmac-sha1', 'hmac-sha1-96',
            'hmac-sha2-256', 'hmac-sha2-256-96', 'hmac-sha2-512', 'hmac-sha2-512-96'
        ],
        'key': [
            'ecdsa-sha2-nistp256', 'ssh-dss', 'ssh-rsa'
        ]
    }
    
    # Check which weak algorithms appear in output
    text_lower = text_output.lower()
    for category, algos in weak_algorithms.items():
        for algo in algos:
            if algo.lower() in text_lower:
                vulnerabilities[category].append(algo)
    
    return {k: v for k, v in vulnerabilities.items() if v}

def manual_check_ssh():
    """Manual SSH weak algorithm detection when ssh-audit is not available"""
    try:
        import paramiko
        
        # Known weak algorithms
        weak_findings = {
            'kex': [],
            'encryption': [],
            'mac': [],
            'key': []
        }
        
        transport = paramiko.Transport((TARGET_IP, SSH_PORT))
        transport.connect()
        
        # Get server's supported algorithms
        server_kex = transport.get_security_options().kex
        server_ciphers = transport.get_security_options().ciphers
        server_macs = transport.get_security_options().digests
        server_keys = transport.get_security_options().key_types
        
        transport.close()
        
        # Check for weak algorithms
        weak_kex = ['diffie-hellman-group1-sha1', 'diffie-hellman-group14-sha1', 
                    'diffie-hellman-group-exchange-sha1']
        weak_ciphers = ['3des-cbc', 'arcfour', 'blowfish-cbc', 'cast128-cbc', 
                        'aes128-cbc', 'aes192-cbc', 'aes256-cbc']
        weak_macs = ['hmac-md5', 'hmac-sha1', 'hmac-ripemd160']
        weak_keys = ['ssh-dss', 'ssh-rsa', 'ecdsa-sha2-nistp256']
        
        for kex in server_kex:
            if any(weak in kex for weak in weak_kex):
                weak_findings['kex'].append(kex)
        
        for cipher in server_ciphers:
            if any(weak in cipher for weak in weak_ciphers):
                weak_findings['encryption'].append(cipher)
        
        for mac in server_macs:
            if any(weak in mac for weak in weak_macs):
                weak_findings['mac'].append(mac)
        
        for key in server_keys:
            if any(weak in key for weak in weak_keys):
                weak_findings['key'].append(key)
        
        # Display results
        if any(weak_findings.values()):
            print_result("SSH Configuration", "VULNERABLE", "Weak algorithms detected")
            for category, algos in weak_findings.items():
                if algos:
                    print(f"  {Colors.FAIL}Weak {category.upper()}:{Colors.ENDC} {', '.join(algos)}")
        else:
            print_result("SSH Configuration", "RESOLVED", "No common weak algorithms found")
    
    except ImportError:
        print_result("SSH Configuration", "INFO", 
                    "Install paramiko (pip install paramiko) or ssh-audit for SSH testing")
    except Exception as e:
        print_result("SSH Configuration", "INFO", f"Could not check SSH: {str(e)}")

# 2. HTTP Security Headers & Cookies
def check_http_security():
    print(f"\n{Colors.HEADER}--- Checking HTTP Security Headers & Cookies ---{Colors.ENDC}")
    try:
        response = requests.get(BASE_URL)
        headers = response.headers
        
        required_headers = {
            "Strict-Transport-Security": "HSTS Missing",
            "Content-Security-Policy": "CSP Missing",
            "X-Frame-Options": "Clickjacking protection missing",
            "X-Content-Type-Options": "MIME sniffing protection missing",
            "X-XSS-Protection": "XSS Filter missing"
        }
        
        for header, desc in required_headers.items():
            if header not in headers:
                print_result(f"Header: {header}", "VULNERABLE", desc)
            else:
                print_result(f"Header: {header}", "RESOLVED")

        # Cookie Flags
        if 'Set-Cookie' in headers:
            cookies = response.cookies
            for cookie in cookies:
                if not cookie.secure:
                    print_result(f"Cookie: {cookie.name}", "VULNERABLE", "Missing Secure flag")
                if not cookie.has_nonstandard_attr('HttpOnly') and not cookie.http_only:
                     print_result(f"Cookie: {cookie.name}", "VULNERABLE", "Missing HttpOnly flag")
        else:
            print_result("Cookies", "INFO", "No cookies sent by server")

    except Exception as e:
        print(f"Error checking security headers: {e}")

# 3. Path & Directory Listing Checks
def check_paths():
    print(f"\n{Colors.HEADER}--- Checking Sensitive Paths & Directory Listing ---{Colors.ENDC}")
    
    # Check Directory Listing
    for folder in DIRECTORIES:
        url = urljoin(BASE_URL, folder)
        try:
            r = requests.get(url)
            if "Index of /" in r.text or "Parent Directory" in r.text:
                print_result(f"Directory Listing: {folder}", "VULNERABLE")
            else:
                print_result(f"Directory Listing: {folder}", "RESOLVED")
        except:
            pass

    # Check XML-RPC
    xmlrpc_url = urljoin(BASE_URL, "wp/xmlrpc.php")
    try:
        r = requests.get(xmlrpc_url)
        if r.status_code == 200 or r.status_code == 405:
             print_result("XML-RPC Attack", "VULNERABLE", f"Path exists at {xmlrpc_url}")
        else:
             print_result("XML-RPC Attack", "RESOLVED")
    except:
        pass

# 4. HTTP Methods (Junk Methods)
def check_methods():
    print(f"\n{Colors.HEADER}--- Checking for Junk HTTP Method (ABC) ---{Colors.ENDC}")
    
    method = 'ABC'
    try:
        r = requests.request(method, BASE_URL, timeout=5)

        if r.status_code < 400:
            print_result(
                "HTTP Junk Methods", 
                "VULNERABLE", 
                f"Server accepted custom method '{method}' (Status: {r.status_code})"
            )
        else:
            print_result(
                "HTTP Junk Methods", 
                "RESOLVED", 
                f"Server correctly rejected '{method}' (Status: {r.status_code})"
            )

    except Exception as e:
        print_result("HTTP Junk Methods", "INFO", f"Error during test: {str(e)}")

# 5. Hardcoded Credentials Check
def check_hardcoded_credentials():
    print(f"\n{Colors.HEADER}--- Checking Hardcoded Credentials ---{Colors.ENDC}")
    
    targets = [
        {
            "name": "Menubar.php (Database Credentials)",
            "url": f"http://{TARGET_IP}/includes/menubar.php",
            "credentials": [
                {"username": "admin@technovation.local", "password": "Abcd1234"}
            ]
        },
        {
            "name": "DB Config via File Viewer (LFI)",
            "url": f"http://{TARGET_IP}/cp/index.php?op=fileviewer&file=../db.php",
            "credentials": [
                {"username": "root", "password": "root"}
            ]
        }
    ]
    
    for target in targets:
        try:
            response = requests.get(target['url'], timeout=5)
            
            found_creds = []
            for cred in target['credentials']:
                if cred['username'] in response.text and cred['password'] in response.text:
                    found_creds.append(f"{cred['username']}:{cred['password']}")
                elif cred['username'] in response.text or cred['password'] in response.text:
                    found_creds.append(f"Partial match for {cred['username']}")
            
            if found_creds:
                print_result(
                    target['name'],
                    "VULNERABLE",
                    f"Exposed credentials: {', '.join(found_creds)}"
                )
            else:
                if response.status_code == 200 and len(response.text) > 100:
                    print_result(
                        target['name'],
                        "VULNERABLE",
                        "File accessible but credentials not in plain text"
                    )
                else:
                    print_result(target['name'], "RESOLVED")
        
        except Exception as e:
            print_result(target['name'], "INFO", f"Could not access: {str(e)}")

# 6. HTML Injection Check
def check_html_injection():
    print(f"\n{Colors.HEADER}--- Checking HTML Injection ---{Colors.ENDC}")
    
    test_payloads = [
        {
            "marker": "HTMLINJ12345",
            "payload": "<h1>HTMLINJ12345</h1>"
        },
        {
            "marker": "IFRAMETEST",
            "payload": "<iframe src='http://attacker.com'></iframe>"
        },
        {
            "marker": "IMGTEST",
            "payload": "<img src=x onerror='console.log(\"IMGTEST\")'>"
        }
    ]
    
    targets = [
        {
            "name": "Search Page (search parameter)",
            "url": f"http://{TARGET_IP}/index.php",
            "method": "GET",
            "param": "search",
            "params": {
                "search": ""
            },
            "requires_auth": False
        }
    ]
    
    for target in targets:
        print(f"\n{Colors.WARNING}Testing: {target['name']}{Colors.ENDC}")
        
        # Check if authentication is required
        if target.get('requires_auth'):
            session = get_authenticated_session()
            if not session:
                print_result(
                    target['name'],
                    "SKIPPED",
                    f"Authentication required. Set ADMIN_USER and ADMIN_PASS in script."
                )
                continue
        else:
            session = requests.Session()
        
        vulnerable_payloads = []
        
        for payload_test in test_payloads:
            try:
                if target['method'] == "POST":
                    test_data = target['data'].copy()
                    test_data[target['param']] = payload_test['payload']
                    response = session.post(target['url'], data=test_data, timeout=5, allow_redirects=True)
                else:
                    test_params = target['params'].copy()
                    test_params[target['param']] = payload_test['payload']
                    response = session.get(target['url'], params=test_params, timeout=5, allow_redirects=True)
                
                if payload_test['marker'] in response.text:
                    if payload_test['payload'] in response.text:
                        vulnerable_payloads.append(f"Raw HTML: {payload_test['payload'][:50]}")
                    else:
                        vulnerable_payloads.append(f"Encoded reflection: {payload_test['marker']}")
                
            except Exception as e:
                pass
        
        if vulnerable_payloads:
            print_result(
                target['name'],
                "VULNERABLE",
                f"HTML injection possible"
            )
            for vuln in vulnerable_payloads:
                print(f"  {Colors.FAIL}•{Colors.ENDC} {vuln}")
        else:
            print_result(target['name'], "RESOLVED", "No HTML injection detected")

# 7. Cross-Site Scripting (XSS) Check
def check_xss():
    print(f"\n{Colors.HEADER}--- Checking Cross-Site Scripting (XSS) ---{Colors.ENDC}")
    
    # Generic XSS test payloads
    print(f"\n{Colors.OKBLUE}Testing Generic XSS Payloads...{Colors.ENDC}")
    
    generic_xss_payloads = [
        {
            "marker": "XSSTEST67890",
            "payload": "<script>alert('XSSTEST67890')</script>"
        },
        {
            "marker": "XSSIMG",
            "payload": "<img src=x onerror=alert('XSSIMG')>"
        },
        {
            "marker": "XSSSVG",
            "payload": "<svg/onload=alert('XSSSVG')>"
        }
    ]
    
    generic_targets = [
        {
            "name": "Search Page (search parameter)",
            "url": f"http://{TARGET_IP}/index.php",
            "method": "GET",
            "param": "search",
            "params": {
                "search": ""
            },
            "requires_auth": False
        }
    ]
    
    for target in generic_targets:
        print(f"\n{Colors.WARNING}Testing: {target['name']}{Colors.ENDC}")
        
        # Check if authentication is required
        if target.get('requires_auth'):
            session = get_authenticated_session()
            if not session:
                print_result(
                    target['name'],
                    "SKIPPED",
                    f"Authentication required. Set ADMIN_USER and ADMIN_PASS in script."
                )
                continue
        else:
            session = requests.Session()
        
        vulnerable_payloads = []
        
        for payload_test in generic_xss_payloads:
            try:
                if target['method'] == "POST":
                    test_data = target['data'].copy()
                    test_data[target['param']] = payload_test['payload']
                    response = session.post(target['url'], data=test_data, timeout=5, allow_redirects=True)
                else:
                    test_params = target['params'].copy()
                    test_params[target['param']] = payload_test['payload']
                    response = session.get(target['url'], params=test_params, timeout=5, allow_redirects=True)
                
                if payload_test['marker'] in response.text:
                    if payload_test['payload'] in response.text:
                        vulnerable_payloads.append(f"Script executed: {payload_test['payload'][:50]}")
                    else:
                        vulnerable_payloads.append(f"Partial reflection: {payload_test['marker']}")
                
            except Exception as e:
                pass
                
                if payload_test['marker'] in response.text:
                    if payload_test['payload'] in response.text:
                        vulnerable_payloads.append(f"Script executed: {payload_test['payload'][:50]}")
                    else:
                        vulnerable_payloads.append(f"Partial reflection: {payload_test['marker']}")
                
            except Exception as e:
                pass
        
        if vulnerable_payloads:
            print_result(
                target['name'],
                "VULNERABLE",
                f"XSS vulnerability detected"
            )
            for vuln in vulnerable_payloads:
                print(f"  {Colors.FAIL}•{Colors.ENDC} {vuln}")
        else:
            print_result(target['name'], "RESOLVED", "No XSS detected")
    
    # Reflected XSS Tests (Specific Confirmed Vulnerabilities)
    print(f"\n{Colors.OKBLUE}Testing Reflected XSS (Known Vulnerabilities)...{Colors.ENDC}")
    
    reflected_xss_tests = [
        {
            "name": "File Viewer Reflected XSS (file parameter)",
            "url": f"http://{TARGET_IP}/cp/index.php",
            "params": {
                "op": "fileviewer",
                "file": "</title><script>alert(1);</script><title>"
            },
            "detection_strings": ["<script>alert(1);</script>", "alert(1)"],
            "severity": "High"
        },
        {
            "name": "Search Page Reflected XSS (search parameter)",
            "url": f"http://{TARGET_IP}/index.php",
            "params": {
                "search": "<ScRiPt>alert('XSS')</sCrIpT>"
            },
            "detection_strings": ["<ScRiPt>alert('XSS')</sCrIpT>", "alert('XSS')"],
            "severity": "High"
        }
    ]
    
    for test in reflected_xss_tests:
        try:
            response = requests.get(test['url'], params=test['params'], timeout=5, allow_redirects=True)
            
            # Check if any detection string is reflected in response
            xss_detected = False
            detected_string = None
            
            for detection in test['detection_strings']:
                if detection in response.text:
                    xss_detected = True
                    detected_string = detection
                    break
            
            if xss_detected:
                print_result(
                    test['name'],
                    "VULNERABLE",
                    f"Reflected XSS confirmed ({test['severity']} severity)"
                )
                print(f"  {Colors.FAIL}•{Colors.ENDC} Payload reflected: {detected_string[:60]}")
                
                # Build the vulnerable URL
                from urllib.parse import urlencode
                vuln_url = f"{test['url']}?{urlencode(test['params'])}"
                print(f"  {Colors.FAIL}•{Colors.ENDC} PoC URL: {vuln_url[:90]}...")
            else:
                print_result(test['name'], "RESOLVED", "XSS payload not reflected or properly sanitized")
        
        except Exception as e:
            print_result(test['name'], "INFO", f"Error testing: {str(e)}")

# 8. SQL Injection using sqlmap
def check_sqli(verbose=False):
    print(f"\n{Colors.HEADER}--- SQL Injection: Verification using sqlmap ---{Colors.ENDC}")
    
    try:
        subprocess.run(['sqlmap', '--version'], capture_output=True, check=True, timeout=5)
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        print_result("sqlmap", "INFO", "sqlmap not found. Install it: apt-get install sqlmap")
        return
    
    targets = [
        {
            "name": "Login API (email parameter)",
            "url": f"http://{TARGET_IP}/api/login.php",
            "data": "email=test@test.com&password=test",
            "param": "email"
        },
        {
            "name": "Search Page (search parameter)",
            "url": f"http://{TARGET_IP}/index.php?search=test",
            "param": "search"
        },
        {
            "name": "Cart Action (update_id parameter)",
            "url": f"http://{TARGET_IP}/api/cart_action.php",
            "data": "updateItem=1&update_id=1&qty=2",
            "param": "update_id"
        },
        {
            "name": "Admin Actions (update_id parameter)",
            "url": f"http://{TARGET_IP}/api/admin_actions.php",
            "data": "update_id=1&pro_title=Test&pro_price=100&pro_cat=1&pro_brand=1&edit_pro=",
            "param": "update_id",
            "cookie": "PHPSESSID=test_session"
        }
    ]
    
    for target in targets:
        print(f"\n{Colors.WARNING}Testing: {target['name']}{Colors.ENDC}")
        print(f"URL: {target['url']}")
        print(f"Running sqlmap... (this may take 30-60 seconds)\n")
        
        cmd = [
            'sqlmap',
            '-u', target['url'],
            '--batch',
            '--level=1',
            '--risk=1',
            '--threads=4',
            '--technique=BEUSTQ',
            '--answers=follow=Y',
            '--random-agent',
            '--timeout=10',
            '--retries=1'
        ]
        
        if 'data' in target:
            cmd.extend(['--data', target['data']])
        
        if 'cookie' in target:
            cmd.extend(['--cookie', target['cookie']])
            print(f"{Colors.WARNING}Note: Admin endpoint may require valid session cookie{Colors.ENDC}")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            output = result.stdout + result.stderr
            
            if verbose:
                print(f"\n{Colors.WARNING}=== DEBUG: Raw sqlmap output ==={Colors.ENDC}")
                print(output)
                print(f"{Colors.WARNING}=== End of raw output ==={Colors.ENDC}\n")
            
            vulnerabilities = parse_sqlmap_output(output, target['param'])
            
            if vulnerabilities:
                print_result(
                    target['name'],
                    "VULNERABLE",
                    f"Found {len(vulnerabilities['types'])} injection type(s)"
                )
                
                for injection_type in vulnerabilities['types']:
                    print(f"  {Colors.FAIL}•{Colors.ENDC} {injection_type['type']}: {injection_type['title']}")
                
                if vulnerabilities.get('dbms'):
                    print(f"  {Colors.OKBLUE}•{Colors.ENDC} Database: {vulnerabilities['dbms']}")
                if vulnerabilities.get('os'):
                    print(f"  {Colors.OKBLUE}•{Colors.ENDC} OS: {vulnerabilities['os']}")
                if vulnerabilities.get('web_server'):
                    print(f"  {Colors.OKBLUE}•{Colors.ENDC} Web Server: {vulnerabilities['web_server']}")
                
            else:
                if "all tested parameters do not appear to be injectable" in output.lower():
                    print_result(target['name'], "RESOLVED", "No SQL injection found")
                elif "does not appear to be dynamic" in output.lower():
                    print_result(target['name'], "RESOLVED", "Parameter not dynamic (likely safe)")
                else:
                    print_result(target['name'], "INFO", "Scan completed but results unclear")
        
        except subprocess.TimeoutExpired:
            print_result(target['name'], "INFO", "Scan timed out")
        
        except Exception as e:
            print_result(target['name'], "INFO", f"Error running sqlmap: {str(e)}")

def parse_sqlmap_output(output, param_name):
    """Parse sqlmap output to extract vulnerability information"""
    vulnerabilities = {
        'types': [],
        'dbms': None,
        'os': None,
        'web_server': None
    }
    
    if f"Parameter: {param_name}" not in output and "is vulnerable" not in output:
        return None
    
    injection_types = [
        "boolean-based blind",
        "error-based",
        "time-based blind",
        "UNION query",
        "stacked queries",
        "inline queries"
    ]
    
    lines = output.split('\n')
    current_type = None
    
    for i, line in enumerate(lines):
        line_lower = line.lower()
        for inj_type in injection_types:
            if f"Type: {inj_type}" in line_lower or inj_type in line_lower:
                current_type = inj_type
        
        if current_type and "Title:" in line:
            title = line.split("Title:", 1)[1].strip()
            if not any(t['type'].lower() == current_type for t in vulnerabilities['types']):
                vulnerabilities['types'].append({
                    'type': current_type.title(),
                    'title': title
                })
            current_type = None
        
        if "back-end dbms:" in line_lower or "back-end DBMS:" in line:
            vulnerabilities['dbms'] = line.split(":", 1)[1].strip()
        
        if "the back-end dbms is" in line_lower:
            match = re.search(r'the back-end dbms is\s+(.+?)(?:\n|$)', line_lower, re.IGNORECASE)
            if match:
                vulnerabilities['dbms'] = match.group(1).strip()
        
        if "web server operating system:" in line_lower:
            vulnerabilities['os'] = line.split(":", 1)[1].strip()
        
        if "web application technology:" in line_lower:
            vulnerabilities['web_server'] = line.split(":", 1)[1].strip()
    
    if vulnerabilities['types']:
        return vulnerabilities
    
    if "is vulnerable" in output.lower() or "injectable" in output.lower():
        vulnerabilities['types'].append({
            'type': 'Unknown Type',
            'title': 'SQL injection detected'
        })
        return vulnerabilities
    
    return None

def check_command_injection():
    print(f"\n{Colors.HEADER}--- Checking OS Command Injection ---{Colors.ENDC}")
    
    # Payloads for Linux-based targets
    test_payloads = [
        {"cmd": "whoami", "pattern": r"^[a-z_][a-z0-9_-]*\$?"}, 
        {"cmd": "id", "pattern": "uid="},
        {"cmd": "expr 123 + 123", "pattern": "246"}
    ]
    
    target_path = "cp/cmd" # Based on your screenshot
    url = urljoin(BASE_URL, target_path)
    
    try:
        # First check if the endpoint exists
        initial_check = requests.get(url, timeout=5)
        if initial_check.status_code == 404:
            print_result("Command Injection", "SKIPPED", f"Endpoint {target_path} not found")
            return

        vulnerable = False
        for test in test_payloads:
            # Testing the 'cmd' parameter identified in your image
            params = {'cmd': test['cmd']}
            response = requests.get(url, params=params, timeout=5)
            
            if re.search(test['pattern'], response.text):
                print_result(
                    "OS Command Injection", 
                    "CRITICAL", 
                    f"Command '{test['cmd']}' executed successfully on {target_path}"
                )
                print(f"  {Colors.FAIL}•{Colors.ENDC} POC: {response.url}")
                vulnerable = True
                break
        
        if not vulnerable:
            print_result("OS Command Injection", "RESOLVED", "No command injection detected on known endpoints")

    except Exception as e:
        print_result("Command Injection", "INFO", f"Error testing endpoint: {str(e)}")

if __name__ == "__main__":
    verbose = '--verbose' in sys.argv or '-v' in sys.argv
    
    print(f"{Colors.HEADER}")
    print("=" * 60)
    print("  SHOPEA SECURITY SCANNER")
    print("  Target: " + TARGET_IP)
    if verbose:
        print("  Mode: VERBOSE (showing raw sqlmap output)")
    print("=" * 60)
    print(f"{Colors.ENDC}")
    
    check_vulnerable_components()
    check_banners()
    check_ssh_configuration()
    check_http_security()
    check_paths()
    check_methods()
    check_hardcoded_credentials()
    check_html_injection()
    check_xss()
    check_sqli(verbose=verbose)
    check_command_injection()
    
    print(f"\n{Colors.HEADER}{'=' * 60}{Colors.ENDC}")
    print(f"{Colors.HEADER}  Verification Complete{Colors.ENDC}")
    print(f"{Colors.HEADER}{'=' * 60}{Colors.ENDC}\n")
    
    if not verbose:
        print(f"{Colors.OKBLUE}Tip: Run with --verbose flag to see raw sqlmap output{Colors.ENDC}\n")
