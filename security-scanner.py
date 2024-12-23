import requests
import re
import ssl
import socket
import subprocess
import json
import hashlib
import jwt
import base64
import xml.etree.ElementTree as ET
from datetime import datetime
from urllib.parse import urljoin, urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup

class EnhancedWebSecurityScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.findings = []
        self.headers = {
            'User-Agent': 'Security-Scanner-v1.0'
        }
        self.session = requests.Session()
    
    def scan(self):
        """scanning function covering OWASP Top 10"""
        print(f"Starting comprehensive security scan for {self.target_url}")
        
        # A01:2021 - Broken Access Control
        self.check_broken_access_control()
        
        # A02:2021 - Cryptographic Failures
        self.check_crypto_failures()
        
        # A03:2021 - Injection
        self.check_injection_vulnerabilities()
        
        # A04:2021 - Insecure Design
        self.check_insecure_design()
        
        # A05:2021 - Security Misconfiguration
        self.check_security_misconfig()
        
        # A06:2021 - Vulnerable Components
        self.check_vulnerable_components()
        
        # A07:2021 - Authentication Failures
        self.check_auth_failures()
        
        # A08:2021 - Software and Data Integrity Failures
        self.check_integrity_failures()
        
        # A09:2021 - Security Logging and Monitoring Failures
        self.check_logging_failures()
        
        # A10:2021 - Server-Side Request Forgery
        self.check_ssrf()
        
        self.generate_report()

    def check_broken_access_control(self):
        """Broken Access Control"""
        # Check for directory traversal
        traversal_paths = ["../../../etc/passwd", "..\\..\\..\\windows\\win.ini"]
        for path in traversal_paths:
            try:
                response = self.session.get(f"{self.target_url}/{path}")
                if "root:" in response.text or "[extensions]" in response.text:
                    self.findings.append({
                        'type': 'Broken Access Control',
                        'severity': 'High',
                        'description': 'Directory traversal vulnerability detected',
                        'recommendation': 'Implement proper path validation and access controls'
                    })
            except:
                pass

        # Check for IDOR
        ids = [1, 2, 3]
        for id in ids:
            try:
                response = self.session.get(f"{self.target_url}/api/user/{id}")
                if response.status_code == 200:
                    self.findings.append({
                        'type': 'Broken Access Control',
                        'severity': 'High',
                        'description': 'Potential IDOR vulnerability detected',
                        'recommendation': 'Implement proper authorization checks'
                    })
            except:
                pass

    def check_crypto_failures(self):
        """Cryptographic Failures"""
        try:
            response = self.session.get(self.target_url)
            
            # Check for sensitive data in HTML comments
            if '<!--' in response.text and any(word in response.text.lower() for word in ['password', 'token', 'key']):
                self.findings.append({
                    'type': 'Cryptographic Failures',
                    'severity': 'Medium',
                    'description': 'Sensitive data found in HTML comments',
                    'recommendation': 'Remove sensitive data from HTML comments'
                })

            # Check for weak SSL/TLS
            hostname = urlparse(self.target_url).hostname
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cipher = ssock.cipher()
                    if 'TLSv1.0' in str(cipher) or 'TLSv1.1' in str(cipher):
                        self.findings.append({
                            'type': 'Cryptographic Failures',
                            'severity': 'High',
                            'description': 'Weak SSL/TLS version in use',
                            'recommendation': 'Upgrade to TLS 1.2 or higher'
                        })
        except:
            pass

    def check_injection_vulnerabilities(self):
        """Injection"""
        # SQL Injection
        sql_payloads = ["' OR '1'='1", "1; DROP TABLE users", "1 UNION SELECT null,null,null--"]
        for payload in sql_payloads:
            try:
                response = self.session.get(f"{self.target_url}?id={payload}")
                if any(error in response.text for error in ['mysql', 'sqlite', 'ORA-']):
                    self.findings.append({
                        'type': 'SQL Injection',
                        'severity': 'High',
                        'description': 'SQL Injection vulnerability detected',
                        'recommendation': 'Use parameterized queries and input validation'
                    })
            except:
                pass

        # NoSQL Injection
        nosql_payloads = ['{"$gt":""}', '{"$ne":null}']
        for payload in nosql_payloads:
            try:
                response = self.session.get(f"{self.target_url}?query={payload}")
                if response.status_code == 200:
                    self.findings.append({
                        'type': 'NoSQL Injection',
                        'severity': 'High',
                        'description': 'Potential NoSQL Injection vulnerability',
                        'recommendation': 'Implement proper input validation for NoSQL queries'
                    })
            except:
                pass

        # Command Injection
        cmd_payloads = ['; ls', '& dir', '| whoami']
        for payload in cmd_payloads:
            try:
                response = self.session.get(f"{self.target_url}?cmd={payload}")
                if any(term in response.text for term in ['root:', 'Volume']):
                    self.findings.append({
                        'type': 'Command Injection',
                        'severity': 'Critical',
                        'description': 'Command Injection vulnerability detected',
                        'recommendation': 'Never pass user input directly to system commands'
                    })
            except:
                pass

    def check_insecure_design(self):
        """Insecure Design"""
        try:
            # Check for common insecure design patterns
            
            # Rate limiting check
            requests_count = 0
            for _ in range(50):
                response = self.session.get(self.target_url)
                if response.status_code == 200:
                    requests_count += 1
            
            if requests_count >= 50:
                self.findings.append({
                    'type': 'Insecure Design',
                    'severity': 'Medium',
                    'description': 'No rate limiting detected',
                    'recommendation': 'Implement rate limiting to prevent abuse'
                })

            # Check for sensitive operations without confirmation
            response = self.session.get(f"{self.target_url}/delete")
            if response.status_code == 200:
                self.findings.append({
                    'type': 'Insecure Design',
                    'severity': 'Medium',
                    'description': 'Sensitive operations without confirmation',
                    'recommendation': 'Implement confirmation steps for sensitive operations'
                })

        except:
            pass

    def check_security_misconfig(self):
        """Security Misconfiguration"""
        try:
            # Check for exposed configuration files
            common_configs = [
                '/config.php', '/wp-config.php', '/config.yml',
                '/.env', '/web.config', '/robots.txt', '/sitemap.xml'
            ]
            
            for config in common_configs:
                response = self.session.get(self.target_url + config)
                if response.status_code == 200:
                    self.findings.append({
                        'type': 'Security Misconfiguration',
                        'severity': 'High',
                        'description': f'Exposed configuration file: {config}',
                        'recommendation': 'Restrict access to configuration files'
                    })

            # Check for directory listing
            response = self.session.get(self.target_url + '/assets/')
            if 'Index of' in response.text:
                self.findings.append({
                    'type': 'Security Misconfiguration',
                    'severity': 'Medium',
                    'description': 'Directory listing enabled',
                    'recommendation': 'Disable directory listing'
                })

            # Check default credentials
            common_creds = [
                ('admin', 'admin'),
                ('root', 'root'),
                ('admin', 'password')
            ]
            
            for username, password in common_creds:
                response = self.session.post(
                    f"{self.target_url}/login",
                    data={'username': username, 'password': password}
                )
                if 'welcome' in response.text.lower():
                    self.findings.append({
                        'type': 'Security Misconfiguration',
                        'severity': 'Critical',
                        'description': 'Default credentials in use',
                        'recommendation': 'Change default credentials'
                    })

        except:
            pass

    def check_vulnerable_components(self):
        """Vulnerable Components"""
        try:
            response = self.session.get(self.target_url)
            
            # Check for known vulnerable JavaScript libraries
            vulnerable_libs = {
                'jquery-1.': 'jQuery 1.x',
                'jquery-2.': 'jQuery 2.x',
                'bootstrap-2': 'Bootstrap 2.x',
                'angular.js/1.': 'AngularJS 1.x'
            }
            
            for lib, name in vulnerable_libs.items():
                if lib in response.text:
                    self.findings.append({
                        'type': 'Vulnerable Components',
                        'severity': 'High',
                        'description': f'Outdated {name} detected',
                        'recommendation': f'Update {name} to the latest version'
                    })

            # Check HTTP response headers for server info
            if 'Server' in response.headers:
                server = response.headers['Server']
                if any(old in server.lower() for old in ['apache/2.2', 'nginx/1.8', 'php/5.']):
                    self.findings.append({
                        'type': 'Vulnerable Components',
                        'severity': 'High',
                        'description': f'Outdated server software: {server}',
                        'recommendation': 'Update server software to latest version'
                    })

        except:
            pass

    def check_auth_failures(self):
        """Authentication Failures"""
        try:
            # Check password policies
            weak_passwords = ['password123', '123456', 'qwerty']
            for password in weak_passwords:
                response = self.session.post(
                    f"{self.target_url}/register",
                    data={'password': password}
                )
                if response.status_code == 200:
                    self.findings.append({
                        'type': 'Authentication Failures',
                        'severity': 'High',
                        'description': 'Weak password policy',
                        'recommendation': 'Implement strong password requirements'
                    })
                    break

            # Check for missing brute force protection
            for _ in range(10):
                response = self.session.post(
                    f"{self.target_url}/login",
                    data={'username': 'admin', 'password': 'wrong'}
                )
                if response.status_code == 200:
                    self.findings.append({
                        'type': 'Authentication Failures',
                        'severity': 'High',
                        'description': 'Missing brute force protection',
                        'recommendation': 'Implement account lockout and rate limiting'
                    })
                    break

        except:
            pass

    def check_integrity_failures(self):
        """Software and Data Integrity Failures"""
        try:
            # Check for insecure deserialization
            payload = base64.b64encode(b'{"user": "admin"}').decode()
            response = self.session.get(f"{self.target_url}?data={payload}")
            
            if 'admin' in response.text:
                self.findings.append({
                    'type': 'Integrity Failures',
                    'severity': 'High',
                    'description': 'Potential insecure deserialization',
                    'recommendation': 'Implement proper input validation and signing'
                })

            # Check for unsafe file uploads
            files = {'file': ('test.php', '<?php echo "test"; ?>')}
            response = self.session.post(f"{self.target_url}/upload", files=files)
            
            if response.status_code == 200:
                self.findings.append({
                    'type': 'Integrity Failures',
                    'severity': 'High',
                    'description': 'Unsafe file upload detected',
                    'recommendation': 'Implement proper file upload validation'
                })

        except:
            pass

    def check_logging_failures(self):
        """Security Logging and Monitoring Failures"""
        try:
            # Check for error exposure
            response = self.session.get(f"{self.target_url}/error")
            if any(term in response.text for term in ['stack trace', 'exception', 'error']):
                self.findings.append({
                    'type': 'Logging Failures',
                    'severity': 'Medium',
                    'description': 'Detailed error messages exposed',
                    'recommendation': 'Implement proper error handling and logging'
                })

            # Check for debug endpoints
            debug_endpoints = ['/debug', '/trace', '/status', '/health']
            for endpoint in debug_endpoints:
                response = self.session.get(self.target_url + endpoint)
                if response.status_code == 200:
                    self.findings.append({
                        'type': 'Logging Failures',
                        'severity': 'Medium',
                        'description': f'Debug endpoint exposed: {endpoint}',
                        'recommendation': 'Disable or protect debug endpoints'
                    })

        except:
            pass

    def check_ssrf(self):
        """Server-Side Request Forgery"""
        try:
            # Test for basic SSRF
            ssrf_urls = [
                'http://localhost',
                'http://127.0.0.1',
                'http://169.254.169.254',  # AWS metadata
                'http://192.168.1.1'
            ]
            
            for url in ssrf_urls:
                response = self.session.get(f"{self.target_url}?url={url}")
                if response.status_code == 200:
                    self.findings.append({
                        'type': 'SSRF',
                        'severity': 'High',
                        'description': 'Potential SSRF vulnerability detected',
                        'recommendation': 'Implement URL validation and whitelist'
                    })
                    break

        except:
            pass

    def generate_report(self):
        """Generate comprehensive security report"""
        report = {
            'scan_target': self.target_url,
            'scan_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'findings': self.findings,
            'summary': {
                'critical': len([f for f in self.findings if f['severity'] == 'Critical']),
                'high': len([f for f in self.findings if f['severity'] == 'High']),
                'medium': len([f for f in self.findings if f['severity'] == 'Medium']),
                'low': len([f for f in self.findings if f['severity'] == 'Low']),
                'info': len([f for f in self.findings if f['severity'] == 'Info'])
            }
        }
        
        # Save report to file
        with open('security_report.json', 'w') as f:
            json.dump(report, f, indent=4)
        
        print("\nSecurity Scan Complete!")
        print(f"Total findings: {len(self.findings)}")
        print(f"Critical: {report['summary']['critical']}")
        print(f"High: {report['summary']['high']}")
        print(f"Medium: {report['summary']['medium']}")
        print(f"Low: {report['summary']['low']}")
        print(f"Info: {report['summary']['info']}")
        print("\nDetailed report saved to 'security_report.json'")

def main():
    target = input("Enter target URL to scan (e.g., https://example.com): ")
    scanner = EnhancedWebSecurityScanner(target)
    scanner.scan()

if __name__ == "__main__":
    main()