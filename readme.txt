# Web Security Scanner

A Python-based automated security scanner for web applications that performs basic vulnerability assessments and generates detailed reports.

## Features

- **SSL/TLS Analysis**
  - Certificate validation
  - Expiration checks
  - Configuration assessment

- **Security Headers Inspection**
  - X-Frame-Options
  - X-XSS-Protection
  - X-Content-Type-Options
  - Strict-Transport-Security
  - Content-Security-Policy

- **Vulnerability Scanning**
  - Cross-Site Scripting (XSS) detection
  - SQL Injection testing
  - Open ports discovery

- **Reporting**
  - JSON format reports
  - Severity classifications (High, Medium, Low, Info)
  - Detailed findings with recommendations
  - Summary statistics

## Requirements
python 3.x
requests

## Installation

1. Clone this repository:
```bash
git clone https://github.com/yourusername/web-security-scanner.git
cd web-security-scanner

pip install requests


## Usage
-Run the scanner:
'python scanner.py'

-Enter the target URL when prompted:
Enter target URL to scan (e.g., https://example.com):

-The scanner will perform all checks and generate a report in security_report.json (in the same folder)

## Limitations
-Basic vulnerability checks only
-False positives may occur
-No authentication support
-Limited to HTTP/HTTPS protocols
-No recursive scanning

## Contributing
-Fork the repository
-Create your feature branch
-Commit your changes
-Push to the branch
-Create a new Pull Request

## Disclaimer
This tool is provided as-is without any warranties. Users are responsible for ensuring they have appropriate permissions before conducting security scans.