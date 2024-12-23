
# Web Security Scanner

A Python-based automated security scanner for web applications that performs basic vulnerability assessments and generates detailed reports.

---

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

---

## Requirements
- Python 3.x
- `requests` library

---

## Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/Oussssn/security-scanner.git
   cd security-scanner
   ```

2. Install dependencies:
   ```bash
   pip install requests
   ```

---

## Usage

1. Run the scanner:
   ```bash
   python security-scanner.py
   ```

2. Enter the target URL when prompted:
   ```
   Enter target URL to scan (e.g., https://example.com):
   ```

3. The scanner will perform all checks and generate a report:
   - Report file: `security_report.json` (in the same folder).

---

## Limitations
- Basic vulnerability checks only.
- False positives may occur.
- No authentication support.
- Limited to HTTP/HTTPS protocols.
- No recursive scanning.

---

## Contributing

Contributions are welcome! Feel free to fork the repository and use it for your own purposes.

---

## Disclaimer

This tool is provided as-is without any warranties. Users are responsible for ensuring they have appropriate permissions before conducting security scans.
