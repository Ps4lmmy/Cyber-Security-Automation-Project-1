# Cybersecurity Automation Project: Real-Time Email Threat Detection and SIEM Integration

## 📌 Overview

This project automates the **detection and analysis of phishing emails and malicious communications**. It processes stored email files (.eml format), extracts key email components, scans embedded links with VirusTotal, analyzes attachments with ClamAV, and generates comprehensive security reports.

The implementation demonstrates **practical Cybersecurity automation**, providing a scalable analysis workflow that significantly reduces manual effort in email threat investigation while improving incident response capabilities through structured, automated analysis of suspicious emails.

---

## ⚙️ Automated Workflow Breakdown

### Phase 1 -- Email Collection & Monitoring
- Processes existing email files in .eml format from local storage
- Supports batch analysis of multiple email files in a directory
- Maintains file integrity throughout the analysis process

### Phase 2 -- Email Parsing & Structuring
- Extracts headers, sender, recipient, subject, and body content from .eml files
- Decodes MIME-encoded headers and attachments
- Handles both multipart and plaintext email formats
- Preserves original email structure and metadata

### Phase 3 -- Comprehensive Threat Analysis
- **URL Extraction & Scanning**
  - Extracts links from email bodies using regex pattern matching
  - Submits URLs to **VirusTotal API** for reputation analysis
  - Retrieves malicious/suspicious/harmless detection counts

- **Attachment Processing**
  - Extracts and analyzes email attachments
  - Performs SHA-256 hashing for file identification
  - **Dual-layer scanning**: VirusTotal hash lookup + ClamAV content scanning
  - Base64 encoding for safe handling of suspicious files

- **Header Analysis**
  - Detects email spoofing attempts through Return-Path and Reply-To verification
  - Identifies header inconsistencies that indicate potential phishing
  - Analyzes email authentication headers for suspicious patterns

### Phase 4 -- Reporting & Output
- Generates comprehensive CSV reports with detailed scan results
- Provides clear verdicts (MALICIOUS/SUSPICIOUS/CLEAN/UNKNOWN) for each element
- Supports both individual file and bulk directory processing
- Creates structured output for integration with security workflows
- Includes timestamps and analysis metadata for audit purposes

---

## 🔑 Core Features Implemented

- ✅ Email parsing with Python's email library
- ✅ Local .eml file processing (batch and individual file support)
- ✅ URL extraction and VirusTotal API scanning
- ✅ Attachment analysis with SHA-256 hashing
- ✅ Dual-layer malware detection (VirusTotal + ClamAV)
- ✅ Header spoofing detection
- ✅ Comprehensive CSV reporting
- ✅ Secure secrets management with `.env` (via `python-dotenv`)
- ✅ Multi-format email handling (MIME decoding for headers and attachments)
- ✅ Structured data output for security analysis workflows

---

## 🛠️ Technologies & Tools

- **Python 3.8+** (core automation and parsing)
- **VirusTotal API** (URL and file reputation checking)
- **ClamAV** (local antivirus scanning)
- **Pandas** (data processing and report generation)
- **python-dotenv** (secure credential management)

---

## 🚀 Installation & Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/Ps4lmmy/Cyber-Security-Automation-Project.git
   cd Cyber-Security-Automation-Project
   ```

2. **Create and activate virtual environment**:
   ```bash
   python -m venv .venv   
   source .venv/bin/activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   pip install pandas
   pip install python-dotenv
   ```

4. **Install and configure ClamAV**:
   ```bash
   sudo apt update
   sudo apt install clamav clamav-daemon
   sudo freshclam  # Update virus definitions
   sudo systemctl start clamav-daemon
   ```

5. **Configure Environment Variables**:
   Create a `.env` file in the project root:
   ```env
   VT_API_KEY=your_virustotal_api_key_here
   # Optional: Email credentials if using IMAP monitoring
   EMAIL_USER=your_email@domain.com
   EMAIL_PASS=your_app_specific_password
   ```

6. **Run the scanner**:
   ```bash
   # Scan a single email
   python main.py --input emails/sample.eml --output report.csv
   
   # Scan a directory of emails
   python main.py --input emails/ --output bulk_report.csv
   ```

---

## 📊 Output & Reporting

The tool generates detailed CSV reports containing:
- Email metadata (sender, recipient, subject)
- Extracted URLs with VirusTotal results
- Attachment information with scanning results
- Header analysis findings
- Final verdict for each scanned element

Example report structure:
| filename | sender | to | subject | url | vt_result | clamav_result | verdict |
|----------|--------|----|---------|-----|-----------|---------------|---------|
| sample.eml | sender@domain.com | recipient@company.com | Important Update | https://example.com | {'malicious': 0, 'suspicious': 0, ...} | {'status': 'CLEAN'} | CLEAN |

---

## 🔮 Future Enhancements

- Enable **live IMAP scanning** for continuous monitoring.
- **SIEM Integration**: Direct forwarding of events to Splunk HTTP Event Collector (HEC).
- **Advanced ML Detection**: Machine learning models for phishing content identification.
- **Expanded Threat Intelligence**: Integration with additional threat feeds.
- **Dashboard Interface**: Web-based dashboard for visualization and management.
- **Automated Response**: Integration with SOAR platforms for automated remediation.

---

## ✅ Conclusion

This project demonstrates how strategic automation enhances phishing analysis capabilities by integrating multiple investigation techniques into a cohesive workflow. The solution successfully combines:

- Batch email analysis of stored .eml files
- Multi-layered threat intelligence (VirusTotal + ClamAV integration)
- Comprehensive forensic analysis of URLs, attachments, and headers
- Structured reporting for security documentation and review

The framework significantly reduces manual analysis workload, accelerates email threat investigation, and provides a scalable foundation for organizational email security processes. The modular architecture allows for easy expansion and integration with additional security tools and platforms for enhanced forensic capabilities.
---