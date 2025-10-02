    🛡️ Phishing Analyzer v1.1

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey)

Rapid phishing screening tool for SOC Analysts - Python-powered threat detection for quick incident triage.


    📋 Overview
Phishing Analyzer is a command-line utility designed for Security Operations Center (SOC) teams to quickly assess URLs and email addresses for common phishing indicators during initial incident analysis.


    ✨ Features
 🔍 URL Security Assessment

  - HTTP vs HTTPS protocol detection

  - Basic URL structure validation

  - Suspicious TLD detection

 📧 Email Reputation Check

  - Temporary email service detection

  - Suspicious domain identification

  - Customizable domain blacklist

 ⚡ Instant Analysis

  - Real-time results

  - Clean, intuitive interface

  - SOC-friendly workflow

 🚀 Quick Start
  - bash
        # Clone the repository
        git clone https://github.com/your-username/phishing_analyzer_v1_1.git

        # Navigate to directory
        cd phishing_analyzer_v1_1

        # Install dependencies (if any)
        pip install -r requirements.txt

        # Run the analyzer
        python3 p_a.py

 ⚙️ Configuration
  VirusTotal API Setup
  For enhanced detection, configure your VirusTotal API key:
  - bash
        # Linux/macOS
        export VIRUSTOTAL_API_KEY="your_api_key_here"

        # Windows (Command Prompt)
        set VIRUSTOTAL_API_KEY=your_api_key_here

        # Windows (PowerShell)
        $env:VIRUSTOTAL_API_KEY="your_api_key_here"

  - Config File
        The config.json file includes:
        Customizable temporary email domains
        Suspicious TLD list
        Version and author information


 🎯 Usage
  Execute the script and provide the required inputs when prompted:
  - bash
        python3 phishing_analyzer.py

  Interactive Input:
  - text
        === PHISHING ANALYZER v1.1 ===
        URL: https://your-bank.com
        Email: user@company.com

  Sample Output:
  - text
        ✅ Secure URL (HTTPS Enabled)
        ✅ Legitimate Email Address

 🛡️ Detection Capabilities

  URL Analysis
  - Insecure Protocols: http:// detection

  - Missing Encryption: No HTTPS validation

  - Basic Structure: URL format verification.

  - Suspicious TLDs: Detection of risky domain extensions

  Email Analysis
   Temporary Email Services Detected:

     - temp-mail.org, temp-mail.io

     - mailinator.com, guerrillamail.com

     - 10minutemail.com, yopmail.com

     - sharklasers.com, getairmail.com

 ⚠️ Important Limitations
  This is a preliminary screening tool and should not replace comprehensive security analysis:

      - ✅ Basic indicator verification

      - ❌ No webpage content analysis

      - ❌ No SSL certificate validation

      - ❌ No advanced phishing technique detection

      - ❌ No real-time threat intelligence feeds

      - ❌ Not a replacement for enterprise security solutions

 🏗️ Project Structure
  text
    phishing_analyzer_v1_1/
    ├── config.json                  # Configuration file
    ├── examples_for_testing.txt     # Usage examples
    ├── p_a.py                       # Main analysis script
    └── README.md                    # Documentation

 🔧 For Developers
  The tool is built with simplicity and extensibility in mind:
  - python
        # Basic usage example
        import json
        import os

        # Load configuration
        with open('config.json', 'r') as f:
            config = json.load(f)

        # Use detection lists
        temp_domains = config.get('temp_email_domains', [])
        suspicious_tlds = config.get('suspicious_tlds', [])

 🤝 Contributing
  We welcome contributions from the security community:
  - 🐛 Report bugs and issues

  - 💡 Suggest new detection methods

  - 🔧 Submit pull requests

  - 📚 Improve documentation

 📄 License
  This project is licensed under the MIT License - see the LICENSE file for details.

 🆘 Support
  For issues and questions:
  - Check existing GitHub issues

  - Create a new issue with detailed description

  - Provide sample data for detection improvements



Created for SOC teams by security professional 🔒
Use responsibly as part of a comprehensive security strategy.