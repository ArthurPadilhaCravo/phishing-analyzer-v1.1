#!/usr/bin/env python3
import json
import os

print("=== PHISHING ANALYZER v1.1 ===")

# Load configuration
try:
    with open('config.json', 'r') as f:
        config = json.load(f)
    
    temp_domains = config.get('temp_email_domains', [])
    suspicious_tlds = config.get('suspicious_tlds', [])
    version = config.get('versao', '1.1')
    
    print(f"Configuration loaded - Version {version}")
except FileNotFoundError:
    print("⚠️  config.json not found. Using default detections.")
    temp_domains = ["temp-mail", "mailinator", "guerrillamail", "10minutemail", "yopmail"]
    suspicious_tlds = [".xyz", ".top", ".club", ".info", ".biz"]

url = input("URL: ")
email = input("Email: ")

print(f"\nAnalyzed.")
print(f"URL: {url}")
print(f"Email: {email}")

# URL Analysis
if "http://" in url and not url.startswith("https://"):
    print("🔴 RISK: Insecure URL (HTTP)")
elif url.startswith("https://"):
    print("🟢 Secure URL (HTTPS)")
else:
    print("🟡 WARNING: No protocol specified")

# Check suspicious TLDs
tld_risk = False
for tld in suspicious_tlds:
    if tld in url.lower():
        print(f"🔴 RISK: Suspicious TLD detected ({tld})")
        tld_risk = True
        break

# Email Analysis
email_risk = False
for domain in temp_domains:
    if domain in email.lower():
        print(f"🔴 RISK: Temporary email detected ({domain})")
        email_risk = True
        break

if not email_risk and "@" in email:
    print("🟢 Legitimate email")
elif not email_risk:
    print("🟡 WARNING: Invalid email format")

# Check VirusTotal API
vt_api_key = os.getenv('VIRUSTOTAL_API_KEY')
if vt_api_key:
    print("🟢 VirusTotal API: Configured")
    # Here you could add VirusTotal integration in the future
else:
    print("🟡 VirusTotal API: Not configured (set VIRUSTOTAL_API_KEY environment variable)")

print("\n=== ANALYSIS COMPLETED ===")