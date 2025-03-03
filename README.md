# Phishing Email Detector

A simple Python tool to detect phishing indicators in emails, such as suspicious sender domains, insecure URLs, and phishing keywords.

## Features
- Checks sender domains against a list of known suspicious ones.
- Scans for insecure URLs (e.g., HTTP instead of HTTPS).
- Detects common phishing keywords like "urgent" or "verify your account".

## How to Run
1. Install Python 3: `sudo apt install python3`
2. Make the script executable: `chmod +x phishing_detector.py`
3. Run it: `./phishing_detector.py`
4. Enter a sender email and content when prompted.

## Example
Input:
- Sender: `user@fakebank.com`
- Content: `Urgent! Verify your account at http://fake-login.com`
Output:
- Suspicious sender domain detected: fakebank.com
- Suspicious URL detected: http://fake-login.com
- Phishing keyword detected: 'urgent'
