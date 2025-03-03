#!/usr/bin/env python3
import re

# Sample phishing indicators
SUSPICIOUS_DOMAINS = ["fakebank.com", "login-security.com"]
PHISHING_KEYWORDS = ["urgent", "verify your account", "login now"]

def check_sender(sender):
    """Check if the sender's domain is suspicious."""
    domain = sender.split('@')[-1] if '@' in sender else sender
    if domain in SUSPICIOUS_DOMAINS:
        return f"Suspicious sender domain detected: {domain}"
    return "Sender seems okay."

def check_urls(text):
    """Check for suspicious URLs in the email."""
    url_pattern = re.compile(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
    urls = url_pattern.findall(text)
    for url in urls:
        if "http://" in url or ".xyz" in url:  # HTTP (not HTTPS) or odd TLDs
            return f"Suspicious URL detected: {url}"
    return "No suspicious URLs found."

def check_content(text):
    """Check for phishing keywords in the email content."""
    text_lower = text.lower()
    for keyword in PHISHING_KEYWORDS:
        if keyword in text_lower:
            return f"Phishing keyword detected: '{keyword}'"
    return "Content seems okay."

def analyze_email(sender, content):
    """Analyze the email for phishing indicators."""
    print("Analyzing email...")
    print(check_sender(sender))
    print(check_urls(content))
    print(check_content(content))

# Test the script with mock email data
if __name__ == "__main__":
    sender = input("Enter the sender email (e.g., user@domain.com): ")
    content = input("Enter the email content: ")
    analyze_email(sender, content)
