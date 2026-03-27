import re
from urllib.parse import urlparse

def check_https(url):
    return url.startswith("https://")

def check_ip(url):
    ip_pattern = r'http[s]?://\d+\.\d+\.\d+\.\d+'
    return re.match(ip_pattern, url)

def check_keywords(url):
    keywords = ["login", "verify", "update", "secure", "account", "bank"]
    return any(word in url.lower() for word in keywords)

def check_length(url):
    return len(url) > 75

def analyze(url):
    print("\n Analyzing URL:", url)
    score = 0

    # HTTPS
    if check_https(url):
        print(" HTTPS Secure")
    else:
        print(" No HTTPS")
        score += 1

    # IP check
    if check_ip(url):
        print(" IP Address used")
        score += 2

    # Keywords
    if check_keywords(url):
        print(" Suspicious keywords detected")
        score += 1

    # Length check
    if check_length(url):
        print(" URL too long (possible obfuscation)")
        score += 1

    # Domain info
    domain = urlparse(url).netloc
    print("Domain:", domain)

    # Final decision
    print("\n Result:")
    if score == 0:
        print(" SAFE URL")
    elif score <= 2:
        print(" SUSPICIOUS URL")
    else:
        print(" PHISHING URL")

# Run
url = input("Enter URL: ")
analyze(url)