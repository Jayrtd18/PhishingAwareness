import re
from urllib.parse import urlparse

# Common trusted domains for demo purposes
TRUSTED_DOMAINS = {
    "google.com",
    "youtube.com",
    "github.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "wikipedia.org",
    "openai.com",
    "stackoverflow.com",
    "linkedin.com",
    "facebook.com",
    "instagram.com",
    "twitter.com",
    "x.com",
    "gmail.com"
}

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure", "account",
    "bank", "password", "signin", "confirm", "payment",
    "wallet", "otp", "claim", "gift", "bonus"
]


def normalize_url(url: str) -> str:
    """Add scheme if missing."""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url


def is_valid_url(url: str) -> bool:
    """Check whether the URL is structurally valid."""
    try:
        parsed = urlparse(url)
        return bool(parsed.scheme and parsed.netloc)
    except Exception:
        return False


def get_domain(url: str) -> str:
    """Extract clean domain without port or www."""
    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    # Remove port if present
    domain = domain.split(":")[0]

    # Remove www.
    if domain.startswith("www."):
        domain = domain[4:]

    return domain


def is_https(url: str) -> bool:
    return urlparse(url).scheme.lower() == "https"


def uses_ip_address(domain: str) -> bool:
    """Detect IPv4 address instead of domain name."""
    ip_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"
    return re.fullmatch(ip_pattern, domain) is not None


def has_suspicious_keywords(url: str) -> bool:
    url_lower = url.lower()
    return any(word in url_lower for word in SUSPICIOUS_KEYWORDS)


def is_long_url(url: str) -> bool:
    return len(url) > 75


def has_many_subdomains(domain: str) -> bool:
    """Too many subdomains can be suspicious."""
    parts = domain.split(".")
    return len(parts) > 3


def has_at_symbol(url: str) -> bool:
    """'@' can hide the real destination in phishing URLs."""
    return "@" in url


def has_hyphenated_domain(domain: str) -> bool:
    """Fake sites often use hyphens like secure-bank-login.com"""
    return "-" in domain


def is_trusted_domain(domain: str) -> bool:
    """
    Check exact trusted domain or subdomain of trusted domain.
    Example: mail.google.com should count as trusted.
    """
    for trusted in TRUSTED_DOMAINS:
        if domain == trusted or domain.endswith("." + trusted):
            return True
    return False


def analyze_url(url: str) -> None:
    url = normalize_url(url)

    print("\n--- URL Analysis Report ---")
    print("Input URL :", url)

    if not is_valid_url(url):
        print("Status    : INVALID URL")
        return

    domain = get_domain(url)
    score = 0

    print("Domain    :", domain)

    # Safe indicators
    if is_https(url):
        print("[SAFE]   HTTPS is enabled")
    else:
        print("[UNSAFE] HTTPS is not enabled")
        score += 2

    if is_trusted_domain(domain):
        print("[SAFE]   Trusted domain detected")
        score -= 2
    else:
        print("[INFO]   Domain not in trusted list")

    # Unsafe indicators
    if uses_ip_address(domain):
        print("[UNSAFE] IP address used instead of domain")
        score += 3

    if has_suspicious_keywords(url):
        print("[UNSAFE] Suspicious keywords found in URL")
        score += 2

    if is_long_url(url):
        print("[UNSAFE] URL is very long")
        score += 1

    if has_many_subdomains(domain):
        print("[UNSAFE] Too many subdomains detected")
        score += 1

    if has_at_symbol(url):
        print("[UNSAFE] '@' symbol detected in URL")
        score += 3

    if has_hyphenated_domain(domain):
        print("[UNSAFE] Hyphen found in domain")
        score += 1

    # Final decision
    print("\nFinal Score:", score)

    if score <= 0:
        print("Result     : SAFE URL")
    elif 1 <= score <= 3:
        print("Result     : SUSPICIOUS URL")
    else:
        print("Result     : UNSAFE / POSSIBLE PHISHING URL")


if __name__ == "__main__":
    user_url = input("Enter URL to analyze: ")
    analyze_url(user_url)
