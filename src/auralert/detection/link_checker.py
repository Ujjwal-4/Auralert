"""Static URL analyzer for scam, phishing, and spoofing detection.

Strictly static analysis: NEVER performs network requests or DNS resolution.
Evaluates homoglyphs, brand typosquatting, URL shorteners, risky TLDs,
excessive subdomains, credential harvesting paths, and non-HTTPS usage.
"""

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

# URL shortener domains known to conceal destinations
SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "cutt.ly",
    "is.gd",
    "ow.ly",
    "rb.gy",
    "buff.ly",
    "adf.ly",
    "shorturl.at",
}

# TLDs heavily correlated with disposable/abused domains
RISKY_TLDS = {
    "top",
    "xyz",
    "tk",
    "ml",
    "ga",
    "cf",
    "gq",
    "buzz",
    "club",
    "work",
    "icu",
    "cam",
    "vip",
    "fit",
    "surf",
    "click",
    "link",
    "live",
}

# Credential / account sensitive keywords in path
CREDENTIAL_KEYWORDS = [
    "login",
    "signin",
    "verify",
    "kyc",
    "otp",
    "account",
    "banking",
    "password",
    "update",
    "secure",
    "wallet",
    "aadhaar",
    "pan",
    "refund",
]


def _levenshtein_distance(s1: str, s2: str) -> int:
    """Compute Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def _load_brands() -> list[str]:
    """Load known target brand names from data/brands.json."""
    brand_file = Path(__file__).resolve().parent.parent.parent.parent / "data" / "brands.json"
    if brand_file.exists():
        try:
            with open(brand_file, encoding="utf-8") as f:
                data = json.load(f)
                return data.get("brands", [])
        except (OSError, json.JSONDecodeError):
            return ["sbi", "hdfc", "icici", "axis", "amazon", "google", "paytm", "phonepe"]
    return ["sbi", "hdfc", "icici", "axis", "amazon", "google", "paytm", "phonepe"]


KNOWN_BRANDS = _load_brands()


def check_link(url: str) -> dict[str, Any]:
    """Perform safe static analysis of a link without network I/O.

    Args:
        url: The raw URL string provided by the user.

    Returns:
        Structured result with verdict, risk_score (0-100), signals,
        normalized_domain, and speak text.
    """
    cleaned_url = url.strip()
    if not cleaned_url:
        return {
            "verdict": "safe",
            "risk_score": 0,
            "signals": [],
            "normalized_domain": "",
            "speak": "No link was provided to check.",
        }

    # Ensure URL has scheme for urllib parsing
    raw_has_scheme = "://" in cleaned_url
    if not raw_has_scheme:
        parse_target = "http://" + cleaned_url
    else:
        parse_target = cleaned_url

    parsed = urlparse(parse_target)
    netloc = parsed.netloc.lower()

    signals: list[dict[str, str]] = []
    score = 0

    # 1. Check for @ symbol trick (userinfo spoofing)
    if "@" in netloc or "@" in cleaned_url.split("?")[0]:
        signals.append(
            {
                "code": "USERINFO_AT_TRICK",
                "detail": "The URL uses the '@' character to deceive users about the true destination domain.",
            }
        )
        score += 45

    # Extract actual host (removing port if present)
    host = netloc.split("@")[-1].split(":")[0]
    normalized_domain = host

    # 2. Check for raw IP address as host
    ip_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    if re.match(ip_pattern, host):
        signals.append(
            {
                "code": "IP_ADDRESS_HOST",
                "detail": f"The link points directly to a raw numeric IP address ({host}) instead of a verified domain name.",
            }
        )
        score += 40

    # 3. Check for Punycode / IDN homoglyphs
    if "xn--" in host:
        signals.append(
            {
                "code": "PUNYCODE_HOMOGLYPH",
                "detail": f"The domain uses Punycode ({host}) which is frequently used to impersonate lookalike letters.",
            }
        )
        score += 45

    # 4. Check for URL shorteners
    if host in SHORTENER_DOMAINS:
        signals.append(
            {
                "code": "URL_SHORTENER",
                "detail": f"The domain ({host}) is a URL shortener designed to mask the final destination website.",
            }
        )
        score += 30

    # 5. Check TLD reputation
    parts = host.split(".")
    tld = parts[-1] if len(parts) > 1 else ""
    if tld in RISKY_TLDS:
        signals.append(
            {
                "code": "RISKY_TLD",
                "detail": f"The link uses high-risk top-level domain '.{tld}', which is heavily associated with fraudulent sites.",
            }
        )
        score += 30

    # 6. Check for excessive subdomains
    if len(parts) >= 4 and not re.match(ip_pattern, host):
        signals.append(
            {
                "code": "EXCESSIVE_SUBDOMAINS",
                "detail": f"The domain has {len(parts)} levels of subdomains, which is commonly used to construct deceptive URLs.",
            }
        )
        score += 25

    # 7. Check non-HTTPS (only if scheme was explicitly http://)
    if cleaned_url.startswith("http://"):
        signals.append(
            {
                "code": "NON_HTTPS",
                "detail": "The link uses unencrypted HTTP instead of secure HTTPS.",
            }
        )
        score += 15

    # 8. Check Brand Impersonation / Typosquatting
    # Split domain into base labels (e.g. 'sbi-kyc-verify' from 'sbi-kyc-verify.top')
    domain_labels = parts[:-1] if len(parts) > 1 else parts
    primary_label = parts[-2] if len(parts) >= 2 else parts[0]

    for brand in KNOWN_BRANDS:
        # Check if the host is legitimate for this brand
        is_legitimate_brand_domain = (
            host == f"{brand}.com"
            or host == f"www.{brand}.com"
            or host == f"{brand}.in"
            or host.endswith((f".{brand}.com", f".{brand}.in", f".{brand}.gov.in", f".{brand}"))
            or (brand == "sbi" and host.endswith(".sbi"))
            or (brand == "amazon" and ("amazon.com" in host or "amazon.in" in host))
            or (brand == "google" and ("google.com" in host or "google.co.in" in host))
        )
        if is_legitimate_brand_domain:
            continue

        # Check if brand is embedded in compound label (e.g. 'sbi-kyc', 'paytm-refund', 'amazon-support')
        has_compound_brand = (brand in primary_label and primary_label != brand) or any(
            brand in lbl for lbl in domain_labels if lbl != brand
        )

        if has_compound_brand:
            signals.append(
                {
                    "code": "BRAND_NAME_IMPERSONATION",
                    "detail": f"Domain contains brand name '{brand}' in an unauthorized suspicious combination: {host}",
                }
            )
            score += 40
            break

        # Check Levenshtein distance typosquatting (e.g. 'amaz0n' or 'sbii')
        sub_tokens = re.split(r"[-_.]", primary_label)
        typo_match = None
        for tok in [primary_label] + sub_tokens:
            if not tok or len(tok) < 3:
                continue
            dist = _levenshtein_distance(tok, brand)
            if 1 <= dist <= 2 and len(brand) >= 4 and tok != brand:
                typo_match = (tok, dist)
                break

        if typo_match:
            tok, dist = typo_match
            signals.append(
                {
                    "code": "TYPOSQUATTING",
                    "detail": f"Domain component '{tok}' closely mimics legitimate brand '{brand}' (edit distance: {dist}).",
                }
            )
            score += 40
            break

    # 9. Check sensitive path keywords
    path = parsed.path.lower()
    found_keywords = [kw for kw in CREDENTIAL_KEYWORDS if kw in path]
    if found_keywords:
        signals.append(
            {
                "code": "CREDENTIAL_KEYWORDS_IN_PATH",
                "detail": f"The URL path contains sensitive credential keywords: {', '.join(found_keywords)}.",
            }
        )
        score += 20

    # 10. Check excessive path length or unusual encoding
    if len(path) > 100 or path.count("%") >= 4:
        signals.append(
            {
                "code": "SUSPICIOUS_ENCODED_PATH",
                "detail": "The URL path is excessively long or heavily obfuscated with percentage-encoding.",
            }
        )
        score += 15

    # Determine final risk score and verdict
    risk_score = min(score, 100)
    if risk_score >= 60:
        verdict = "likely_scam"
    elif risk_score >= 25:
        verdict = "suspicious"
    else:
        verdict = "safe"

    # Calm, 2-sentence voice summary
    if verdict == "likely_scam":
        speak = (
            f"This link looks like a scam imitating an official website on domain {normalized_domain}. "
            "Do not open it or enter any passwords or OTPs."
        )
    elif verdict == "suspicious":
        speak = (
            f"The link to {normalized_domain} looks suspicious with multiple security warning signs. "
            "Avoid tapping on it until you verify with the official source."
        )
    else:
        speak = (
            f"The link to {normalized_domain} has standard security indicators and appears safe. "
            "Always check that the address bar matches the intended service."
        )

    return {
        "verdict": verdict,
        "risk_score": risk_score,
        "signals": signals,
        "normalized_domain": normalized_domain,
        "speak": speak,
    }
