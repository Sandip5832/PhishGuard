import re

from urllib.parse import urlparse


# ============================================================
# COMMON URL SHORTENING SERVICES
# ============================================================

SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "rb.gy",
}


# ============================================================
# SUSPICIOUS WORDS OFTEN SEEN IN PHISHING URLs
# ============================================================

SUSPICIOUS_URL_WORDS = {
    "login",
    "signin",
    "verify",
    "verification",
    "secure",
    "security",
    "account",
    "update",
    "password",
    "credential",
    "confirm",
    "payment",
    "wallet",
}


# ============================================================
# EXTRACT URLS
# ============================================================

def extract_urls(email_message):
    """
    Extract HTTP and HTTPS URLs from an email message.

    Duplicate URLs are removed.
    """

    urls = []

    # Get complete raw email
    try:
        raw_email = email_message.as_string()
    except AttributeError:
        raw_email = str(email_message)

    # Match HTTP and HTTPS URLs
    pattern = r'https?://[^\s<>"\']+'

    found_urls = re.findall(
        pattern,
        raw_email,
        re.IGNORECASE
    )

    # Clean and remove duplicates
    for url in found_urls:

        url = url.rstrip(
            ".,;:!?)]}>\"'"
        )

        if url not in urls:
            urls.append(url)

    return urls


# ============================================================
# CHECK IP ADDRESS
# ============================================================

def is_ip_address(domain):
    """
    Check whether a domain is an IPv4 address.
    """

    ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"

    return re.match(ip_pattern, domain) is not None


# ============================================================
# CHECK SUSPICIOUS URL WORDS
# ============================================================

def find_suspicious_words(url):
    """
    Find phishing-related words inside the URL.
    """

    parsed = urlparse(url)

    domain = parsed.hostname or ""

    path = parsed.path or ""

    query = parsed.query or ""

    complete_text = (
        domain + " " +
        path + " " +
        query
    ).lower()

    found_words = []

    for word in SUSPICIOUS_URL_WORDS:

        if word in complete_text:

            found_words.append(word)

    return found_words


# ============================================================
# ANALYZE SINGLE URL
# ============================================================

def analyze_url(url):
    """
    Analyze a single URL for suspicious indicators.
    """

    findings = []

    parsed = urlparse(url)

    # --------------------------------------------------------
    # Basic validation
    # --------------------------------------------------------

    if not parsed.scheme or not parsed.netloc:

        return findings

    # Get hostname safely
    domain = parsed.hostname or ""

    domain = domain.lower()

    # ========================================================
    # CHECK 1: HTTP INSTEAD OF HTTPS
    # ========================================================

    if parsed.scheme.lower() == "http":

        findings.append({
            "type": "insecure_url",
            "severity": "medium",
            "message": (
                "URL uses HTTP instead of HTTPS."
            ),
            "evidence": {
                "url": url,
                "scheme": parsed.scheme
            }
        })

    # ========================================================
    # CHECK 2: IP ADDRESS INSTEAD OF DOMAIN
    # ========================================================

    if is_ip_address(domain):

        findings.append({
            "type": "ip_based_url",
            "severity": "high",
            "message": (
                "URL uses an IP address instead of "
                "a domain name."
            ),
            "evidence": {
                "url": url,
                "ip": domain
            }
        })

    # ========================================================
    # CHECK 3: URL SHORTENER
    # ========================================================

    if domain in SHORTENER_DOMAINS:

        findings.append({
            "type": "url_shortener",
            "severity": "medium",
            "message": (
                "URL uses a known URL-shortening service."
            ),
            "evidence": {
                "url": url,
                "domain": domain
            }
        })

    # ========================================================
    # CHECK 4: VERY LONG URL
    # ========================================================

    if len(url) > 150:

        findings.append({
            "type": "long_url",
            "severity": "medium",
            "message": (
                "URL is unusually long."
            ),
            "evidence": {
                "url": url,
                "length": len(url)
            }
        })

    # ========================================================
    # CHECK 5: SUSPICIOUS URL ENCODING
    # ========================================================

    suspicious_patterns = [
        r"%40",
        r"%2f",
        r"%5c",
        r"%2e",
    ]

    encoding_detected = False

    for pattern in suspicious_patterns:

        if re.search(
            pattern,
            url,
            re.IGNORECASE
        ):

            encoding_detected = True
            break

    # Check @ separately
    if "@" in url:

        encoding_detected = True

    if encoding_detected:

        findings.append({
            "type": "suspicious_url_encoding",
            "severity": "medium",
            "message": (
                "URL contains suspicious encoding "
                "or characters."
            ),
            "evidence": {
                "url": url
            }
        })

    # ========================================================
    # CHECK 6: USERNAME/PASSWORD IN URL
    # ========================================================

    if parsed.username or parsed.password:

        findings.append({
            "type": "url_credentials",
            "severity": "high",
            "message": (
                "URL contains embedded username or "
                "password information."
            ),
            "evidence": {
                "url": url,
                "username_present": bool(parsed.username),
                "password_present": bool(parsed.password)
            }
        })

    # ========================================================
    # CHECK 7: NON-STANDARD PORT
    # ========================================================

    try:
        port = parsed.port
    except ValueError:
        port = None

    if port is not None:

        standard_ports = {
            80,
            443
        }

        if port not in standard_ports:

            findings.append({
                "type": "nonstandard_port",
                "severity": "medium",
                "message": (
                    "URL uses a non-standard network port."
                ),
                "evidence": {
                    "url": url,
                    "port": port
                }
            })

    # ========================================================
    # CHECK 8: EXCESSIVE SUBDOMAINS
    # ========================================================

    domain_parts = domain.split(".")

    # Example:
    # login.verify.account.example.com
    #
    # This has many domain labels and can be suspicious.

    if len(domain_parts) >= 5:

        findings.append({
            "type": "excessive_subdomains",
            "severity": "medium",
            "message": (
                "URL contains an unusually large number "
                "of subdomains."
            ),
            "evidence": {
                "url": url,
                "domain": domain,
                "subdomain_count": len(domain_parts) - 2
            }
        })

    # ========================================================
    # CHECK 9: PUNYCODE DOMAIN
    # ========================================================

    if domain.startswith("xn--") or ".xn--" in domain:

        findings.append({
            "type": "punycode_domain",
            "severity": "medium",
            "message": (
                "URL uses a Punycode-encoded domain, "
                "which can be used in look-alike domains."
            ),
            "evidence": {
                "url": url,
                "domain": domain
            }
        })

    # ========================================================
    # CHECK 10: SUSPICIOUS PHISHING WORDS
    # ========================================================

    suspicious_words = find_suspicious_words(url)

    if suspicious_words:

        findings.append({
            "type": "suspicious_url_keywords",
            "severity": "medium",
            "message": (
                "URL contains words commonly associated "
                "with phishing or credential theft."
            ),
            "evidence": {
                "url": url,
                "keywords": suspicious_words
            }
        })

    # ========================================================
    # RETURN FINDINGS
    # ========================================================

    return findings


# ============================================================
# ANALYZE ALL URLS
# ============================================================

def analyze_urls(email_message):
    """
    Extract and analyze all URLs found in an email.
    """

    findings = []

    urls = extract_urls(email_message)

    for url in urls:

        url_findings = analyze_url(url)

        findings.extend(url_findings)

    return findings