from email.utils import parseaddr


# ============================================================
# DOMAIN EXTRACTION
# ============================================================

def get_domain(email_address):
    """
    Extract the domain from an email address.

    Example:
    security@example.com
    -> example.com
    """

    if not email_address or "@" not in email_address:
        return ""

    return email_address.rsplit("@", 1)[1].lower().strip()


# ============================================================
# AUTHENTICATION ANALYSIS
# ============================================================

def analyze_authentication(email_message):
    """
    Analyze the Authentication-Results header.

    This checks authentication results already recorded
    inside the email. It does not perform live verification.
    """

    findings = []

    authentication_results = email_message.get(
        "Authentication-Results",
        ""
    ).lower()

    # No authentication information found
    if not authentication_results:
        return findings

    # --------------------------------------------------------
    # SPF
    # --------------------------------------------------------

    if "spf=fail" in authentication_results:

        findings.append({
            "type": "spf_failure",
            "severity": "high",
            "message": (
                "SPF authentication result indicates failure."
            ),
            "evidence": {
                "authentication_results": authentication_results
            }
        })

    elif "spf=softfail" in authentication_results:

        findings.append({
            "type": "spf_soft_failure",
            "severity": "medium",
            "message": (
                "SPF authentication result indicates soft failure."
            ),
            "evidence": {
                "authentication_results": authentication_results
            }
        })

    # --------------------------------------------------------
    # DKIM
    # --------------------------------------------------------

    if "dkim=fail" in authentication_results:

        findings.append({
            "type": "dkim_failure",
            "severity": "high",
            "message": (
                "DKIM authentication result indicates failure."
            ),
            "evidence": {
                "authentication_results": authentication_results
            }
        })

    # --------------------------------------------------------
    # DMARC
    # --------------------------------------------------------

    if "dmarc=fail" in authentication_results:

        findings.append({
            "type": "dmarc_failure",
            "severity": "high",
            "message": (
                "DMARC authentication result indicates failure."
            ),
            "evidence": {
                "authentication_results": authentication_results
            }
        })

    return findings


# ============================================================
# ADDRESS VALIDATION
# ============================================================

def analyze_sender_address(email_message):
    """
    Analyze the From address for basic structural problems.
    """

    findings = []

    from_header = email_message.get("From", "")

    # --------------------------------------------------------
    # Missing From header
    # --------------------------------------------------------

    if not from_header:

        findings.append({
            "type": "missing_from_header",
            "severity": "medium",
            "message": (
                "The email does not contain a From header."
            ),
            "evidence": {}
        })

        return findings

    # Extract address
    display_name, from_address = parseaddr(from_header)

    # --------------------------------------------------------
    # Invalid From address
    # --------------------------------------------------------

    if not from_address or "@" not in from_address:

        findings.append({
            "type": "invalid_from_address",
            "severity": "high",
            "message": (
                "The From header does not contain a valid "
                "email address."
            ),
            "evidence": {
                "from_header": from_header
            }
        })

        return findings

    from_domain = get_domain(from_address)

    # --------------------------------------------------------
    # Missing domain
    # --------------------------------------------------------

    if not from_domain:

        findings.append({
            "type": "missing_sender_domain",
            "severity": "high",
            "message": (
                "The sender address does not contain a valid domain."
            ),
            "evidence": {
                "from_address": from_address
            }
        })

    return findings


# ============================================================
# REPLY-TO ANALYSIS
# ============================================================

def analyze_reply_to(email_message):
    """
    Compare From and Reply-To addresses/domains.
    """

    findings = []

    from_header = email_message.get("From", "")
    reply_to_header = email_message.get("Reply-To", "")

    # Extract addresses
    _, from_address = parseaddr(from_header)
    _, reply_address = parseaddr(reply_to_header)

    from_domain = get_domain(from_address)
    reply_to_domain = get_domain(reply_address)

    # --------------------------------------------------------
    # From vs Reply-To address
    # --------------------------------------------------------

    if from_address and reply_address:

        if from_address.lower() != reply_address.lower():

            findings.append({
                "type": "reply_to_mismatch",
                "severity": "medium",
                "message": (
                    "The Reply-To address differs "
                    "from the From address."
                ),
                "evidence": {
                    "from": from_address,
                    "reply_to": reply_address
                }
            })

    # --------------------------------------------------------
    # From vs Reply-To domain
    # --------------------------------------------------------

    if from_domain and reply_to_domain:

        if from_domain != reply_to_domain:

            findings.append({
                "type": "reply_to_domain_mismatch",
                "severity": "high",
                "message": (
                    "The Reply-To domain differs "
                    "from the From domain."
                ),
                "evidence": {
                    "from_domain": from_domain,
                    "reply_to_domain": reply_to_domain
                }
            })

    return findings


# ============================================================
# RETURN-PATH ANALYSIS
# ============================================================

def analyze_return_path(email_message):
    """
    Compare the Return-Path domain with the From domain.

    A difference is not automatically malicious because
    legitimate mail systems can use different envelope
    sender domains. Therefore this finding is medium severity.
    """

    findings = []

    from_header = email_message.get("From", "")
    return_path = email_message.get("Return-Path", "")

    _, from_address = parseaddr(from_header)
    _, return_address = parseaddr(return_path)

    from_domain = get_domain(from_address)
    return_domain = get_domain(return_address)

    if from_domain and return_domain:

        if from_domain != return_domain:

            findings.append({
                "type": "return_path_mismatch",
                "severity": "medium",
                "message": (
                    "The Return-Path domain differs "
                    "from the From domain."
                ),
                "evidence": {
                    "from_domain": from_domain,
                    "return_path_domain": return_domain
                }
            })

    return findings


# ============================================================
# MULTIPLE FROM HEADER ANALYSIS
# ============================================================

def analyze_multiple_from(email_message):
    """
    Detect multiple From headers.
    """

    findings = []

    from_headers = email_message.get_all("From", [])

    if from_headers and len(from_headers) > 1:

        findings.append({
            "type": "multiple_from_headers",
            "severity": "high",
            "message": (
                "The email contains multiple From headers."
            ),
            "evidence": {
                "from_headers": from_headers,
                "count": len(from_headers)
            }
        })

    return findings


# ============================================================
# SPF ANALYSIS
# ============================================================

def analyze_spf(email_message):
    """
    Analyze SPF result from Authentication-Results.
    """

    findings = []

    auth_results = email_message.get(
        "Authentication-Results",
        ""
    )

    auth_results_lower = auth_results.lower()

    if "spf=fail" in auth_results_lower:

        findings.append({
            "type": "spf_failure",
            "severity": "high",
            "message": (
                "SPF authentication result indicates failure."
            ),
            "evidence": {
                "authentication_results": auth_results
            }
        })

    elif "spf=softfail" in auth_results_lower:

        findings.append({
            "type": "spf_soft_failure",
            "severity": "medium",
            "message": (
                "SPF authentication result indicates soft failure."
            ),
            "evidence": {
                "authentication_results": auth_results
            }
        })

    return findings


# ============================================================
# MAIN HEADER ANALYZER
# ============================================================

def analyze_headers(email_message):
    """
    Analyze important email headers for suspicious indicators.

    Checks:
    - From address
    - Reply-To address
    - Reply-To domain
    - Return-Path
    - Authentication-Results
    - SPF
    - DKIM
    - DMARC
    - Multiple From headers
    """

    findings = []

    # --------------------------------------------------------
    # Sender address analysis
    # --------------------------------------------------------

    findings.extend(
        analyze_sender_address(email_message)
    )

    # --------------------------------------------------------
    # Reply-To analysis
    # --------------------------------------------------------

    findings.extend(
        analyze_reply_to(email_message)
    )

    # --------------------------------------------------------
    # Return-Path analysis
    # --------------------------------------------------------

    findings.extend(
        analyze_return_path(email_message)
    )

    # --------------------------------------------------------
    # Authentication analysis
    # --------------------------------------------------------

    findings.extend(
        analyze_authentication(email_message)
    )


    # --------------------------------------------------------
    # Multiple From header analysis
    # --------------------------------------------------------

    findings.extend(
        analyze_multiple_from(email_message)
    )

    return findings