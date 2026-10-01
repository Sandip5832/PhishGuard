def analyze_content(email_message):
    """
    Analyze email body for suspicious phishing indicators.
    """

    findings = []

    # ============================================================
    # GET EMAIL BODY
    # ============================================================

    try:
        body = email_message.get_body(
            preferencelist=("plain", "html")
        )

        content = body.get_content()

    except Exception:
        content = str(email_message)

    content_lower = content.lower()


    # ============================================================
    # MEDIUM-SEVERITY PHISHING PHRASES
    # ============================================================

    suspicious_phrases = [
        # Account verification
        "verify your account",
        "verify your identity",
        "confirm your account",
        "confirm your identity",

        # Account problems
        "account has been suspended",
        "account will be suspended",
        "your account is locked",
        "your account has been locked",
        "account has been compromised",

        # Password / login
        "reset your password",
        "change your password",
        "login immediately",
        "sign in immediately",
        "update your password",

        # Urgency
        "urgent action required",
        "click here immediately",
        "action required",
        "immediate action required",

        # Security
        "security alert",
        "security verification required",
        "unusual activity detected",
        "suspicious activity detected"
    ]


    # ============================================================
    # HIGH-SEVERITY PHISHING PHRASES
    # ============================================================

    high_risk_phrases = [
        # Credential requests
        "enter your password",
        "provide your password",
        "enter your login details",
        "enter your credentials",
        "provide your credentials",

        # Financial information
        "enter your credit card",
        "enter your card details",
        "provide your bank details",
        "provide your banking information",
        "enter your bank account",

        # Payment requests
        "make a payment immediately",
        "payment is required immediately",
        "send money immediately",
        "transfer money immediately",

        # Sensitive information
        "provide your otp",
        "enter your otp",
        "share your otp",
        "provide your social security number"
    ]


    # ============================================================
    # CHECK MEDIUM-SEVERITY PHRASES
    # ============================================================

    for phrase in suspicious_phrases:

        if phrase in content_lower:

            findings.append({
                "type": "suspicious_content",
                "severity": "medium",
                "message": (
                    f"Suspicious phishing phrase detected: "
                    f"'{phrase}'"
                ),
                "evidence": {
                    "phrase": phrase
                }
            })


    # ============================================================
    # CHECK HIGH-SEVERITY PHRASES
    # ============================================================

    for phrase in high_risk_phrases:

        if phrase in content_lower:

            findings.append({
                "type": "high_risk_content",
                "severity": "high",
                "message": (
                    f"High-risk phishing phrase detected: "
                    f"'{phrase}'"
                ),
                "evidence": {
                    "phrase": phrase
                }
            })


    # ============================================================
    # URGENCY INDICATORS
    # ============================================================

    urgency_phrases = [
        "within 24 hours",
        "within 12 hours",
        "within 1 hour",
        "act now",
        "do not delay",
        "last warning",
        "final warning",
        "expires today",
        "expires soon"
    ]

    for phrase in urgency_phrases:

        if phrase in content_lower:

            findings.append({
                "type": "urgency_indicator",
                "severity": "medium",
                "message": (
                    f"Urgency indicator detected: "
                    f"'{phrase}'"
                ),
                "evidence": {
                    "phrase": phrase
                }
            })


    # ============================================================
    # ATTACHMENT INDICATORS
    # ============================================================

    attachment_phrases = [
        "open the attachment",
        "open attached file",
        "download the attachment",
        "download the attached file",
        "see attached document",
        "attached document"
    ]

    for phrase in attachment_phrases:

        if phrase in content_lower:

            findings.append({
                "type": "suspicious_attachment_reference",
                "severity": "medium",
                "message": (
                    f"Suspicious attachment instruction detected: "
                    f"'{phrase}'"
                ),
                "evidence": {
                    "phrase": phrase
                }
            })


    # ============================================================
    # REWARD / THREAT INDICATORS
    # ============================================================

    threat_phrases = [
        "your account will be closed",
        "your account will be deleted",
        "you will lose access",
        "legal action will be taken",
        "your account will be permanently disabled"
    ]

    for phrase in threat_phrases:

        if phrase in content_lower:

            findings.append({
                "type": "threat_indicator",
                "severity": "high",
                "message": (
                    f"Threat-based phishing language detected: "
                    f"'{phrase}'"
                ),
                "evidence": {
                    "phrase": phrase
                }
            })


    # ============================================================
    # RETURN FINDINGS
    # ============================================================

    return findings