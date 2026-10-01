from core.parser import parse_email

from analyzers.content_analyzer import analyze_content
from analyzers.header_analyzer import analyze_headers
from analyzers.url_analyzer import analyze_urls


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def get_finding_source(source):
    """
    Return a readable source name for a finding.
    """

    source_names = {
        "content": "Email Content",
        "header": "Email Headers",
        "url": "URL Analysis"
    }

    return source_names.get(source, "Security Analysis")


def format_evidence(evidence):
    """
    Format evidence dictionary in a readable way.
    """

    if not evidence:
        return "No additional evidence available."

    lines = []

    for key, value in evidence.items():

        if isinstance(value, list):
            value = ", ".join(str(item) for item in value)

        lines.append(
            f"  {key}: {value}"
        )

    return "\n".join(lines)


def print_findings(findings, source):
    """
    Print findings with clear source and evidence.
    """

    if not findings:

        print("No suspicious findings detected.")

        return

    source_name = get_finding_source(source)

    for i, finding in enumerate(findings, start=1):

        print()
        print(f"Finding {i}")
        print("------------------------------------")

        print("Type:", finding.get("type", "unknown"))

        print(
            "Severity:",
            finding.get("severity", "unknown").upper()
        )

        print("Source:", source_name)

        print(
            "Message:",
            finding.get(
                "message",
                "No message available."
            )
        )

        print("Evidence:")

        print(
            format_evidence(
                finding.get("evidence", {})
            )
        )


def write_findings(report, findings, source):
    """
    Write detailed findings to the report file.
    """

    source_name = get_finding_source(source)

    if not findings:

        report.write(
            "No suspicious findings detected.\n\n"
        )

        return

    for i, finding in enumerate(findings, start=1):

        report.write(
            f"\nFinding {i}\n"
        )

        report.write(
            "------------------------------------\n"
        )

        report.write(
            f"Type: {finding.get('type', 'unknown')}\n"
        )

        report.write(
            f"Severity: "
            f"{finding.get('severity', 'unknown').upper()}\n"
        )

        report.write(
            f"Source: {source_name}\n"
        )

        report.write(
            f"Message: "
            f"{finding.get('message', 'No message available.')}\n"
        )

        report.write("Evidence:\n")

        evidence = finding.get("evidence", {})

        if evidence:

            for key, value in evidence.items():

                if isinstance(value, list):
                    value = ", ".join(
                        str(item)
                        for item in value
                    )

                report.write(
                    f"  {key}: {value}\n"
                )

        else:

            report.write(
                "  No additional evidence available.\n"
            )

        report.write("\n")


# ============================================================
# LOAD EMAIL
# ============================================================

email_file = input(
    "Enter email file path: "
).strip()

email = parse_email(email_file)


# ============================================================
# CONTENT ANALYSIS
# ============================================================

content_findings = analyze_content(email)


# ============================================================
# HEADER ANALYSIS
# ============================================================

header_findings = analyze_headers(email)


# ============================================================
# URL ANALYSIS
# ============================================================

url_findings = analyze_urls(email)


# ============================================================
# COMBINE ALL FINDINGS
# ============================================================

all_findings = (
    content_findings
    + header_findings
    + url_findings
)


# ============================================================
# COUNT SEVERITY
# ============================================================

high_count = 0
medium_count = 0
low_count = 0


for finding in all_findings:

    severity = finding.get(
        "severity",
        ""
    ).lower()

    if severity == "high":

        high_count += 1

    elif severity == "medium":

        medium_count += 1

    elif severity == "low":

        low_count += 1


# ============================================================
# PHISHING RISK SCORE
# ============================================================

HIGH_POINTS = 25
MEDIUM_POINTS = 10
LOW_POINTS = 5


raw_score = (
    high_count * HIGH_POINTS
    + medium_count * MEDIUM_POINTS
    + low_count * LOW_POINTS
)


# Maximum score is 100
phishing_score = min(
    raw_score,
    100
)


# ============================================================
# OVERALL RISK
# ============================================================

if high_count >= 2:

    overall_risk = "HIGH"

elif high_count == 1:

    overall_risk = "MEDIUM-HIGH"

elif medium_count >= 2:

    overall_risk = "MEDIUM"

elif medium_count == 1:

    overall_risk = "LOW-MEDIUM"

else:

    overall_risk = "LOW"


# ============================================================
# DISPLAY REPORT
# ============================================================

print("\n====================================")
print("          PHISHGUARD REPORT")
print("====================================")


# ============================================================
# CONTENT ANALYSIS
# ============================================================

print("\nCONTENT ANALYSIS")
print("------------------------------------")

print_findings(
    content_findings,
    "content"
)


# ============================================================
# HEADER ANALYSIS
# ============================================================

print("\nHEADER ANALYSIS")
print("------------------------------------")

print_findings(
    header_findings,
    "header"
)


# ============================================================
# URL ANALYSIS
# ============================================================

print("\nURL ANALYSIS")
print("------------------------------------")

print_findings(
    url_findings,
    "url"
)


# ============================================================
# RISK ASSESSMENT
# ============================================================

print("\n====================================")
print("          RISK ASSESSMENT")
print("====================================")

print(
    f"Overall Risk: {overall_risk}"
)

print(
    f"Phishing Risk Score: "
    f"{phishing_score}/100"
)

print(
    f"High Findings: {high_count}"
)

print(
    f"Medium Findings: {medium_count}"
)

print(
    f"Low Findings: {low_count}"
)


# ============================================================
# SCORE BREAKDOWN
# ============================================================

print("\n====================================")
print("          SCORE BREAKDOWN")
print("====================================")

print(
    f"High Findings    : "
    f"{high_count} x {HIGH_POINTS} = "
    f"{high_count * HIGH_POINTS}"
)

print(
    f"Medium Findings  : "
    f"{medium_count} x {MEDIUM_POINTS} = "
    f"{medium_count * MEDIUM_POINTS}"
)

print(
    f"Low Findings     : "
    f"{low_count} x {LOW_POINTS} = "
    f"{low_count * LOW_POINTS}"
)

print("------------------------------------")

print(
    f"Raw Score        : {raw_score}"
)

print(
    f"Final Score      : "
    f"{phishing_score}/100"
)


# ============================================================
# RECOMMENDATION
# ============================================================

print("\n====================================")
print("          RECOMMENDATION")
print("====================================")


if overall_risk == "HIGH":

    print(
        "Do NOT click links or open attachments."
    )

    print(
        "Do NOT provide passwords or personal information."
    )

    print(
        "Verify the sender through an official channel."
    )


elif overall_risk == "MEDIUM-HIGH":

    print(
        "Be very careful with links and attachments."
    )

    print(
        "Verify the sender before taking any action."
    )


elif overall_risk == "MEDIUM":

    print(
        "Do not trust suspicious links or attachments."
    )

    print(
        "Verify the email before responding."
    )


elif overall_risk == "LOW-MEDIUM":

    print(
        "Exercise caution and verify suspicious content."
    )


else:

    print(
        "No major suspicious indicators were detected."
    )

    print(
        "Continue following normal email security practices."
    )


# ============================================================
# SAVE FINAL REPORT
# ============================================================

report_path = (
    "reports/phishguard_report.txt"
)


with open(
    report_path,
    "w",
    encoding="utf-8"
) as report:

    # --------------------------------------------------------
    # REPORT HEADER
    # --------------------------------------------------------

    report.write(
        "====================================\n"
    )

    report.write(
        "          PHISHGUARD REPORT\n"
    )

    report.write(
        "====================================\n\n"
    )


    # --------------------------------------------------------
    # RISK SUMMARY
    # --------------------------------------------------------

    report.write(
        "RISK ASSESSMENT\n"
    )

    report.write(
        "------------------------------------\n"
    )

    report.write(
        f"Overall Risk: "
        f"{overall_risk}\n"
    )

    report.write(
        f"Phishing Risk Score: "
        f"{phishing_score}/100\n"
    )

    report.write(
        f"High Findings: "
        f"{high_count}\n"
    )

    report.write(
        f"Medium Findings: "
        f"{medium_count}\n"
    )

    report.write(
        f"Low Findings: "
        f"{low_count}\n\n"
    )


    # --------------------------------------------------------
    # SCORE BREAKDOWN
    # --------------------------------------------------------

    report.write(
        "SCORE BREAKDOWN\n"
    )

    report.write(
        "------------------------------------\n"
    )

    report.write(
        f"High Findings   : "
        f"{high_count} x {HIGH_POINTS} = "
        f"{high_count * HIGH_POINTS}\n"
    )

    report.write(
        f"Medium Findings : "
        f"{medium_count} x {MEDIUM_POINTS} = "
        f"{medium_count * MEDIUM_POINTS}\n"
    )

    report.write(
        f"Low Findings    : "
        f"{low_count} x {LOW_POINTS} = "
        f"{low_count * LOW_POINTS}\n"
    )

    report.write(
        f"Raw Score       : "
        f"{raw_score}\n"
    )

    report.write(
        f"Final Score     : "
        f"{phishing_score}/100\n\n"
    )


    # --------------------------------------------------------
    # CONTENT FINDINGS
    # --------------------------------------------------------

    report.write(
        "CONTENT ANALYSIS\n"
    )

    report.write(
        "====================================\n"
    )

    write_findings(
        report,
        content_findings,
        "content"
    )


    # --------------------------------------------------------
    # HEADER FINDINGS
    # --------------------------------------------------------

    report.write(
        "HEADER ANALYSIS\n"
    )

    report.write(
        "====================================\n"
    )

    write_findings(
        report,
        header_findings,
        "header"
    )


    # --------------------------------------------------------
    # URL FINDINGS
    # --------------------------------------------------------

    report.write(
        "URL ANALYSIS\n"
    )

    report.write(
        "====================================\n"
    )

    write_findings(
        report,
        url_findings,
        "url"
    )


    # --------------------------------------------------------
    # ALL FINDINGS SUMMARY
    # --------------------------------------------------------

    report.write(
        "\nDETAILED FINDING SUMMARY\n"
    )

    report.write(
        "====================================\n"
    )

    report.write(
        f"Total Findings: "
        f"{len(all_findings)}\n"
    )

    report.write(
        f"High: {high_count}\n"
    )

    report.write(
        f"Medium: {medium_count}\n"
    )

    report.write(
        f"Low: {low_count}\n\n"
    )


    # --------------------------------------------------------
    # RECOMMENDATION
    # --------------------------------------------------------

    report.write(
        "RECOMMENDATION\n"
    )

    report.write(
        "------------------------------------\n"
    )


    if overall_risk == "HIGH":

        report.write(
            "Do NOT click links or open attachments.\n"
        )

        report.write(
            "Do NOT provide passwords or personal information.\n"
        )

        report.write(
            "Verify the sender through an official channel.\n"
        )


    elif overall_risk == "MEDIUM-HIGH":

        report.write(
            "Be very careful with links and attachments.\n"
        )

        report.write(
            "Verify the sender before taking any action.\n"
        )


    elif overall_risk == "MEDIUM":

        report.write(
            "Do not trust suspicious links or attachments.\n"
        )

        report.write(
            "Verify the email before responding.\n"
        )


    elif overall_risk == "LOW-MEDIUM":

        report.write(
            "Exercise caution and verify suspicious content.\n"
        )


    else:

        report.write(
            "No major suspicious indicators were detected.\n"
        )

        report.write(
            "Continue following normal email security practices.\n"
        )


# ============================================================
# FINAL MESSAGE
# ============================================================

print("\n====================================")
print("       REPORT SAVED SUCCESSFULLY")
print("====================================")

print(
    f"Location: {report_path}"
)