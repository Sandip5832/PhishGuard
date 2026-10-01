from core.parser import parse_email

from analyzers.url_analyzer import (
    extract_urls,
    analyze_url,
    analyze_urls
)


# ==========================================
# TEST 1: SAMPLE EMAIL
# ==========================================

print("\n====================================")
print("      PHISHGUARD URL TEST")
print("====================================")


email = parse_email(
    "samples/sample_phishing.eml"
)


# ==========================================
# TEST 2: EXTRACT URLS
# ==========================================

urls = extract_urls(email)

print("\nEXTRACTED URLS")
print("------------------------------------")

if not urls:

    print("No URLs found.")

else:

    for i, url in enumerate(
        urls,
        start=1
    ):

        print(f"{i}. {url}")


print(
    f"\nTotal URLs Found: {len(urls)}"
)


# ==========================================
# TEST 3: ANALYZE EACH URL
# ==========================================

print("\nURL ANALYSIS")
print("------------------------------------")

if not urls:

    print("No URLs available for analysis.")

else:

    for i, url in enumerate(
        urls,
        start=1
    ):

        print(f"\nURL {i}")
        print(f"URL: {url}")

        findings = analyze_url(url)

        if not findings:

            print(
                "Status: No suspicious indicators detected."
            )

        else:

            for finding in findings:

                print(
                    f"Type: {finding['type']}"
                )

                print(
                    f"Severity: {finding['severity']}"
                )

                print(
                    f"Message: {finding['message']}"
                )

                print(
                    f"Evidence: {finding['evidence']}"
                )


# ==========================================
# TEST 4: ANALYZE ALL EMAIL URLs
# ==========================================

all_findings = analyze_urls(email)


print("\n====================================")
print("       URL FINDING SUMMARY")
print("====================================")


high_count = 0
medium_count = 0
low_count = 0


for finding in all_findings:

    severity = finding["severity"].lower()

    if severity == "high":

        high_count += 1

    elif severity == "medium":

        medium_count += 1

    elif severity == "low":

        low_count += 1


print(f"Total URL Findings: {len(all_findings)}")
print(f"High: {high_count}")
print(f"Medium: {medium_count}")
print(f"Low: {low_count}")


# ==========================================
# TEST 5: FINAL RESULT
# ==========================================

print("\n====================================")
print("          TEST RESULT")
print("====================================")


if all_findings:

    print(
        "PASS: Suspicious URL indicators detected."
    )

else:

    print(
        "PASS: No suspicious URL indicators detected."
    )


print("\nURL analyzer test completed.")