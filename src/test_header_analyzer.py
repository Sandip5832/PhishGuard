from core.parser import parse_email
from analyzers.header_analyzer import analyze_headers


# Parse the sample email
email = parse_email("samples/sample_phishing.eml")


# Display important headers
print("FROM HEADER:")
print(email.get("From"))

print()

print("REPLY-TO HEADER:")
print(email.get("Reply-To"))

print()

print("AUTHENTICATION RESULTS:")
print(email.get("Authentication-Results"))

print()


# Analyze all headers
# This already includes SPF, DKIM and DMARC analysis
findings = analyze_headers(email)


# Display results
print("HEADER ANALYSIS")
print("----------------")

if not findings:

    print("No suspicious header findings detected.")

else:

    for finding in findings:

        print()
        print("Type:", finding["type"])
        print("Severity:", finding["severity"])
        print("Message:", finding["message"])
        print("Evidence:", finding["evidence"])