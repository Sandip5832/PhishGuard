from core.parser import parse_email
from analyzers.content_analyzer import analyze_content

# Parse sample email
email = parse_email("samples/sample_phishing.eml")

# Analyze email content
findings = analyze_content(email)

print("CONTENT ANALYSIS")
print("----------------")

if not findings:
    print("No suspicious content findings detected.")
else:
    for finding in findings:
        print()
        print("Type:", finding["type"])
        print("Severity:", finding["severity"])
        print("Message:", finding["message"])
        print("Evidence:", finding["evidence"])