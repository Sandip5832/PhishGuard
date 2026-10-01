from core.parser import parse_email
email=parse_email("samples/sample_phishing.eml")

print("FROM:", email["FROM"])
print("TO:", email["TO"])
print("REPLY-TO:", email["Reply-To"])
print("SUBJECT:", email["Subject"])