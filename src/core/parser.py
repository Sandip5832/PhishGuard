from email import policy
from email.parser import BytesParser


def parse_email(file_path):
    with open(file_path, "rb") as file:
        email_message=BytesParser(policy=policy.default).parse(file)
        return email_message