import os
import smtplib
import ssl
from email.message import EmailMessage


def mask_email(email: str) -> str:
    if not isinstance(email, str):
        return "invalid_email"

    email = email.strip()

    if email.count("@") != 1:
        return "invalid_email"

    username, domain = email.rsplit("@", 1)

    if not username or not domain or any(c.isspace() for c in email):
        return "invalid_email"

    length = len(username)

    if length <= 2:
        masked_username = "*" * length
    elif length <= 4:
        masked_username = username[0] + "*" * (length - 1)
    else:
        masked_username = (
            username[0]
            + "*" * (length - 2)
            + username[-1]
        )

    return f"{masked_username}@{domain.lower()}"


def send_reset_code(recipient: str, pin: str) -> None:
    sender = os.environ["SMTP_EMAIL"]
    password = os.environ["SMTP_PASSWORD"]

    message = EmailMessage()

    message["Subject"] = "Password Reset Verification Code"
    message["From"] = sender
    message["To"] = recipient

    message.set_content(
        f"Your password reset code is: {pin}\n\n"
        "This code expires in 10 minutes.\n"
        "If you did not request this, ignore this email."
    )

    context = ssl.create_default_context()

    with smtplib.SMTP_SSL(
        "smtp.gmail.com",
        465,
        context=context,
        timeout=10
    ) as smtp:
        smtp.login(sender, password)
        smtp.send_message(message)


