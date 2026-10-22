"""
Validate user input according to the project's requirements and best practices.
"""

import re

from config import Config

EMAIL_REGEX = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
EMAIL_PATTERN = re.compile(EMAIL_REGEX)

PHONE_REGEX = r"^\+?[0-9]{7,15}$"
PHONE_PATTERN = re.compile(PHONE_REGEX)

def is_valid_username(username: str) -> bool:
    return len(username) > 0

def is_valid_email(email: str) -> bool:
    return bool(EMAIL_PATTERN.match(email))

def is_valid_phone(phone: str):
    return bool(PHONE_PATTERN.match(phone))

def is_valid_password(password: str) -> bool:
    if len(password) < Config.PASSWORD_MIN_LENGTH:
        return False

    if Config.PASSWORD_REQUIRE_DIGIT:
        has_digit = any(str.isdigit(c) for c in password)
        if not has_digit:
            return False

    if Config.PASSWORD_REQUIRE_LOWERCASE:
        has_lower = any(c.islower() for c in password)
        if not has_lower:
            return False

    if Config.PASSWORD_REQUIRE_UPPERCASE:
        has_upper = any(c.isupper() for c in password)
        if not has_upper:
            return False

    if Config.PASSWORD_REQUIRE_SPECIAL:
        is_special_char = lambda c: not (c.isalnum() or c.isspace())
        has_special = any(is_special_char(c) for c in password)
        if not has_special:
            return False

    # valid password
    return True


def is_valid_data(username: str, email: str, password: str):
    return is_valid_username(username) and is_valid_email(email) and is_valid_password(password)

