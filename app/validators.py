"""
Validate user input according to the project's requirements and best practices.
"""

import re
from pathlib import Path

from .models import PasswordHistory
from .utils.verify_password import check_password
from config import Config

EMAIL_REGEX = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
EMAIL_PATTERN = re.compile(EMAIL_REGEX)

PHONE_REGEX = r"^\+?[0-9]{7,15}$"
PHONE_PATTERN = re.compile(PHONE_REGEX)

# Load the dictionary txt file for weak passwords
BASE_DIR = Path(__file__).resolve().parents[2]
DICTIONARY_PATH = BASE_DIR / "data" / "10k-most-common.txt"

try:
    with open(DICTIONARY_PATH, "rt") as file:
        weak_passwords_list = file.readlines()
        WEAK_PASSWORDS = {
            weak_password.strip().casefold() for weak_password in weak_passwords_list
        }
except:
    WEAK_PASSWORDS = (
        set()
    )  # We shouldn't allow changing/reseting passwords in that case


def in_weak_dictionary(password: str) -> bool:
    return password.strip().casefold() in WEAK_PASSWORDS


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

    if Config.DICTIONARY_CHECK_ENABLED:
        if not WEAK_PASSWORDS or in_weak_dictionary(password):
            return False

    # valid password
    return True


def is_valid_data(username: str, email: str, password: str):
    return (
        is_valid_username(username)
        and is_valid_email(email)
        and is_valid_password(password)
    )


def in_password_history(user, new_password: str) -> bool:
    # Check the current password
    if user.check_password(new_password):
        return True

    history = (
        PasswordHistory.query.filter_by(user_id=user.id)
        .order_by(PasswordHistory.id.desc())
        .limit(Config.PASSWORD_HISTORY)
        .all()
    )

    for entry in history:
        if check_password(new_password, entry.salt, entry.password_hash):
            return True

    return False
