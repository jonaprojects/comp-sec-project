import hashlib
import secrets


def generate_reset_code() -> str:
    random_value = secrets.token_hex(16)

    return hashlib.sha1(
        random_value.encode()
    ).hexdigest()
