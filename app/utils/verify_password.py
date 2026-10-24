import hashlib
import hmac

from ...config import Config


def check_password(password: str, stored_salt: str, stored_hash: str ) -> bool:
    """Check whether a password is correct for that user"""

    # 1. Salt
    salt = bytes.fromhex(stored_salt)
    message = password.encode("utf-8") + salt

    secret_key = bytes.fromhex(Config.HMAC_SECRET_KEY)

    # 2. Hash
    hash_result = hmac.new(
        key=secret_key, msg=message, digestmod=hashlib.sha256
    ).hexdigest()

    # 3. Compare safely (not with ==, that's vulnerable to timing attacks)
    return hmac.compare_digest(hash_result, stored_hash)