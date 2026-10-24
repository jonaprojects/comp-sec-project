import hashlib
import secrets

from app import db

from ...config import Config
from ..models import PasswordHistory


def generate_reset_code() -> str:
    random_value = secrets.token_hex(16)

    return hashlib.sha1(random_value.encode()).hexdigest()

def update_password(user, new_password: str):
    try:
        # Save the previous password in history
        old_password_record = PasswordHistory(
            user_id=user.id, password_hash=user.hashed_password, salt=user.salt
        )
        db.session.add(old_password_record)

        # Update the current password
        user.set_password(new_password)

        # Flush changes before querying history
        db.session.flush()

        # Retrieve password history, newest first
        history = (
            PasswordHistory.query.filter_by(user_id=user.id)
            .order_by(PasswordHistory.id.desc())
            .all()
        )

        # Remove entries exceeding configured history limit
        for entry in history[Config.PASSWORD_HISTORY :]:
            db.session.delete(entry)

        # Save all changes atomically
        db.session.commit()

    except Exception:
        db.session.rollback()
        raise
