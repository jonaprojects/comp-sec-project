import secrets 
from datetime import datetime, timezone
import hashlib
from flask import session
from app import db 

def on_reset_code_verified(user):

    # 1. Generate a secure token
    token = secrets.token_urlsafe(32)

    # 2. Store the token in the flask session
    session["reset_token"] = token

    # 3. Store hash in db 
    user.reset_token_hash = hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()

    # 4. Remember when verification happened
    session["reset_verified_user_id"] = user.id
    session["reset_verified_at"] = datetime.now(timezone.utc).timestamp()

    # 5. Clear the email verification code
    user.clear_reset_code()

    db.session.commit()
