from datetime import datetime, timedelta, timezone

from app import db
from config import Config


def is_login_locked(user) ->bool:
    if user.locked_until is None:
        return False

    now = datetime.now(timezone.utc)
    if now >= user.locked_until: # lockdown expired
        user.locked_until = None
        user.failed_login_attempts = 0
        db.session.commit()
        return False 

    return True 


def on_failed_login_attempt(user):
    user.failed_login_attempts += 1
    if user.failed_login_attempts >= Config.FAILED_LOGIN_LIMIT:
        now = datetime.now(timezone.utc)
        user.locked_until = now + timedelta(
            minutes=Config.FAILED_LOGIN_TIMEOUT_MINUTES
        )
    db.session.commit()


def on_successful_login_attempt(user):
    # clear lockdowns and reset failed attempt counter 
    user.failed_login_attempts = 0
    user.locked_until = None
    db.session.commit()