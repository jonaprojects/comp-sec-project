import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    SQLALCHEMY_DATABASE_URI = os.environ["DATABASE_URL"]
    HMAC_SECRET_KEY = os.environ["HMAC_SECRET_KEY"]

    # Password Configurations
    PASSWORD_MIN_LENGTH = 10
    PASSWORD_REQUIRE_UPPERCASE = True
    PASSWORD_REQUIRE_LOWERCASE = True
    PASSWORD_REQUIRE_DIGIT = True
    PASSWORD_REQUIRE_SPECIAL = True

    @classmethod
    def get_validation_dict(cls)->dict:
        return {
            "password_min_length": cls.PASSWORD_MIN_LENGTH,
            "password_require_lowercase": cls.PASSWORD_REQUIRE_LOWERCASE,
            "password_require_uppercase": cls.PASSWORD_REQUIRE_UPPERCASE,
            "password_require_digit": cls.PASSWORD_REQUIRE_DIGIT,
            "password_require_special": cls.PASSWORD_REQUIRE_SPECIAL,
        }
