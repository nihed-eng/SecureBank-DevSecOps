import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


class Config:
    APP_ENV = os.getenv("APP_ENV", "development")

    SECRET_KEY = os.getenv("SECRET_KEY")
    DATABASE = os.getenv("DATABASE_PATH", str(BASE_DIR / "securebank.db"))

    VULNERABLE_DEMO = os.getenv("VULNERABLE_DEMO", "0").lower() in {"1", "true", "yes"}

    TESTING = False
    JSON_SORT_KEYS = False
    MAX_CONTENT_LENGTH = 1 * 1024 * 1024

    @classmethod
    def validate(cls):
        if cls.APP_ENV == "production":
            if cls.VULNERABLE_DEMO:
                raise RuntimeError("ERREUR : VULNERABLE_DEMO interdit en production")

            if not cls.SECRET_KEY or len(cls.SECRET_KEY) < 32:
                raise RuntimeError(
                    "ERREUR : SECRET_KEY de production absente ou trop courte"
                )


class TestingConfig(Config):
    TESTING = True
    DATABASE = ":memory:"
