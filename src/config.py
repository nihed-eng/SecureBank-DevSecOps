import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "local-only-change-me")
    DATABASE = os.getenv("DATABASE_PATH", str(BASE_DIR / "securebank.db"))
    VULNERABLE_DEMO = os.getenv("VULNERABLE_DEMO", "0").lower() in {"1", "true", "yes"}
    TESTING = False
    JSON_SORT_KEYS = False
    MAX_CONTENT_LENGTH = 1 * 1024 * 1024


class TestingConfig(Config):
    TESTING = True
    SECRET_KEY = "test-secret-not-for-production"
    DATABASE = ":memory:"
