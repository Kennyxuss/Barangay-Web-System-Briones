"""
BarangayConnect - Barangay Management and Information System
Application configuration.
"""
import os
import secrets

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def _load_secret_key() -> str:
    """
    Return the application secret key.

    Order of preference:
      1. SECRET_KEY environment variable
      2. .secret_key file (auto-generated on first run so that sessions
         survive server restarts)
    """
    env_key = os.environ.get("SECRET_KEY")
    if env_key:
        return env_key

    key_file = os.path.join(BASE_DIR, ".secret_key")
    try:
        with open(key_file, "r", encoding="utf-8") as fh:
            key = fh.read().strip()
            if key:
                return key
    except OSError:
        pass

    key = secrets.token_hex(32)
    try:
        with open(key_file, "w", encoding="utf-8") as fh:
            fh.write(key)
    except OSError:
        pass  # fall back to an ephemeral key rather than crashing
    return key


class Config:
    """Base configuration for the Flask application."""

    SECRET_KEY = _load_secret_key()
    DATABASE = os.path.join(BASE_DIR, "barangay.db")
    UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "uploads")
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 5 MB max upload

    ALLOWED_IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "webp", "gif"}

    # Pagination defaults
    PER_PAGE = 10

    # System identity (defaults used when seeding the database; can be
    # changed later from Admin > Settings)
    SYSTEM_NAME = "BarangayConnect"
    SYSTEM_TAGLINE = "Barangay Management and Information System"
