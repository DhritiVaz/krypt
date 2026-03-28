import os
from dotenv import load_dotenv

load_dotenv()  # reads your .env file and loads variables into the environment

class Config:
    """Base configuration — settings shared across all environments."""

    # Secret key for signing JWT tokens. MUST be long and random in production.
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-in-production")

    # Database connection URL
    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL",
        "postgresql://postgres:password@localhost:5432/krypt"
    )

    # Disable a SQLAlchemy feature we don't need (saves memory)
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Redis URL for rate limiting
    RATELIMIT_STORAGE_URI = os.getenv("REDIS_URL", "redis://localhost:6379")


class DevelopmentConfig(Config):
    """Development settings — extra debug info, relaxed rules."""
    DEBUG = True


class TestingConfig(Config):
    """Testing settings — uses a separate test database."""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = os.getenv(
        "TEST_DATABASE_URL",
        "postgresql://postgres:password@localhost:5432/krypt_test"
    )


class ProductionConfig(Config):
    """Production settings — strict, no debug info exposed."""
    DEBUG = False


# This dict lets us select config by name (string) instead of importing the class directly
config_by_name = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
}