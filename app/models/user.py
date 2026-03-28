from app.extensions import db
from datetime import datetime, timezone


class User(db.Model):
    __tablename__ = "users"

    # Primary key — unique ID for each user, auto-incremented
    id = db.Column(db.Integer, primary_key=True)

    # User's email — must be unique, used for login
    email = db.Column(db.String(255), unique=True, nullable=False)

    # Argon2 hash of master password — never store the real password
    auth_hash = db.Column(db.String(512), nullable=False)

    # Salt used for deriving the encryption key (Path B from our architecture)
    # Different from the salt inside auth_hash (which Argon2 manages internally)
    encryption_salt = db.Column(db.LargeBinary(16), nullable=False)

    # TOTP secret for 2FA — base32 encoded string
    totp_secret = db.Column(db.String(32), nullable=True)

    # Whether the user has completed 2FA setup
    totp_enabled = db.Column(db.Boolean, default=False, nullable=False)

    # Account lockout — track failed login attempts
    failed_login_attempts = db.Column(db.Integer, default=0, nullable=False)
    locked_until = db.Column(db.DateTime, nullable=True)

    # Timestamps
    created_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )
    updated_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    # Relationship — one user has many vault entries
    vault_entries = db.relationship(
        "VaultEntry",
        backref="user",
        lazy=True,
        cascade="all, delete-orphan"
    )

    def __repr__(self):
        return f"<User {self.email}>"