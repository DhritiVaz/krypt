from app.extensions import db
from datetime import datetime, timezone


class VaultEntry(db.Model):
    __tablename__ = "vault_entries"

    # Primary key
    id = db.Column(db.Integer, primary_key=True)

    # Foreign key — which user owns this entry
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    # Website name — stored as plain text (not sensitive)
    website = db.Column(db.String(255), nullable=False)

    # Username/email for that website — stored encrypted
    encrypted_username = db.Column(db.LargeBinary, nullable=False)

    # The actual password — stored encrypted
    encrypted_password = db.Column(db.LargeBinary, nullable=False)

    # Notes — stored encrypted
    encrypted_notes = db.Column(db.LargeBinary, nullable=True)

    # IV (Initialization Vector) for username encryption — unique per entry
    iv_username = db.Column(db.LargeBinary(12), nullable=False)

    # IV for password encryption — unique per entry
    iv_password = db.Column(db.LargeBinary(12), nullable=False)

    # IV for notes encryption — unique per entry
    iv_notes = db.Column(db.LargeBinary(12), nullable=True)

    # Soft delete — marks entry as deleted without removing from DB
    is_deleted = db.Column(db.Boolean, default=False, nullable=False)
    deleted_at = db.Column(db.DateTime, nullable=True)

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

    def __repr__(self):
        return f"<VaultEntry {self.website} (user_id={self.user_id})>"