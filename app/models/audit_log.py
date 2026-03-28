from app.extensions import db
from datetime import datetime, timezone


class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    # Primary key
    id = db.Column(db.Integer, primary_key=True)

    # Which user performed the action (nullable — failed logins may have no valid user)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)

    # What action was performed — e.g. "LOGIN_SUCCESS", "VAULT_CREATE", "LOGIN_FAILED"
    action = db.Column(db.String(64), nullable=False)

    # Extra context — e.g. which vault entry was accessed, IP address
    details = db.Column(db.Text, nullable=True)

    # IP address of the request
    ip_address = db.Column(db.String(45), nullable=True)

    # When it happened — set once on insert, never changed
    created_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    def __repr__(self):
        return f"<AuditLog {self.action} (user_id={self.user_id})>"