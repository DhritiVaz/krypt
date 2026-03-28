from app.extensions import db
from app.models.audit_log import AuditLog
from flask import request


def log_action(user_id: int | None, action: str, details: str | None = None):
    """
    Writes an audit log entry.
    Called after every significant action — login, vault access, edits, deletes.

    Args:
        user_id: ID of the user performing the action (None for failed logins)
        action: string like "VAULT_CREATE", "LOGIN_SUCCESS", "VAULT_DELETE"
        details: optional extra context
    """
    entry = AuditLog(
        user_id=user_id,
        action=action,
        details=details,
        ip_address=request.remote_addr
    )
    db.session.add(entry)
    db.session.commit()