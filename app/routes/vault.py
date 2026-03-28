import os
import secrets
import string
from flask import Blueprint, request, jsonify, g
from app.extensions import db
from app.models.vault_entry import VaultEntry
from app.schemas.vault_schema import VaultEntryCreateSchema, VaultEntryUpdateSchema
from app.services.crypto_service import generate_encryption_key, encrypt, decrypt
from app.services.audit_service import log_action
from app.middleware.jwt_required import jwt_required
from marshmallow import ValidationError
from datetime import datetime, timezone

vault_bp = Blueprint("vault", __name__)


def get_encryption_key(user):
    """
    Derives the AES-256 encryption key from the user's master password.
    We can't do this without the master password — so we require it
    in the request header for every vault operation.
    """
    master_password = request.headers.get("X-Master-Password")
    if not master_password:
        return None, jsonify({"error": "Master password required in X-Master-Password header."}), 401

    key = generate_encryption_key(
        encryption_salt=user.encryption_salt,
        password=master_password.encode("utf-8")
    )
    return key, None, None


def entry_to_dict(entry, key):
    """Decrypts a vault entry and returns it as a dictionary."""
    return {
        "id": entry.id,
        "website": entry.website,
        "username": decrypt(entry.encrypted_username, entry.iv_username, key),
        "password": decrypt(entry.encrypted_password, entry.iv_password, key),
        "notes": decrypt(entry.encrypted_notes, entry.iv_notes, key) if entry.encrypted_notes else None,
        "created_at": entry.created_at.isoformat(),
        "updated_at": entry.updated_at.isoformat(),
    }


# ─── List All Entries ────────────────────────────────────────────────────────

@vault_bp.route("/", methods=["GET"])
@jwt_required
def list_entries():
    key, error, status = get_encryption_key(g.current_user)
    if error:
        return error, status

    entries = VaultEntry.query.filter_by(
        user_id=g.current_user.id,
        is_deleted=False
    ).all()

    log_action(g.current_user.id, "VAULT_LIST", f"Listed {len(entries)} entries")

    return jsonify([entry_to_dict(e, key) for e in entries]), 200


# ─── Get Single Entry ────────────────────────────────────────────────────────

@vault_bp.route("/<int:entry_id>", methods=["GET"])
@jwt_required
def get_entry(entry_id):
    key, error, status = get_encryption_key(g.current_user)
    if error:
        return error, status

    entry = VaultEntry.query.filter_by(
        id=entry_id,
        user_id=g.current_user.id,
        is_deleted=False
    ).first()

    if not entry:
        return jsonify({"error": "Entry not found."}), 404

    log_action(g.current_user.id, "VAULT_READ", f"Read entry id={entry_id}")

    return jsonify(entry_to_dict(entry, key)), 200


# ─── Create Entry ────────────────────────────────────────────────────────────

@vault_bp.route("/", methods=["POST"])
@jwt_required
def create_entry():
    key, error, status = get_encryption_key(g.current_user)
    if error:
        return error, status

    schema = VaultEntryCreateSchema()
    try:
        data = schema.load(request.get_json())
    except ValidationError as e:
        return jsonify({"errors": e.messages}), 400

    # Encrypt each sensitive field with its own IV
    encrypted_username, iv_username = encrypt(data["username"], key)
    encrypted_password, iv_password = encrypt(data["password"], key)

    encrypted_notes, iv_notes = None, None
    if data["notes"]:
        encrypted_notes, iv_notes = encrypt(data["notes"], key)

    entry = VaultEntry(
        user_id=g.current_user.id,
        website=data["website"],
        encrypted_username=encrypted_username,
        encrypted_password=encrypted_password,
        encrypted_notes=encrypted_notes,
        iv_username=iv_username,
        iv_password=iv_password,
        iv_notes=iv_notes,
    )
    db.session.add(entry)
    db.session.commit()

    log_action(g.current_user.id, "VAULT_CREATE", f"Created entry for {data['website']}")

    return jsonify(entry_to_dict(entry, key)), 201


# ─── Update Entry ────────────────────────────────────────────────────────────

@vault_bp.route("/<int:entry_id>", methods=["PUT"])
@jwt_required
def update_entry(entry_id):
    key, error, status = get_encryption_key(g.current_user)
    if error:
        return error, status

    entry = VaultEntry.query.filter_by(
        id=entry_id,
        user_id=g.current_user.id,
        is_deleted=False
    ).first()

    if not entry:
        return jsonify({"error": "Entry not found."}), 404

    schema = VaultEntryUpdateSchema()
    try:
        data = schema.load(request.get_json())
    except ValidationError as e:
        return jsonify({"errors": e.messages}), 400

    # Only update fields that were provided
    if "website" in data:
        entry.website = data["website"]

    if "username" in data:
        entry.encrypted_username, entry.iv_username = encrypt(data["username"], key)

    if "password" in data:
        entry.encrypted_password, entry.iv_password = encrypt(data["password"], key)

    if "notes" in data:
        if data["notes"]:
            entry.encrypted_notes, entry.iv_notes = encrypt(data["notes"], key)
        else:
            entry.encrypted_notes = None
            entry.iv_notes = None

    db.session.commit()

    log_action(g.current_user.id, "VAULT_UPDATE", f"Updated entry id={entry_id}")

    return jsonify(entry_to_dict(entry, key)), 200


# ─── Delete Entry (Soft Delete) ──────────────────────────────────────────────

@vault_bp.route("/<int:entry_id>", methods=["DELETE"])
@jwt_required
def delete_entry(entry_id):
    entry = VaultEntry.query.filter_by(
        id=entry_id,
        user_id=g.current_user.id,
        is_deleted=False
    ).first()

    if not entry:
        return jsonify({"error": "Entry not found."}), 404

    # Soft delete — mark as deleted, don't actually remove
    entry.is_deleted = True
    entry.deleted_at = datetime.now(timezone.utc)
    db.session.commit()

    log_action(g.current_user.id, "VAULT_DELETE", f"Deleted entry id={entry_id}")

    return jsonify({"message": "Entry deleted."}), 200


# ─── Search ──────────────────────────────────────────────────────────────────

@vault_bp.route("/search", methods=["GET"])
@jwt_required
def search_entries():
    key, error, status = get_encryption_key(g.current_user)
    if error:
        return error, status

    query = request.args.get("q", "").strip().lower()
    if not query:
        return jsonify({"error": "Search query required. Use ?q=yourquery"}), 400

    # Search by website name (plain text — not encrypted)
    entries = VaultEntry.query.filter(
        VaultEntry.user_id == g.current_user.id,
        VaultEntry.is_deleted == False,
        VaultEntry.website.ilike(f"%{query}%")
    ).all()

    log_action(g.current_user.id, "VAULT_SEARCH", f"Searched for: {query}")

    return jsonify([entry_to_dict(e, key) for e in entries]), 200


# ─── Password Generator ──────────────────────────────────────────────────────

@vault_bp.route("/generate-password", methods=["GET"])
@jwt_required
def generate_password():
    # Get options from query params with defaults
    try:
        length = int(request.args.get("length", 16))
    except ValueError:
        return jsonify({"error": "Length must be a number."}), 400

    if length < 8 or length > 64:
        return jsonify({"error": "Length must be between 8 and 64."}), 400

    use_upper = request.args.get("upper", "true").lower() == "true"
    use_lower = request.args.get("lower", "true").lower() == "true"
    use_digits = request.args.get("digits", "true").lower() == "true"
    use_symbols = request.args.get("symbols", "true").lower() == "true"

    # Build character pool
    charset = ""
    if use_upper:
        charset += string.ascii_uppercase
    if use_lower:
        charset += string.ascii_lowercase
    if use_digits:
        charset += string.digits
    if use_symbols:
        charset += string.punctuation

    if not charset:
        return jsonify({"error": "At least one character type must be selected."}), 400

    # secrets.choice is cryptographically secure (unlike random.choice)
    password = "".join(secrets.choice(charset) for _ in range(length))

    return jsonify({"password": password, "length": length}), 200