from app.extensions import db as _db
from flask import render_template
from flask import Blueprint, request, jsonify, g
from app.extensions import db
from app.models.user import User
from app.models.audit_log import AuditLog
from app.schemas.auth_schema import RegisterSchema, LoginSchema
from app.services.auth_service import (
    hash_password, verify_password,
    generate_access_token, generate_refresh_token, decode_token,
    generate_totp_secret, get_totp_uri, verify_totp
)
from app.services.crypto_service import generate_encryption_salt
from app.middleware.jwt_required import jwt_required
from marshmallow import ValidationError
from datetime import datetime, timezone, timedelta
import jwt

auth_bp = Blueprint("auth", __name__)


def log_action(user_id, action, details=None):
    """Helper to write an audit log entry."""
    entry = AuditLog(
        user_id=user_id,
        action=action,
        details=details,
        ip_address=request.remote_addr
    )
    db.session.add(entry)
    db.session.commit()


# ─── Register ────────────────────────────────────────────────────────────────

@auth_bp.route("/register", methods=["POST"])
def register():
    # 1. Validate input
    schema = RegisterSchema()
    try:
        data = schema.load(request.get_json())
    except ValidationError as e:
        return jsonify({"errors": e.messages}), 400

    # 2. Check if email already exists
    if User.query.filter_by(email=data["email"]).first():
        return jsonify({"error": "Email already registered."}), 409

    # 3. Hash the master password (for login verification)
    auth_hash = hash_password(data["password"])

    # 4. Generate encryption salt (for AES key derivation — Path B)
    encryption_salt = generate_encryption_salt()

    # 5. Create user
    user = User(
        email=data["email"],
        auth_hash=auth_hash,
        encryption_salt=encryption_salt
    )
    db.session.add(user)
    db.session.commit()

    # 6. Audit log
    log_action(user.id, "REGISTER", f"New user registered: {user.email}")

    return jsonify({"message": "Registration successful."}), 201


# ─── Login ───────────────────────────────────────────────────────────────────

@auth_bp.route("/login", methods=["POST"])
def login():
    # 1. Validate input
    schema = LoginSchema()
    try:
        data = schema.load(request.get_json())
    except ValidationError as e:
        return jsonify({"errors": e.messages}), 400

    # 2. Find user
    user = User.query.filter_by(email=data["email"]).first()

    # 3. Check if account is locked
    if user and user.locked_until:
        if datetime.now(timezone.utc) < user.locked_until.replace(tzinfo=timezone.utc):
            return jsonify({"error": "Account locked. Try again later."}), 423

    # 4. Verify password
    if not user or not verify_password(user.auth_hash, data["password"]):
        # Increment failed attempts
        if user:
            user.failed_login_attempts += 1
            # Lock account after 10 failed attempts
            if user.failed_login_attempts >= 10:
                user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=30)
            db.session.commit()

        log_action(
            user.id if user else None,
            "LOGIN_FAILED",
            f"Failed login attempt for: {data['email']}"
        )
        return jsonify({"error": "Invalid email or password."}), 401

    # 5. Check 2FA if enabled
    if user.totp_enabled:
        if not data["totp_code"]:
            return jsonify({"error": "2FA code required.", "requires_2fa": True}), 401
        if not verify_totp(user.totp_secret, data["totp_code"]):
            log_action(user.id, "LOGIN_FAILED_2FA", "Invalid TOTP code")
            return jsonify({"error": "Invalid 2FA code."}), 401

    # 6. Successful login — reset failed attempts
    user.failed_login_attempts = 0
    user.locked_until = None
    db.session.commit()

    # 7. Generate tokens
    access_token = generate_access_token(user.id)
    refresh_token = generate_refresh_token(user.id)

    log_action(user.id, "LOGIN_SUCCESS", f"User logged in: {user.email}")

    return jsonify({
        "access_token": access_token,
        "refresh_token": refresh_token,
        "user": {"id": user.id, "email": user.email}
    }), 200


# ─── Refresh Token ───────────────────────────────────────────────────────────

@auth_bp.route("/refresh", methods=["POST"])
def refresh():
    data = request.get_json()
    token = data.get("refresh_token") if data else None

    if not token:
        return jsonify({"error": "Refresh token required."}), 400

    try:
        payload = decode_token(token)
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Refresh token expired. Please log in again."}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid refresh token."}), 401

    if payload.get("type") != "refresh":
        return jsonify({"error": "Invalid token type."}), 401

    user = _db.session.get(User, payload["user_id"])
    if not user:
        return jsonify({"error": "User not found."}), 401

    access_token = generate_access_token(user.id)
    return jsonify({"access_token": access_token}), 200


# ─── 2FA Setup ───────────────────────────────────────────────────────────────

@auth_bp.route("/2fa/setup", methods=["POST"])
@jwt_required
def setup_2fa():
    user = g.current_user

    if user.totp_enabled:
        return jsonify({"error": "2FA is already enabled."}), 400

    # Generate a new TOTP secret
    secret = generate_totp_secret()
    uri = get_totp_uri(secret, user.email)

    # Save secret temporarily — user must verify before we enable
    user.totp_secret = secret
    db.session.commit()

    return jsonify({
        "secret": secret,
        "uri": uri,
        "message": "Scan the QR code with Google Authenticator, then call /2fa/verify"
    }), 200


@auth_bp.route("/2fa/verify", methods=["POST"])
@jwt_required
def verify_2fa():
    user = g.current_user
    data = request.get_json()
    code = data.get("code") if data else None

    if not code:
        return jsonify({"error": "TOTP code required."}), 400

    if not user.totp_secret:
        return jsonify({"error": "2FA setup not initiated. Call /2fa/setup first."}), 400

    if not verify_totp(user.totp_secret, code):
        return jsonify({"error": "Invalid code. Try again."}), 400

    user.totp_enabled = True
    db.session.commit()

    log_action(user.id, "2FA_ENABLED", "User enabled 2FA")
    return jsonify({"message": "2FA enabled successfully."}), 200

@auth_bp.route("/", methods=["GET"])
def index():
    return render_template("login.html")