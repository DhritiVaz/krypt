import jwt
from functools import wraps
from flask import request, jsonify, g
from app.services.auth_service import decode_token
from app.models.user import User


def jwt_required(f):
    """
    Decorator that protects a route — requires a valid JWT access token.

    Usage:
        @vault_bp.route("/")
        @jwt_required
        def list_entries():
            user = g.current_user  # available after this decorator runs
            ...

    The token must be in the Authorization header as:
        Authorization: Bearer <token>
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        # 1. Get the Authorization header
        auth_header = request.headers.get("Authorization")

        if not auth_header:
            return jsonify({"error": "Missing authorization header"}), 401

        # 2. Check it's in the right format: "Bearer <token>"
        parts = auth_header.split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            return jsonify({"error": "Invalid authorization format. Use: Bearer <token>"}), 401

        token = parts[1]

        # 3. Decode and validate the token
        try:
            payload = decode_token(token)
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token has expired. Please log in again."}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token."}), 401

        # 4. Make sure it's an access token, not a refresh token
        if payload.get("type") != "access":
            return jsonify({"error": "Invalid token type."}), 401

        # 5. Load the user from the database
        user = User.query.get(payload["user_id"])
        if not user:
            return jsonify({"error": "User not found."}), 401

        # 6. Store user on Flask's g object — available in the route handler
        g.current_user = user

        return f(*args, **kwargs)

    return decorated