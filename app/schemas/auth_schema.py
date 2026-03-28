import re
from marshmallow import Schema, fields, validate, validates, ValidationError


class RegisterSchema(Schema):
    """Validates registration input."""

    email = fields.Email(required=True)

    password = fields.String(required=True)

    @validates("password")
    def validate_password(self, value, **kwargs):
        """
        Enforces password strength rules:
        - Minimum 12 characters
        - At least one uppercase letter
        - At least one lowercase letter
        - At least one digit
        - At least one special character
        """
        if len(value) < 12:
            raise ValidationError("Password must be at least 12 characters.")

        if not re.search(r"[A-Z]", value):
            raise ValidationError("Password must contain at least one uppercase letter.")

        if not re.search(r"[a-z]", value):
            raise ValidationError("Password must contain at least one lowercase letter.")

        if not re.search(r"\d", value):
            raise ValidationError("Password must contain at least one digit.")

        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", value):
            raise ValidationError("Password must contain at least one special character.")


class LoginSchema(Schema):
    """Validates login input."""

    email = fields.Email(required=True)
    password = fields.String(required=True)

    # Optional — only required if user has 2FA enabled
    totp_code = fields.String(
        required=False,
        validate=validate.Length(equal=6),
        load_default=None
    )