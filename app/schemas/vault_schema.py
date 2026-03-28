from marshmallow import Schema, fields, validate


class VaultEntryCreateSchema(Schema):
    """Validates input for creating a new vault entry."""

    website = fields.String(
        required=True,
        validate=validate.Length(min=1, max=255)
    )
    username = fields.String(
        required=True,
        validate=validate.Length(min=1, max=255)
    )
    password = fields.String(
        required=True,
        validate=validate.Length(min=1, max=512)
    )
    notes = fields.String(
        required=False,
        validate=validate.Length(max=2000),
        load_default=None
    )


class VaultEntryUpdateSchema(Schema):
    """Validates input for updating a vault entry — all fields optional."""

    website = fields.String(
        required=False,
        validate=validate.Length(min=1, max=255)
    )
    username = fields.String(
        required=False,
        validate=validate.Length(min=1, max=255)
    )
    password = fields.String(
        required=False,
        validate=validate.Length(min=1, max=512)
    )
    notes = fields.String(
        required=False,
        validate=validate.Length(max=2000),
        load_default=None
    )