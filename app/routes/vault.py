from flask import Blueprint

# Create the vault blueprint
vault_bp = Blueprint("vault", __name__)


@vault_bp.route("/", methods=["GET"])
def list_entries():
    # Placeholder — full logic coming soon
    return {"message": "vault list endpoint"}, 200


@vault_bp.route("/", methods=["POST"])
def create_entry():
    # Placeholder — full logic coming soon
    return {"message": "vault create endpoint"}, 200