from flask import Blueprint

# Create the auth blueprint
# "auth" is the name, used internally by Flask
auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/register", methods=["POST"])
def register():
    # Placeholder — full logic coming soon
    return {"message": "register endpoint"}, 200


@auth_bp.route("/login", methods=["POST"])
def login():
    # Placeholder — full logic coming soon
    return {"message": "login endpoint"}, 200