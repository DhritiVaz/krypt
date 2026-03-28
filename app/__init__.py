from flask import Flask
from app.config import config_by_name
from app.extensions import db, migrate, limiter


def create_app(config_name="development"):
    """
    Application factory — builds and returns the Flask app.
    config_name: "development", "testing", or "production"
    """
    app = Flask(__name__)

    # Load the right config class (Development, Testing, or Production)
    app.config.from_object(config_by_name[config_name])

    # Connect extensions to the app
    db.init_app(app)
    migrate.init_app(app, db)
    limiter.init_app(app)

    # Register blueprints (routes) — we'll create these soon
    from app.routes.auth import auth_bp
    from app.routes.vault import vault_bp

    app.register_blueprint(auth_bp, url_prefix="/api/auth")
    app.register_blueprint(vault_bp, url_prefix="/api/vault")

    # Simple health check endpoint — confirms the server is running
    @app.route("/health")
    def health():
        return {"status": "ok", "message": "Krypt is running"}, 200

    return app