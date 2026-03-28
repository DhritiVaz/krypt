import pytest
from app import create_app
from app.extensions import db as _db
from app.models.user import User
from app.services.auth_service import hash_password, generate_access_token
from app.services.crypto_service import generate_encryption_salt


@pytest.fixture(scope="session")
def app():
    """Create a test Flask app — runs once for the entire test session."""
    app = create_app("testing")

    with app.app_context():
        _db.create_all()
        yield app
        _db.drop_all()


@pytest.fixture(scope="function", autouse=True)
def clean_db(app):
    """Wipe all tables before each test — guarantees clean state."""
    with app.app_context():
        yield
        _db.session.remove()
        for table in reversed(_db.metadata.sorted_tables):
            _db.session.execute(table.delete())
        _db.session.commit()


@pytest.fixture(scope="function")
def db(app):
    with app.app_context():
        yield _db


@pytest.fixture(scope="function")
def client(app):
    return app.test_client()


@pytest.fixture(scope="function")
def test_user(app):
    """Creates a real user in the test DB for use in tests."""
    with app.app_context():
        user = User(
            email="testuser@example.com",
            auth_hash=hash_password("TestPassword123!"),
            encryption_salt=generate_encryption_salt()
        )
        _db.session.add(user)
        _db.session.commit()
        _db.session.refresh(user)
        return user


@pytest.fixture(scope="function")
def auth_headers(app, test_user):
    """Returns headers with a valid JWT token for the test user."""
    with app.app_context():
        token = generate_access_token(test_user.id)
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "X-Master-Password": "TestPassword123!"
        }