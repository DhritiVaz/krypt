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
        _db.create_all()  # create all tables in test DB
        yield app
        _db.drop_all()    # clean up after all tests finish


@pytest.fixture(scope="function")
def db(app):
    """
    Give each test a clean database.
    Wraps each test in a transaction that gets rolled back after.
    """
    with app.app_context():
        connection = _db.engine.connect()
        transaction = connection.begin()

        yield _db

        transaction.rollback()
        connection.close()


@pytest.fixture(scope="function")
def client(app):
    """Flask test client — makes API requests without a real server."""
    return app.test_client()


@pytest.fixture(scope="function")
def test_user(app, db):
    """Creates a real user in the test DB for use in tests."""
    with app.app_context():
        user = User(
            email="testuser@example.com",
            auth_hash=hash_password("TestPassword123!"),
            encryption_salt=generate_encryption_salt()
        )
        db.session.add(user)
        db.session.commit()
        db.session.refresh(user)
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