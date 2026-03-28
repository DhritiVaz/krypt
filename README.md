# Krypt — Secure Password Manager

A self-hosted password manager built with security engineering best practices.
AES-256-GCM encryption, Argon2id key derivation, JWT authentication, and TOTP two-factor authentication.

---

## Features

- **AES-256-GCM encryption** — every password encrypted at rest with a unique IV per entry
- **Zero-knowledge design** — encryption key derived from master password at runtime, never stored
- **Argon2id key derivation** — deliberately slow, memory-intensive hashing resistant to brute-force
- **JWT authentication** — short-lived access tokens (15 min) with refresh token rotation (7 days)
- **TOTP two-factor authentication** — Google Authenticator compatible
- **Rate limiting + account lockout** — brute-force protection via Redis
- **Append-only audit logs** — every login, vault access, and modification recorded
- **Soft delete** — deleted entries recoverable within 30 days
- **Password generator** — cryptographically secure random passwords
- **Dark mode** — persistent theme preference

---

## Security Architecture
```
Master Password
    ├── Path A (auth salt)  → Argon2id → Auth Hash       → stored in DB
    └── Path B (enc salt)   → Argon2id → Encryption Key  → never stored
                                               ↓
                                         AES-256-GCM + unique IV
                                               ↓
                                         Ciphertext → stored in DB
```

The server never stores the encryption key. Even with full database access,
an attacker cannot read stored passwords without the user's master password.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Language | Python 3.11+ |
| Framework | Flask + Flask-RESTful |
| Database | PostgreSQL 15 |
| ORM | SQLAlchemy + Flask-Migrate |
| Encryption | AES-256-GCM (cryptography library) |
| Key Derivation | Argon2id (argon2-cffi) |
| Authentication | JWT (PyJWT) + TOTP (pyotp) |
| Rate Limiting | Flask-Limiter + Redis |
| Validation | Marshmallow |
| Testing | pytest + pytest-cov |
| Containerization | Docker + Docker Compose |

---

## Project Structure
```
krypt/
├── app/
│   ├── models/          # SQLAlchemy models (User, VaultEntry, AuditLog)
│   ├── routes/          # API endpoints (auth, vault)
│   ├── services/        # Business logic (crypto, auth, audit)
│   ├── middleware/       # JWT auth decorator
│   ├── schemas/         # Marshmallow input validation
│   └── templates/       # Jinja2 HTML frontend
├── tests/
│   ├── unit/            # Unit tests
│   ├── integration/     # API endpoint tests
│   └── security/        # Security vulnerability tests
├── migrations/          # Database migration history
├── docker-compose.yml
└── requirements.txt
```

---

## Local Setup

### Prerequisites
- Python 3.11+
- PostgreSQL 15+
- Redis

### Installation

**1. Clone the repository**
```bash
git clone https://github.com/DhritiVaz/krypt.git
cd krypt
```

**2. Create and activate virtual environment**
```bash
python -m venv .venv
.venv\Scripts\Activate.ps1  # Windows
source .venv/bin/activate    # macOS/Linux
```

**3. Install dependencies**
```bash
pip install -r requirements.txt
```

**4. Configure environment**
```bash
cp .env.example .env
# Edit .env with your database credentials and secret key
```

**5. Create the database**
```
Create a PostgreSQL database named 'krypt'
```

**6. Run migrations**
```bash
flask --app run.py db upgrade
```

**7. Start the server**
```bash
python run.py
```

Visit `http://localhost:5000/api/auth/`

### Docker Setup
```bash
docker-compose up --build
```

---

## API Endpoints

### Authentication
| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/auth/register` | Register new user |
| POST | `/api/auth/login` | Login, returns JWT tokens |
| POST | `/api/auth/refresh` | Refresh access token |
| POST | `/api/auth/2fa/setup` | Initiate 2FA setup |
| POST | `/api/auth/2fa/verify` | Verify and enable 2FA |

### Vault
| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/vault/` | List all entries |
| POST | `/api/vault/` | Create new entry |
| GET | `/api/vault/<id>` | Get single entry |
| PUT | `/api/vault/<id>` | Update entry |
| DELETE | `/api/vault/<id>` | Soft delete entry |
| GET | `/api/vault/search?q=` | Search by website |
| GET | `/api/vault/generate-password` | Generate secure password |

### Health
| Method | Endpoint | Description |
|---|---|---|
| GET | `/health` | Server health check |

---

## Security Considerations

- Master password never transmitted after initial login — encryption key derived client-side context
- All vault fields encrypted with independent IVs — identical passwords produce different ciphertext
- JWT tokens expire after 15 minutes — refresh tokens rotated on use
- Failed login attempts tracked per account — lockout after 10 consecutive failures
- All inputs validated and sanitized via Marshmallow schemas
- Audit log is append-only — no API endpoint permits modification or deletion

---

## Testing
```bash
# Run full test suite
pytest

# With coverage report
pytest --cov=app --cov-report=term-missing
```

---

## License

MIT
