from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Database extension — handles all DB connections and queries
db = SQLAlchemy()

# Migration extension — tracks database schema changes (like Git, but for DB tables)
migrate = Migrate()

# Rate limiter — limits how many requests an IP can make per minute
# get_remote_address = identifies users by their IP address
limiter = Limiter(key_func=get_remote_address)