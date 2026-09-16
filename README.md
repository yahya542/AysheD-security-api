# apiSEC - AysheD Security Gateway

Identity Provider & API Gateway for AysheD ecosystem.

## Features

- **Authentication**: JWT-based auth with RS256/HS256 signing
- **User Management**: Register, login, role-based access (user/admin)
- **Admin Dashboard**: Health monitoring, threat logs, user suspension
- **Security**: Bcrypt password hashing, rate limiting ready
- **Database**: PostgreSQL with async SQLAlchemy

## Setup

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Copy and configure environment
cp .env.example .env
# Edit .env with your settings

# Run database migrations (create tables)
python -c "import asyncio; from apiSEC.database import init_db; asyncio.run(init_db())"

# Start server
uvicorn apiSEC.main:app --host 0.0.0.0 --port 8001 --reload
```

## API Endpoints

### Public Auth
- `POST /api/v1/auth/register` - Register new user
- `POST /api/v1/auth/login` - Login, returns JWT

### Protected (JWT required)
- `GET /api/v1/auth/me` - Get current user profile

### Admin Only (role: admin)
- `GET /api/v1/admin/health` - Server health (CPU, RAM, uptime)
- `GET /api/v1/admin/threat-logs` - Fail2ban threat logs
- `POST /api/v1/admin/suspend-user` - Suspend user account

## Environment Variables

See `.env.example` for all options.

## Database

PostgreSQL table `users`:
- id (UUID, PK)
- email (unique, indexed)
- password_hash (bcrypt)
- role (user/admin)
- is_active (boolean)
- created_at (timestamp)