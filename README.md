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

## Catatan Perubahan (Changelog)

### [2026-11-03]
- **Kalibrasi Bcrypt**: Dipindahkan dari pemanggilan lazy ke fase startup `lifespan()`, dengan dukungan env override `BCRYPT_TIME_SECONDS` dan rata-rata 5 sampel untuk kestabilan event loop.
- **Async Password Verification**: Implementasi `verify_password_async` berbasis `asyncio.to_thread` agar proses hashing bcrypt tidak memblokir async event loop.
- **Alur Login & Timing Safety**:
  - Urutan evaluasi: Cek Full Lock (`account_locks`) -> Cek Delay Progresif (`count_recent_failures`) -> Verifikasi Password (dummy hash fallback untuk email tidak dikenal).
  - Delay progresif menggunakan `asyncio.sleep(get_bcrypt_time())` saat throttled sebelum melempar HTTP 401.
- **Perbaikan Timezone**:
  - Standardisasi timezone-aware UTC (`datetime.now(timezone.utc)`) pada cutoff query `count_recent_failures()` dan timestamp log.
  - Normalisasi naive datetime dari SQLite sebelum pengurangan selisih waktu (`elapsed = (get_utc_time() - last_failure).total_seconds()`) untuk mencegah crash `TypeError` (HTTP 500).
- **Serialisasi WIB**: Penambahan serializer `serialize_timestamp_wib` pada `LoginLogResponse` (`apiSEC/schemas.py`) untuk menampilkan timestamp dalam format zona waktu `Asia/Jakarta` (WIB, `+07:00`).
- **Migrasi Database**: Hapus kolom legacy `email NOT NULL` pada tabel `account_locks` dan sesuaikan foreign key berbasis `user_id`.
- **Konkurensi & Resiliensi SQLite (Langkah 1)**:
  - Mengaktifkan `PRAGMA journal_mode=WAL;` dan `PRAGMA busy_timeout=5000;` pada engine SQLite (`apiSEC/database.py`) untuk mengatasi lock contention (`database is locked`) pada pengujian beban konkurensi tinggi.
  - Memperbaiki penanganan transaksi `db.commit()` pada fungsi `login()` (`apiSEC/main.py`):
    - Jalur gagal: kegagalan commit log ditangkap secara elegan dengan `rollback()`, pesan dicatat ke `stderr`, dan tetap memberikan kesempatan fungsi pencatatan lock (`record_failed_attempt`) untuk berjalan.
    - Jalur sukses: penulisan audit log dan pembersihan lock dibungkus `try/except` dengan `rollback()`, sehingga pengguna sah dengan kredensial valid tidak mengalami HTTP 500 crash jika terjadi kesibukan penulisan database.