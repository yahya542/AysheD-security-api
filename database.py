from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import event, inspect, Column, String, Boolean, DateTime, Enum as SQLEnum, Integer, ForeignKey, select, delete
from sqlalchemy.dialects.postgresql import UUID as PGUUID
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional
import enum
from apiSEC.config import settings

class Base(DeclarativeBase):
    pass

class UserRole(str, enum.Enum):
    user = "user"
    admin = "admin"

class LoginFailureReason(str, enum.Enum):
    bad_password = "bad_password"
    unknown_user = "unknown_user"
    locked = "locked"
    admin_suspended = "admin_suspended"

def _uuid_type():
    if settings.database_url.startswith("sqlite"):
        return String(36)
    return PGUUID(as_uuid=True)

class User(Base):
    __tablename__ = "users"
    
    id = Column(_uuid_type(), primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String(255), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(SQLEnum(UserRole), default=UserRole.user, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

class LoginLog(Base):
    __tablename__ = "login_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(_uuid_type(), ForeignKey("users.id"), nullable=True, index=True)
    email = Column(String(255), nullable=True, index=True)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(500), nullable=True)
    device_id = Column(String(255), nullable=True, index=True)
    request_id = Column(String(255), nullable=True, index=True)
    success = Column(Boolean, nullable=False)
    failure_reason = Column(SQLEnum(LoginFailureReason), nullable=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

class AccountLock(Base):
    __tablename__ = "account_locks"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(_uuid_type(), ForeignKey("users.id"), nullable=True, index=True)
    failed_attempts = Column(Integer, default=0, nullable=False)
    locked_until = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

engine = create_async_engine(settings.database_url, echo=False, pool_pre_ping=True)

if settings.database_url.startswith("sqlite"):
    @event.listens_for(engine.sync_engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL;")
        cursor.execute("PRAGMA busy_timeout=5000;")
        cursor.execute("PRAGMA synchronous=NORMAL;")
        cursor.close()

AsyncSessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

async def get_db():
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()

async def init_db():
    async with engine.begin() as conn:
        if settings.database_url.startswith("sqlite"):
            await conn.exec_driver_sql("PRAGMA journal_mode=WAL;")
            await conn.exec_driver_sql("PRAGMA busy_timeout=5000;")
            await conn.exec_driver_sql("PRAGMA synchronous=NORMAL;")
        await conn.run_sync(Base.metadata.create_all)
        await conn.run_sync(_auto_migrate)


def _auto_migrate(conn):
    """Auto-migrate: tambahkan kolom yang mungkin ada di model tapi belum di DB."""
    # --- login_logs ---
    cols = {c["name"] for c in inspect(conn).get_columns("login_logs")}
    if "user_id" not in cols:
        conn.exec_driver_sql("ALTER TABLE login_logs ADD COLUMN user_id VARCHAR(36)")
    if "device_id" not in cols:
        conn.exec_driver_sql("ALTER TABLE login_logs ADD COLUMN device_id VARCHAR(255)")
    if "request_id" not in cols:
        conn.exec_driver_sql("ALTER TABLE login_logs ADD COLUMN request_id VARCHAR(255)")

    # --- account_locks ---
    cols = {c["name"] for c in inspect(conn).get_columns("account_locks")}
    if "user_id" not in cols:
        conn.exec_driver_sql("ALTER TABLE account_locks ADD COLUMN user_id VARCHAR(36)")

    # --- Data Cleanup (Sanitize legacy enum values) ---
    conn.exec_driver_sql(
        "UPDATE login_logs SET failure_reason = 'bad_password' "
        "WHERE failure_reason NOT IN ('bad_password', 'unknown_user', 'locked', 'admin_suspended') "
        "AND failure_reason IS NOT NULL"
    )

    # --- Sync user_id for legacy data (based on email) ---
    conn.exec_driver_sql(
        "UPDATE login_logs SET user_id = (SELECT id FROM users WHERE users.email = login_logs.email) "
        "WHERE user_id IS NULL AND email IS NOT NULL"
    )

async def get_active_account_lock(db: AsyncSession, user_id: str) -> Optional[AccountLock]:
    """Return an active (non-expired) account lock for the given user ID, or None."""
    now = datetime.now(timezone.utc)
    result = await db.execute(
        select(AccountLock)
        .where(AccountLock.user_id == user_id)
        .where(AccountLock.locked_until.isnot(None))
        .where(AccountLock.locked_until > now)
        .order_by(AccountLock.id.desc())
        .limit(1)
    )
    return result.scalar_one_or_none()

async def record_failed_attempt(db: AsyncSession, user_id: str) -> Optional[AccountLock]:
    """Record a failed login attempt.
    
    If the threshold (settings.max_login_attempts) is reached, locks the account
    for settings.lockout_duration_minutes and returns the AccountLock.
    Otherwise returns None.
    """
    now = datetime.now(timezone.utc)
    result = await db.execute(
        select(AccountLock)
        .where(AccountLock.user_id == user_id)
        .order_by(AccountLock.id.desc())
        .limit(1)
    )
    lock = result.scalar_one_or_none()
    
    if lock and lock.locked_until and lock.locked_until > now:
        # Currently locked - increment attempts
        lock.failed_attempts += 1
    elif lock and lock.locked_until and lock.locked_until <= now:
        # Previous lock expired - reset counter
        lock.failed_attempts = 1
        lock.locked_until = None
    else:
        # No active lock - create or increment
        if lock:
            lock.failed_attempts = (lock.failed_attempts or 0) + 1
        else:
            lock = AccountLock(
                user_id=user_id,
                failed_attempts=1,
                locked_until=None
            )
            db.add(lock)
    
    db.add(lock)
    await db.commit()
    await db.refresh(lock)
    
    if lock.failed_attempts >= settings.max_login_attempts:
        lock.locked_until = now + timedelta(minutes=settings.lockout_duration_minutes)
        db.add(lock)
        await db.commit()
        await db.refresh(lock)
        return lock
    
    return None

async def clear_account_lock(db: AsyncSession, user_id: str):
    """Clear all account locks for the given user ID (on successful login)."""
    await db.execute(
        delete(AccountLock).where(AccountLock.user_id == user_id)
    )
    await db.commit()

async def count_recent_failures(db, user_id: str, window_minutes: int) -> int:
    """Hitung jumlah kegagalan login dalam window_minutes terakhir."""
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
    result = await db.execute(
        select(LoginLog)
        .where(LoginLog.user_id == user_id)
        .where(LoginLog.success == False)
        .where(LoginLog.timestamp >= cutoff)
        .order_by(LoginLog.timestamp.desc())
    )
    return len(result.scalars().all())

async def get_last_failure_time(db, user_id: str):
    """Ambil timestamp kegagalan terakhir, atau None."""
    result = await db.execute(
        select(LoginLog.timestamp)
        .where(LoginLog.user_id == user_id)
        .where(LoginLog.success == False)
        .order_by(LoginLog.timestamp.desc())
        .limit(1)
    )
    return result.scalar_one_or_none()