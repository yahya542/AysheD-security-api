import time
import psutil
import re
import asyncio
import sys
from datetime import datetime, timezone
from fastapi import FastAPI, Depends, HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from contextlib import asynccontextmanager
from apiSEC.config import settings
from zoneinfo import ZoneInfo

from apiSEC.database import (
    init_db, get_db, User, UserRole, LoginLog,
    LoginFailureReason, AccountLock,
    get_active_account_lock, record_failed_attempt, clear_account_lock,
    count_recent_failures, get_last_failure_time,
)

from apiSEC.auth import (
    hash_password, verify_password, create_access_token, DUMMY_HASH,
    calibrate_bcrypt_time, get_bcrypt_time,
)
from apiSEC.schemas import (
    RegisterRequest, RegisterResponse,
    LoginRequest, LoginResponse,
    HealthResponse, ThreatLogsResponse, ThreatLogEntry,
    SuspendUserRequest, SuspendUserResponse, UserResponse,
    LoginLogResponse,
    LogoutRequest, LogoutResponse,
    UFWLogsResponse, UFWLogEntry
)
from apiSEC.dependencies import get_current_user, get_current_admin
from fastapi import APIRouter


ufw_pattern = re.compile(
    r'(\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2}).*?\[UFW\s+(BLOCK|ALLOW)\].*?SRC=(\d+\.\d+\.\d+\.\d+).*?IN=(\w+)'
)


def get_utc_time():
    return datetime.now(timezone.utc)

start_time = time.time()

@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    calibrate_bcrypt_time()
    yield

app = FastAPI(
    title="AysheD Security Gateway",
    version="1.0.0",
    description="Identity Provider & API Gateway for AysheD",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    openapi_tags=[
        {"name": "Authentication", "description": "User registration and login endpoints"},
        {"name": "Admin", "description": "Admin-only endpoints for monitoring and management"},
    ],
)

auth_router = APIRouter(prefix="/auth", tags=["Authentication"])
admin_router = APIRouter(prefix="/admin", tags=["Admin"])

bearer_scheme = {
    "type": "http",
    "scheme": "bearer",
    "bearerFormat": "JWT",
    "description": "Enter JWT token from auth/login",
}

app.openapi_extra = {
    "components": {
        "securitySchemes": {
            "BearerAuth": bearer_scheme
        }
    },
    "security": [{"BearerAuth": []}]
}

@app.get("/")
def read_root():
    return {"message": "Welcome to AysheD Security Gateway (apiSEC)", "version": "1.0.0"}


@auth_router.post("/register", response_model=RegisterResponse, status_code=status.HTTP_201_CREATED)
async def register(payload: RegisterRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.email == payload.email))
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered"
        )
    
    user = User(
        email=payload.email,
        password_hash=hash_password(payload.password),
        role=UserRole.user,
    )
    db.add(user)
    await db.commit()
    
    return RegisterResponse(message="Registration successful")


def calculate_delay(failure_count: int) -> int:
    if failure_count <= 0:
        return 0
    delay = settings.BASE_DELAY_SECONDS * (2 ** (failure_count - 1))
    return min(delay, settings.MAX_DELAY_SECONDS)


async def verify_password_async(plain_password: str, hashed_password: str) -> bool:
    return await asyncio.to_thread(verify_password, plain_password, hashed_password)


@auth_router.post("/login", response_model=LoginResponse)
async def login(payload: LoginRequest, db: AsyncSession = Depends(get_db), request: Request = None):
    ip = request.client.host if request and request.client else None
    ua = request.headers.get('user-agent') if request else None

    result = await db.execute(select(User).where(User.email == payload.email))
    user = result.scalar_one_or_none()

    # 2. Cek FULL LOCK (account_locks)
    active_lock = await get_active_account_lock(db, str(user.id) if user else None)
    if active_lock:
        login_log = LoginLog(
            user_id=str(user.id) if user else None,
            email=payload.email,
            ip_address=ip,
            user_agent=ua,
            success=False,
            device_id=request.headers.get('x-device-id') if request else None,
            request_id=request.headers.get('x-request-id') if request else None,
            failure_reason=LoginFailureReason.locked,
            timestamp=get_utc_time()
        )
        db.add(login_log)
        try:
            await db.commit()
        except Exception as e:
            await db.rollback()
            print(f"[SYSTEM-WARN] Failed to write locked log to DB: {e}", file=sys.stderr)

        await asyncio.sleep(get_bcrypt_time())
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 3. Cek DELAY PROGRESIF (rate_limited)
    if user:
        failure_count = await count_recent_failures(db, str(user.id), settings.THRESHOLD_WINDOW_MINUTES)
        required_delay = calculate_delay(failure_count)
        if required_delay > 0:
            last_failure = await get_last_failure_time(db, str(user.id))
            if last_failure:
                if last_failure.tzinfo is None:
                    last_failure = last_failure.replace(tzinfo=timezone.utc)
                elapsed = (get_utc_time() - last_failure).total_seconds()
                if elapsed < required_delay:
                    login_log = LoginLog(
                        user_id=str(user.id),
                        email=payload.email,
                        ip_address=ip,
                        user_agent=ua,
                        success=False,
                        device_id=request.headers.get('x-device-id') if request else None,
                        request_id=request.headers.get('x-request-id') if request else None,
                        failure_reason=LoginFailureReason.rate_limited,
                        timestamp=get_utc_time()
                    )
                    db.add(login_log)
                    try:
                        await db.commit()
                    except Exception as e:
                        await db.rollback()
                        print(f"[SYSTEM-WARN] Failed to write rate_limited log to DB: {e}", file=sys.stderr)

                    await asyncio.sleep(get_bcrypt_time())
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Invalid credentials",
                        headers={"WWW-Authenticate": "Bearer"},
                    )

    # 4. Verifikasi password (timing-safe jika user tidak ada)
    stored_hash = user.password_hash if user else DUMMY_HASH
    password_valid = await verify_password_async(payload.password, stored_hash)

    failure_reason = None
    if user and not user.is_active:
        failure_reason = LoginFailureReason.admin_suspended
    elif not user:
        failure_reason = LoginFailureReason.unknown_user
    elif not password_valid:
        failure_reason = LoginFailureReason.bad_password

    if failure_reason is not None:
        login_log = LoginLog(
            user_id=str(user.id) if user else None,
            email=payload.email,
            ip_address=ip,
            user_agent=ua,
            success=False,
            device_id=request.headers.get('x-device-id') if request else None,
            request_id=request.headers.get('x-request-id') if request else None,
            failure_reason=failure_reason,
            timestamp=get_utc_time()
        )
        db.add(login_log)
        try:
            await db.commit()
        except Exception as e:
            await db.rollback()
            print(f"[SYSTEM-WARN] Failed to write failed login_log to DB: {e}", file=sys.stderr)

        if user:
            try:
                await record_failed_attempt(db, str(user.id))
            except Exception as e:
                await db.rollback()
                print(f"[SYSTEM-WARN] Failed to record_failed_attempt: {e}", file=sys.stderr)

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if user:
        try:
            await clear_account_lock(db, str(user.id))
        except Exception as e:
            await db.rollback()
            print(f"[SYSTEM-WARN] Failed to clear account lock: {e}", file=sys.stderr)

    login_log = LoginLog(
        user_id=str(user.id) if user else None,
        email=payload.email,
        ip_address=ip,
        user_agent=ua,
        success=True,
        device_id=request.headers.get('x-device-id') if request else None,
        request_id=request.headers.get('x-request-id') if request else None,
        timestamp=get_utc_time()
    )
    db.add(login_log)
    try:
        await db.commit()
    except Exception as e:
        await db.rollback()
        print(f"[SYSTEM-WARN] Failed to write success login_log to DB: {e}", file=sys.stderr)

    access_token = create_access_token(
        data={"sub": str(user.id), "role": user.role.value}
    )

    return LoginResponse(access_token=access_token, token_type="bearer")


@auth_router.get("/me", response_model=UserResponse)
async def get_me(current_user: User = Depends(get_current_user)):
    return current_user

@auth_router.get("/users", response_model=list[UserResponse])
async def get_users(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    result = await db.execute(select(User))
    users = result.scalars().all()
    return users

@auth_router.post("/logout", response_model=LogoutResponse)
async def logout(current_user: User = Depends(get_current_user)):
    return LogoutResponse(message="Logged out successfully")


@admin_router.get("/logs", response_model=list[LoginLogResponse], tags=["Admin"])
async def get_login_logs(
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin)
):
    result = await db.execute(
        select(LoginLog)
        .order_by(LoginLog.timestamp.desc())
        .limit(limit)
    )
    logs = result.scalars().all()
    return logs


@admin_router.get("/health", response_model=HealthResponse)
async def health_check(current_user: User = Depends(get_current_admin)):
    uptime = time.time() - start_time
    cpu = psutil.cpu_percent(interval=0.1)
    mem = psutil.virtual_memory()
    
    return HealthResponse(
        status="healthy",
        uptime_seconds=uptime,
        cpu_percent=cpu,
        memory_percent=mem.percent,
        memory_available_mb=mem.available / (1024 * 1024)
    )

@admin_router.get("/threat-logs", response_model=ThreatLogsResponse)
async def get_threat_logs(current_user: User = Depends(get_current_admin)):
    log_path = settings.fail2ban_log_path
    threats = []
    
    try:
        with open(log_path, "r") as f:
            lines = f.readlines()
        
        ban_pattern = re.compile(
            r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) .*Ban (\d+\.\d+\.\d+\.\d+) .*\[(\w+)\]'
        )
        
        for line in reversed(lines[-1000:]):
            match = ban_pattern.search(line)
            if match:
                timestamp, ip, jail = match.groups()
                threats.append(ThreatLogEntry(
                    ip=ip,
                    jail=jail,
                    timestamp=timestamp,
                    failures=0
                ))
                if len(threats) >= 50:
                    break
    
    except FileNotFoundError:
        pass
    except PermissionError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Cannot read fail2ban log (permission denied)"
        )
    
    return ThreatLogsResponse(threats=threats, total=len(threats))

@admin_router.get("/ufw-logs", response_model=UFWLogsResponse)
async def get_ufw_logs(current_user: User = Depends(get_current_admin)):
    log_path = settings.ufw_log_path
    logs = []

    try:
        with open(log_path, "r") as f:
            lines = f.readlines()

        for line in reversed(lines[-1000:]):
            match = ufw_pattern.search(line)
            if match:
                timestamp, action, ip, interface = match.groups()
                logs.append(UFWLogEntry(
                    timestamp=timestamp,
                    ip=ip,
                    action=action,
                    interface=interface
                ))
                if len(logs) >= 50:
                    break

    except FileNotFoundError:
        pass
    except PermissionError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Cannot read UFW log (permission denied)"
        )

    return UFWLogsResponse(logs=logs, total=len(logs))


@admin_router.post("/suspend-user", response_model=SuspendUserResponse)
async def suspend_user(
    payload: SuspendUserRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin)
):
    result = await db.execute(select(User).where(User.id == str(payload.user_id)))
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    if user.id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot suspend yourself"
        )
    
    user.is_active = False
    await db.commit()
    
    return SuspendUserResponse(
        message=f"User {user.email} suspended",
        user_id=user.id
    )


app.include_router(auth_router)
app.include_router(admin_router)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=settings.host, port=settings.port)
