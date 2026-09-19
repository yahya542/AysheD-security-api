import time
import psutil
import re
from datetime import datetime
from fastapi import FastAPI, Depends, HTTPException, status, Request 
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from contextlib import asynccontextmanager
from apiSEC.config import settings
from zoneinfo import ZoneInfo


# 💡 1. Pastikan LoginLog sudah dimasukkan ke dalam daftar import di bawah ini
from apiSEC.database import init_db, get_db, User, UserRole, LoginLog 

from apiSEC.auth import hash_password, verify_password, create_access_token
from apiSEC.schemas import (
    RegisterRequest, RegisterResponse,
    LoginRequest, LoginResponse,
    HealthResponse, ThreatLogsResponse, ThreatLogEntry,
    SuspendUserRequest, SuspendUserResponse, UserResponse,
    LoginLogResponse ,
    LogoutRequest, LogoutResponse
)
from apiSEC.dependencies import get_current_user, get_current_admin
from fastapi import APIRouter


def get_wib_time():
    return datetime.now(ZoneInfo("Asia/Jakarta"))

@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
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

# --- KONFIGURASI ROUTER ---
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


# ==========================================
# 🔑 AUTHENTICATION ROUTER (Prefix: /auth)
# ==========================================

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

@auth_router.post("/login", response_model=LoginResponse)
async def login(payload: LoginRequest, db: AsyncSession = Depends(get_db), request: Request = None):
    result = await db.execute(select(User).where(User.email == payload.email))
    user = result.scalar_one_or_none()
    
    # 💡 Perbaikan Logika Gagal: Catat ke database dulu, baru lempar HTTPException
    if not user or not verify_password(payload.password, user.password_hash):
        login_log = LoginLog(
            email=payload.email,
            ip_address=request.client.host if request and request.client else None,
            user_agent=request.headers.get('user-agent') if request else None,
            success=False,
            failure_reason="Invalid credentials",
            timestamp=get_wib_time()
        )
        db.add(login_log)
        await db.commit()

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if not user.is_active:
        login_log = LoginLog(
            email=payload.email,
            ip_address=request.client.host if request and request.client else None,
            user_agent=request.headers.get('user-agent') if request else None,
            success=False,
            failure_reason="Account suspended",
            timestamp=get_wib_time()
        )
        db.add(login_log)
        await db.commit()

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account suspended",
        )
    
    # 💡 Perbaikan Logika Sukses: Catat log sukses sebelum melakukan 'return'
    login_log = LoginLog(
        email=payload.email,
        ip_address=request.client.host if request and request.client else None,
        user_agent=request.headers.get('user-agent') if request else None,
        success=True,
        timestamp=get_wib_time()
    )
    db.add(login_log)
    await db.commit()

    access_token = create_access_token(
        data={"sub": str(user.id), "role": user.role.value}
    )
    
    return LoginResponse(access_token=access_token, token_type="bearer")

@auth_router.get("/me", response_model=UserResponse)
async def get_me(current_user: User = Depends(get_current_user)):
    return current_user

@auth_router.post("/logout", response_model=LogoutResponse)
async def logout(current_user: User = Depends(get_current_user)):
    # Implement logout logic here (e.g., invalidate token)
    return LogoutResponse(message="Logged out successfully")


# ==========================================
# 🛡️ ADMIN ROUTER (Prefix: /admin)
# ==========================================

# 💡 2. Pindahkan ke admin_router, potong prefix-nya, dan tambahkan dependency 'db'
# 💡 Ganti response_model dari list[LoginResponse] menjadi list[LoginLogResponse]
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

@admin_router.post("/suspend-user", response_model=SuspendUserResponse)
async def suspend_user(
    payload: SuspendUserRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin)
):
    result = await db.execute(select(User).where(User.id == payload.user_id))
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

# --- REGISTER ROUTERS ---
app.include_router(auth_router)
app.include_router(admin_router)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=settings.host, port=settings.port)
