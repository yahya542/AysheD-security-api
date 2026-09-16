import time
import psutil
import re
from datetime import datetime
from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from contextlib import asynccontextmanager
from apiSEC.config import settings
from apiSEC.database import init_db, get_db, User, UserRole
from apiSEC.auth import hash_password, verify_password, create_access_token
from apiSEC.schemas import (
    RegisterRequest, RegisterResponse,
    LoginRequest, LoginResponse,
    HealthResponse, ThreatLogsResponse, ThreatLogEntry,
    SuspendUserRequest, SuspendUserResponse, UserResponse
)
from apiSEC.dependencies import get_current_user, get_current_admin

start_time = time.time()

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

bearer_scheme = {
    "type": "http",
    "scheme": "bearer",
    "bearerFormat": "JWT",
    "description": "Enter JWT token from /api/v1/auth/login",
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

@app.post("/api/v1/auth/register", response_model=RegisterResponse, status_code=status.HTTP_201_CREATED, tags=["Authentication"])
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

@app.post("/api/v1/auth/login", response_model=LoginResponse, tags=["Authentication"])
async def login(payload: LoginRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.email == payload.email))
    user = result.scalar_one_or_none()
    
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account suspended",
        )
    
    access_token = create_access_token(
        data={"sub": str(user.id), "role": user.role.value}
    )
    
    return LoginResponse(access_token=access_token, token_type="bearer")

@app.get("/api/v1/admin/health", response_model=HealthResponse, tags=["Admin"])
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

@app.get("/api/v1/admin/threat-logs", response_model=ThreatLogsResponse, tags=["Admin"])
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

@app.post("/api/v1/admin/suspend-user", response_model=SuspendUserResponse, tags=["Admin"])
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

@app.get("/api/v1/auth/me", response_model=UserResponse, tags=["Authentication"])
async def get_me(current_user: User = Depends(get_current_user)):
    return current_user

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=settings.host, port=settings.port)