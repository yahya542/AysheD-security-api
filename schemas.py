from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List
from datetime import datetime
import uuid
from apiSEC.database import UserRole

class RegisterRequest(BaseModel):
    email: EmailStr = Field(description="User email address")
    password: str = Field(min_length=8, max_length=128, description="Password (min 8 characters)")

    class Config:
        json_schema_extra = {
            "example": {
                "email": "user@example.com",
                "password": "securepassword123"
            }
        }

class RegisterResponse(BaseModel):
    message: str = "Registration successful"

    class Config:
        json_schema_extra = {
            "example": {
                "message": "Registration successful"
            }
        }

class LoginRequest(BaseModel):
    email: EmailStr = Field(description="Registered email address")
    password: str = Field(description="User password")

    class Config:
        json_schema_extra = {
            "example": {
                "email": "user@example.com",
                "password": "securepassword123"
            }
        }

class LoginResponse(BaseModel):
    access_token: str = Field(description="JWT access token")
    token_type: str = Field(default="bearer", description="Token type")

    class Config:
        json_schema_extra = {
            "example": {
                "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "token_type": "bearer"
            }
        }
class LogoutResponse(BaseModel):
    message: str = "Logged out successfully"

    class Config:
        json_schema_extra = {
            "example": {
                "message": "Logged out successfully"
            }
        }

class LogoutRequest(BaseModel):
    token: str = Field(description="JWT access token to invalidate")

    class Config:
        json_schema_extra = {
            "example": {
                "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
            }
        }   
        
class TokenData(BaseModel):
    sub: str
    role: UserRole
    exp: Optional[int] = None

class UserResponse(BaseModel):
    id: uuid.UUID = Field(description="Unique user identifier")
    email: str = Field(description="User email address")
    role: UserRole = Field(description="User role: user or admin")
    is_active: bool = Field(description="Account status")
    created_at: datetime = Field(description="Account creation timestamp")

    class Config:
        from_attributes = True
        json_schema_extra = {
            "example": {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "email": "user@example.com",
                "role": "user",
                "is_active": True,
                "created_at": "2026-09-16T09:00:00"
            }
        }

class HealthResponse(BaseModel):
    status: str = Field(description="Server health status")
    uptime_seconds: float = Field(description="Server uptime in seconds")
    cpu_percent: float = Field(description="CPU usage percentage")
    memory_percent: float = Field(description="Memory usage percentage")
    memory_available_mb: float = Field(description="Available memory in MB")

    class Config:
        json_schema_extra = {
            "example": {
                "status": "healthy",
                "uptime_seconds": 3600.0,
                "cpu_percent": 25.5,
                "memory_percent": 60.2,
                "memory_available_mb": 4096.0
            }
        }

class ThreatLogEntry(BaseModel):
    ip: str = Field(description="Banned IP address")
    jail: str = Field(description="Fail2ban jail name")
    timestamp: str = Field(description="Ban timestamp")
    failures: int = Field(description="Number of failed attempts")

    class Config:
        json_schema_extra = {
            "example": {
                "ip": "192.168.1.100",
                "jail": "sshd",
                "timestamp": "2026-09-16 09:00:00,123",
                "failures": 5
            }
        }

class ThreatLogsResponse(BaseModel):
    threats: List[ThreatLogEntry] = Field(description="List of threat log entries")
    total: int = Field(description="Total number of threats")

    class Config:
        json_schema_extra = {
            "example": {
                "threats": [],
                "total": 0
            }
        }

class SuspendUserRequest(BaseModel):
    user_id: uuid.UUID = Field(description="UUID of user to suspend")

    class Config:
        json_schema_extra = {
            "example": {
                "user_id": "550e8400-e29b-41d4-a716-446655440000"
            }
        }

class SuspendUserResponse(BaseModel):
    message: str = Field(description="Operation result message")
    user_id: uuid.UUID = Field(description="Suspended user ID")

    class Config:
        json_schema_extra = {
            "example": {
                "message": "User user@example.com suspended",
                "user_id": "550e8400-e29b-41d4-a716-446655440000"
            }
        }


class LoginLogResponse(BaseModel):
    id: int
    email: str
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    success: bool
    failure_reason: Optional[str] = None
    timestamp: datetime
    
    class Config:
        from_attributes = True