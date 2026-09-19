import os
from pathlib import Path
from pydantic_settings import BaseSettings
from pydantic import Field
from typing import Optional

BASE_DIR = Path(__file__).resolve().parent

class Settings(BaseSettings):
    # Database
    database_url: str = Field(
        default=f"sqlite+aiosqlite:///{BASE_DIR / 'ayshed_auth.db'}",
        alias="DATABASE_URL"
    )
    
    # JWT
    secret_key: str = Field(
        default="your-super-secret-key-change-in-production-min-32-chars",
        alias="SECRET_KEY"
    )
    algorithm: str = Field(default="HS256", alias="JWT_ALGORITHM")
    access_token_expire_minutes: int = Field(default=30, alias="ACCESS_TOKEN_EXPIRE_MINUTES")
    
    # Server
    host: str = Field(default="0.0.0.0", alias="HOST")
    port: int = Field(default=8001, alias="PORT")
    
    # Security
    bcrypt_rounds: int = Field(default=12, alias="BCRYPT_ROUNDS")
    
    # Fail2ban log path
    fail2ban_log_path: str = Field(default="/var/log/fail2ban.log", alias="FAIL2BAN_LOG_PATH")

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "ignore"

settings = Settings()