from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import Optional
from apiSEC.database import get_db, User, UserRole, Permission, RolePermission, UserPermission
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional, List

# ... existing code ...

async def get_user_permissions(db: AsyncSession, user: User) -> List[str]:
    """Return list of permission names for a user (role-based + per-user overrides)."""
    # Role-based permissions
    rp_result = await db.execute(
        select(Permission.name)
        .join(RolePermission, RolePermission.permission_id == Permission.id)
        .where(RolePermission.role == user.role)
    )
    role_perms = {row[0] for row in rp_result.all()}

    # Per-user overrides
    up_result = await db.execute(
        select(Permission.name, UserPermission.granted)
        .join(UserPermission, UserPermission.permission_id == Permission.id)
        .where(UserPermission.user_id == str(user.id))
    )
    for name, granted in up_result.all():
        if granted:
            role_perms.add(name)
        else:
            role_perms.discard(name)

    return sorted(role_perms)

async def has_permission(db: AsyncSession, user: User, permission_name: str) -> bool:
    """Check if user has a specific permission."""
    perms = await get_user_permissions(db, user)
    return permission_name in perms
from apiSEC.auth import decode_access_token
from apiSEC.schemas import TokenData

security = HTTPBearer(auto_error=False)

async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: AsyncSession = Depends(get_db)
) -> User:
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    payload = decode_access_token(credentials.credentials)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account suspended",
        )
    
    return user

async def get_current_admin(
    current_user: User = Depends(get_current_user)
) -> User:
    if current_user.role not in (UserRole.admin, UserRole.superadmin):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    return current_user

async def get_current_superadmin(
    current_user: User = Depends(get_current_user)
) -> User:
    if current_user.role != UserRole.superadmin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Superadmin access required",
        )
    return current_user