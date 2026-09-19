import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import asyncio
import uuid
from passlib.context import CryptContext
from apiSEC.database import AsyncSessionLocal, User, UserRole, init_db
from sqlalchemy import delete
from datetime import datetime

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=12)

async def main():
    await init_db()
    password_hash = pwd_context.hash("superadmin123")
    
    async with AsyncSessionLocal() as db:
        await db.execute(delete(User))
        admin = User(
            id=str(uuid.uuid4()),
            email="superadmin@ayshed.biz.id",
            password_hash=password_hash,
            role=UserRole.admin,
            is_active=True,
            created_at=datetime.utcnow(),
        )
        db.add(admin)
        await db.commit()
        print(f"Admin created: {admin.email}")

if __name__ == "__main__":
    asyncio.run(main())
