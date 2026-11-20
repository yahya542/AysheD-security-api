"""Tests untuk RBAC dan Permission system."""
from fastapi.testclient import TestClient
from apiSEC.main import app
from apiSEC.database import seed_default_permissions, AsyncSessionLocal, Permission, RolePermission, UserRole
from apiSEC.dependencies import get_user_permissions, has_permission
import asyncio


class TestRBAC:
    @classmethod
    def setup_class(cls):
        cls.client = TestClient(app)

    def test_seed_default_permissions(self):
        async def _run():
            async with AsyncSessionLocal() as db:
                await seed_default_permissions(db)
                result = await db.execute(__import__("sqlalchemy").select(Permission))
                perms = result.scalars().all()
                assert len(perms) >= 8
                names = [p.name for p in perms]
                assert "user:read" in names
                assert "user:delete" in names
                assert "role:manage" in names

        asyncio.get_event_loop().run_until_complete(_run())

    def test_role_permission_mapping(self):
        async def _run():
            async with AsyncSessionLocal() as db:
                await seed_default_permissions(db)
                from sqlalchemy import select
                # superadmin should have all permissions
                rp = await db.execute(
                    select(RolePermission).where(RolePermission.role == UserRole.superadmin)
                )
                super_perms = rp.scalars().all()
                assert len(super_perms) >= 8

                # user should have only user:read
                rp = await db.execute(
                    select(RolePermission).where(RolePermission.role == UserRole.user)
                )
                user_perms = rp.scalars().all()
                assert len(user_perms) == 1

        asyncio.get_event_loop().run_until_complete(_run())

    def test_get_user_permissions_for_superadmin(self):
        async def _run():
            async with AsyncSessionLocal() as db:
                await seed_default_permissions(db)
                from apiSEC.database import User
                from sqlalchemy import select
                result = await db.execute(select(User).where(User.email == "superadmin@ayshed.biz.id"))
                user = result.scalar_one_or_none()
                assert user is not None
                perms = await get_user_permissions(db, user)
                assert "role:manage" in perms
                assert "user:delete" in perms
                assert "user:read" in perms

        asyncio.get_event_loop().run_until_complete(_run())

    def test_has_permission_check(self):
        async def _run():
            async with AsyncSessionLocal() as db:
                await seed_default_permissions(db)
                from apiSEC.database import User
                from sqlalchemy import select
                result = await db.execute(select(User).where(User.email == "superadmin@ayshed.biz.id"))
                user = result.scalar_one_or_none()
                assert user is not None
                assert await has_permission(db, user, "role:manage") is True
                assert await has_permission(db, user, "nonexistent:perm") is False

        asyncio.get_event_loop().run_until_complete(_run())

    def test_user_role_has_limited_permissions(self):
        async def _run():
            async with AsyncSessionLocal() as db:
                await seed_default_permissions(db)
                from apiSEC.database import User
                from sqlalchemy import select
                result = await db.execute(select(User).where(User.email == "testuser@example.com"))
                user = result.scalar_one_or_none()
                if user:
                    perms = await get_user_permissions(db, user)
                    assert "user:read" in perms
                    assert "role:manage" not in perms
                    assert "user:delete" not in perms

        asyncio.get_event_loop().run_until_complete(_run())
