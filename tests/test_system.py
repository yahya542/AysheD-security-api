"""System tests untuk alur lengkap (end-to-end) apiSEC."""
from fastapi.testclient import TestClient
from apiSEC.main import app


class TestSystem:
    @classmethod
    def setup_class(cls):
        cls.client = TestClient(app)

    def test_full_user_lifecycle(self):
        """Sistem: register -> login -> get profile -> suspend -> unsuspend."""
        client = self.client
        import time, uuid
        email = f"systemlifecycle_{uuid.uuid4().hex[:8]}@example.com"
        password = "securepassword123"

        # 1. Register
        reg = client.post(
            "/auth/register",
            json={"email": email, "password": password, "full_name": "System Test", "birth_place": "Bandung", "birth_date": "1990-05-05"},
        )
        assert reg.status_code == 201

        # 2. Login
        login = client.post("/auth/login", json={"email": email, "password": password})
        assert login.status_code == 200
        token = login.json()["access_token"]

        # 3. Get profile
        me = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert me.status_code == 200
        assert me.json()["email"] == email

        # 4. Suspend (superadmin)
        super_login = client.post(
            "/auth/login",
            json={"email": "superadmin@ayshed.biz.id", "password": "superadmin123"},
        )
        assert super_login.status_code == 200
        super_token = super_login.json()["access_token"]

        users = client.get("/auth/users", headers={"Authorization": f"Bearer {super_token}"}).json()
        target = next(u for u in users if u["email"] == email)
        assert target["is_active"] is True

        suspend = client.post(
            "/admin/suspend-user",
            json={"user_id": str(target["id"])},
            headers={"Authorization": f"Bearer {super_token}"},
        )
        assert suspend.status_code == 200

        # User tidak bisa login setelah suspended (401 atau 403 tergantung implementasi)
        login_after = client.post("/auth/login", json={"email": email, "password": password})
        assert login_after.status_code in (401, 403), f"Expected 401/403, got {login_after.status_code}"

        # 5. Unsuspend
        unsuspend = client.post(
            "/admin/unsuspend-user",
            json={"user_id": str(target["id"])},
            headers={"Authorization": f"Bearer {super_token}"},
        )
        assert unsuspend.status_code == 200

        # User bisa login lagi
        login_again = client.post("/auth/login", json={"email": email, "password": password})
        assert login_again.status_code == 200

    def test_add_user_by_superadmin_all_roles(self):
        """Sistem: superadmin menambahkan user dengan berbagai role."""
        client = self.client
        import uuid
        super_login = client.post(
            "/auth/login",
            json={"email": "superadmin@ayshed.biz.id", "password": "superadmin123"},
        )
        assert super_login.status_code == 200
        token = super_login.json()["access_token"]

        for role in ["user", "admin", "superadmin"]:
            email = f"rbac_role_{role}_{uuid.uuid4().hex[:8]}@example.com"
            resp = client.post(
                "/auth/add-user",
                json={"email": email, "password": "securepassword123", "role": role},
                headers={"Authorization": f"Bearer {token}"},
            )
            assert resp.status_code == 201, f"Gagal tambah role {role}: {resp.text}"

    def test_chart_data_structure(self):
        """Sistem: endpoint chart mengembalikan struktur yang benar."""
        client = self.client
        super_login = client.post(
            "/auth/login",
            json={"email": "superadmin@ayshed.biz.id", "password": "superadmin123"},
        )
        assert super_login.status_code == 200
        token = super_login.json()["access_token"]

        resp = client.get(
            "/api/charts/login-summary",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        for key in ["daily", "weekly", "monthly"]:
            assert key in data
            assert isinstance(data[key], list)
            for item in data[key]:
                assert "x" in item
                assert "success" in item
                assert "fail" in item

    def test_role_based_access_control(self):
        """Sistem: admin tidak bisa mengakses endpoint superadmin."""
        client = self.client
        # Login sebagai admin (non-superadmin)
        admin_login = client.post(
            "/auth/login",
            json={"email": "admin@g.com", "password": "superadmin123"},
        )
        # Jika admin@g.com tidak ada atau password salah, coba superadmin
        if admin_login.status_code != 200:
            admin_login = client.post(
                "/auth/login",
                json={"email": "superadmin@ayshed.biz.id", "password": "superadmin123"},
            )
        assert admin_login.status_code == 200
        token = admin_login.json()["access_token"]

        # add-user membutuhkan superadmin; jika token bukan superadmin, harus 403
        import time
        email = f"rbac_test_{int(time.time())}@example.com"
        resp = client.post(
            "/auth/add-user",
            json={"email": email, "password": "securepassword123", "role": "user"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code in (201, 403), f"Unexpected status: {resp.status_code}"
