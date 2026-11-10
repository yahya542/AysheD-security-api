"""Integration tests untuk endpoint API apiSEC menggunakan TestClient."""
from fastapi.testclient import TestClient
from apiSEC.main import app


class TestAuthIntegration:
    @classmethod
    def setup_class(cls):
        cls.client = TestClient(app)

    def test_read_root(self):
        response = self.client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert "message" in data
        assert data.get("version") == "1.0.0"

    def test_register_new_user(self):
        import time
        email = f"itest_{int(time.time())}@example.com"
        response = self.client.post(
            "/auth/register",
            json={
                "email": email,
                "password": "securepassword123",
                "full_name": "Integration Test User",
                "birth_place": "Jakarta",
                "birth_date": "2000-01-01",
            },
        )
        assert response.status_code == 201
        assert response.json().get("message") == "Registration successful"

    def test_register_duplicate_email(self):
        import time
        email = f"itest_dup_{int(time.time())}@example.com"
        self.client.post(
            "/auth/register",
            json={
                "email": email,
                "password": "securepassword123",
            },
        )
        response = self.client.post(
            "/auth/register",
            json={
                "email": email,
                "password": "securepassword123",
            },
        )
        assert response.status_code == 409

    def test_login_success(self):
        import time
        email = f"itest_login_{int(time.time())}@example.com"
        self.client.post(
            "/auth/register",
            json={
                "email": email,
                "password": "securepassword123",
            },
        )
        response = self.client.post(
            "/auth/login",
            json={"email": email, "password": "securepassword123"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data.get("token_type") == "bearer"

    def test_login_wrong_password(self):
        response = self.client.post(
            "/auth/login",
            json={"email": "nonexistent@example.com", "password": "wrongpassword"},
        )
        assert response.status_code == 401

    def test_get_users_requires_auth(self):
        response = self.client.get("/auth/users")
        assert response.status_code in (401, 403)

    def test_add_user_requires_superadmin(self):
        import time
        # Login sebagai superadmin
        login_resp = self.client.post(
            "/auth/login",
            json={"email": "superadmin@ayshed.biz.id", "password": "superadmin123"},
        )
        assert login_resp.status_code == 200
        token = login_resp.json()["access_token"]

        # Tanpa token
        email = f"newuser_{int(time.time())}@example.com"
        response = self.client.post(
            "/auth/add-user",
            json={"email": email, "password": "securepassword123", "role": "user"},
        )
        assert response.status_code == 401

        # Dengan token superadmin
        response = self.client.post(
            "/auth/add-user",
            json={"email": email, "password": "securepassword123", "role": "user"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 201
        assert response.json().get("message") == "User created successfully"


class TestAdminIntegration:
    @classmethod
    def setup_class(cls):
        cls.client = TestClient(app)

    def _superadmin_token(self):
        resp = self.client.post(
            "/auth/login",
            json={"email": "superadmin@ayshed.biz.id", "password": "superadmin123"},
        )
        assert resp.status_code == 200
        return resp.json()["access_token"]

    def test_suspend_user(self):
        token = self._superadmin_token()
        # Dapatkan user non-superadmin untuk di-suspend
        users_resp = self.client.get(
            "/auth/users", headers={"Authorization": f"Bearer {token}"}
        )
        assert users_resp.status_code == 200
        users = users_resp.json()
        target = next((u for u in users if u["email"] != "superadmin@ayshed.biz.id"), None)
        assert target is not None, "Tidak ada user target untuk suspend"

        resp = self.client.post(
            "/admin/suspend-user",
            json={"user_id": str(target["id"])},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        assert resp.json().get("message") == f"User {target['email']} suspended"

    def test_unsuspend_user(self):
        token = self._superadmin_token()
        users_resp = self.client.get(
            "/auth/users", headers={"Authorization": f"Bearer {token}"}
        )
        users = users_resp.json()
        target = next((u for u in users if not u["is_active"]), None)
        assert target is not None, "Tidak ada user yang suspended untuk di-unsuspend"

        resp = self.client.post(
            "/admin/unsuspend-user",
            json={"user_id": str(target["id"])},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        assert resp.json().get("message") == f"User {target['email']} unsuspended"

    def test_chart_endpoint(self):
        token = self._superadmin_token()
        resp = self.client.get(
            "/api/charts/login-summary",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "daily" in data
        assert "weekly" in data
        assert "monthly" in data

    def test_admin_logs_endpoint(self):
        token = self._superadmin_token()
        resp = self.client.get(
            "/admin/logs",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)
