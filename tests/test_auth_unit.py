"""Unit tests untuk fungsi auth dan utilitas apiSEC."""
import pytest
from apiSEC.auth import hash_password, verify_password, create_access_token, decode_access_token
from apiSEC.database import UserRole


class TestAuthUnit:
    def test_hash_password_produces_hash(self):
        pw = "securepassword123"
        h = hash_password(pw)
        assert h is not None
        assert h != pw
        assert isinstance(h, str)
        assert len(h) > 20

    def test_verify_password_true(self):
        pw = "securepassword123"
        h = hash_password(pw)
        assert verify_password(pw, h) is True

    def test_verify_password_false(self):
        h = hash_password("securepassword123")
        assert verify_password("wrongpassword", h) is False

    def test_create_and_decode_token(self):
        token = create_access_token(data={"sub": "user123", "role": "user"})
        assert token is not None
        payload = decode_access_token(token)
        assert payload is not None
        assert payload.get("sub") == "user123"
        assert payload.get("role") == "user"

    def test_decode_invalid_token(self):
        assert decode_access_token("not-a-valid-token") is None

    def test_user_role_values(self):
        assert UserRole.user == "user"
        assert UserRole.admin == "admin"
        assert UserRole.superadmin == "superadmin"
