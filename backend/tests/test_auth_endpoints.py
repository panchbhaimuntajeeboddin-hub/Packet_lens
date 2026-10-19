"""Integration tests for authentication API endpoints: register, login, logout, me."""

import pytest
# pyrefly: ignore[missing-import]
from httpx import ASGITransport, AsyncClient

from app.main import app
from app.core.database import SessionLocal, init_db
from app.models.user import User


@pytest.fixture(autouse=True)
def clean_test_users():
    """Ensure clean user records for test accounts."""
    init_db()
    db = SessionLocal()
    try:
        db.query(User).filter(
            User.email.in_([
                "alice@packetlens.org",
                "bob@packetlens.org",
                "duplicate@packetlens.org",
            ])
        ).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()


@pytest.mark.anyio
async def test_register_success_and_cookie():
    """Verifies that an analyst can register and receive an HttpOnly session cookie."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "full_name": "Alice Security",
            "email": "ALICE@PacketLens.org",
            "password": "SecurePassword#2026",
            "confirm_password": "SecurePassword#2026",
        }
        res = await client.post("/api/auth/register", json=payload)
        assert res.status_code == 201
        data = res.json()
        assert data["email"] == "alice@packetlens.org"
        assert data["full_name"] == "Alice Security"
        assert "password" not in data
        assert "password_hash" not in data
        assert "id" in data

        # Check HttpOnly cookie
        assert "packetlens_session" in res.cookies

        # Check GET /api/auth/me using the cookie
        me_res = await client.get("/api/auth/me")
        assert me_res.status_code == 200
        assert me_res.json()["email"] == "alice@packetlens.org"


@pytest.mark.anyio
async def test_register_duplicate_email_rejected():
    """Verifies that duplicate registration is rejected with 409 Conflict."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "full_name": "Duplicate User",
            "email": "duplicate@packetlens.org",
            "password": "SecurePassword#2026",
            "confirm_password": "SecurePassword#2026",
        }
        res1 = await client.post("/api/auth/register", json=payload)
        assert res1.status_code == 201

        # Attempt duplicate registration with different casing
        payload2 = {
            "full_name": "Duplicate User 2",
            "email": "DUPLICATE@packetlens.org ",
            "password": "AnotherPassword#2026",
            "confirm_password": "AnotherPassword#2026",
        }
        res2 = await client.post("/api/auth/register", json=payload2)
        assert res2.status_code == 409
        assert "already exists" in res2.json()["detail"].lower()


@pytest.mark.anyio
async def test_register_validation_errors():
    """Verifies password mismatch and weak password validation."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Password mismatch
        res1 = await client.post(
            "/api/auth/register",
            json={
                "full_name": "Test User",
                "email": "mismatch@packetlens.org",
                "password": "SecurePassword#2026",
                "confirm_password": "DifferentPassword#2026",
            },
        )
        assert res1.status_code == 422

        # Weak password (too short)
        res2 = await client.post(
            "/api/auth/register",
            json={
                "full_name": "Test User",
                "email": "weak@packetlens.org",
                "password": "short",
                "confirm_password": "short",
            },
        )
        assert res2.status_code == 422


@pytest.mark.anyio
async def test_login_success_and_logout_flow():
    """Verifies login, profile inspection, and logout invalidation flow."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Register Bob
        reg_payload = {
            "full_name": "Bob Analyst",
            "email": "bob@packetlens.org",
            "password": "CyberOpsPassword#2026",
            "confirm_password": "CyberOpsPassword#2026",
        }
        reg_res = await client.post("/api/auth/register", json=reg_payload)
        assert reg_res.status_code == 201

        # Clear client cookies to simulate unauthenticated client
        client.cookies.clear()

        # 2. Check /api/auth/me without cookies -> 401
        unauth_res = await client.get("/api/auth/me")
        assert unauth_res.status_code == 401

        # 3. Login with wrong password -> 401
        bad_login = await client.post(
            "/api/auth/login",
            json={"email": "bob@packetlens.org", "password": "WrongPassword#123"},
        )
        assert bad_login.status_code == 401
        assert "Invalid email or password." in bad_login.json()["detail"]

        # 4. Login with non-existent email -> 401
        nonexistent_login = await client.post(
            "/api/auth/login",
            json={"email": "nonexistent@packetlens.org", "password": "CyberOpsPassword#2026"},
        )
        assert nonexistent_login.status_code == 401
        assert "Invalid email or password." in nonexistent_login.json()["detail"]

        # 5. Login with correct credentials -> 200 and cookie set
        login_res = await client.post(
            "/api/auth/login",
            json={"email": "bob@packetlens.org", "password": "CyberOpsPassword#2026"},
        )
        assert login_res.status_code == 200
        assert "packetlens_session" in login_res.cookies

        # 6. Verify /api/auth/me returns Bob
        me_res = await client.get("/api/auth/me")
        assert me_res.status_code == 200
        assert me_res.json()["email"] == "bob@packetlens.org"
        assert me_res.json()["full_name"] == "Bob Analyst"

        # 7. Logout
        logout_res = await client.post("/api/auth/logout")
        assert logout_res.status_code == 200
        assert "Logged out successfully." in logout_res.json()["message"]

        # 8. Subsequent /api/auth/me returns 401
        post_logout_res = await client.get("/api/auth/me")
        assert post_logout_res.status_code == 401
