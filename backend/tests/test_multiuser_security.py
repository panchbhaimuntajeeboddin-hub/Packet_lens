"""Automated multi-user security and data isolation tests.

Verifies strict per-user authorization, IDOR/BOLA prevention, and session security:
1. User A can register and log in.
2. User B can register and log in independently.
3. User A uploads file A.
4. User B uploads file B.
5. User A sees only file A and its analysis.
6. User B sees only file B and its analysis.
7. User B cannot retrieve file A by changing an analysis ID in the URL.
8. User B cannot download, export, delete, or modify User A's records.
9. User B cannot see User A's dashboard statistics.
10. Unauthenticated requests cannot access protected endpoints.
11. Logout invalidates the session.
12. Invalid credentials and duplicate registrations are handled safely.
"""

import pytest
from httpx import ASGITransport, AsyncClient
from scapy.all import wrpcap
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from app.main import app
from app.core.database import SessionLocal, init_db
from app.models.user import User


@pytest.fixture(autouse=True)
def clean_security_users():
    """Ensure clean slate for User A and User B in database."""
    init_db()
    db = SessionLocal()
    try:
        db.query(User).filter(
            User.email.in_([
                "usera@packetlens.org",
                "userb@packetlens.org",
            ])
        ).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()


def create_pcap_bytes(src_ip: str, dst_ip: str, count: int = 3) -> bytes:
    """Helper to generate distinct synthetic PCAP bytes for specific users."""
    import tempfile
    packets = [
        Ether() / IP(src=src_ip, dst=dst_ip) / TCP(sport=1000 + i, dport=80)
        for i in range(count)
    ]
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
        tmp_name = tmp.name
    try:
        wrpcap(tmp_name, packets)
        with open(tmp_name, "rb") as f:
            return f.read()
    finally:
        import os
        if os.path.exists(tmp_name):
            os.remove(tmp_name)


@pytest.mark.anyio
async def test_multiuser_isolation_and_idor_prevention():
    """Comprehensive test validating full User A and User B isolation."""
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://test") as client_a:
        async with AsyncClient(transport=transport, base_url="http://test") as client_b:

            # 1. User A registers and logs in
            reg_a = await client_a.post("/api/auth/register", json={
                "full_name": "User Alpha",
                "email": "usera@packetlens.org",
                "password": "PasswordAlpha#2026",
                "confirm_password": "PasswordAlpha#2026",
            })
            assert reg_a.status_code == 201
            user_a = reg_a.json()
            assert user_a["email"] == "usera@packetlens.org"
            assert "packetlens_session" in reg_a.cookies

            # 2. User B registers and logs in independently
            reg_b = await client_b.post("/api/auth/register", json={
                "full_name": "User Beta",
                "email": "userb@packetlens.org",
                "password": "PasswordBeta#2026",
                "confirm_password": "PasswordBeta#2026",
            })
            assert reg_b.status_code == 201
            user_b = reg_b.json()
            assert user_b["email"] == "userb@packetlens.org"
            assert "packetlens_session" in reg_b.cookies

            # 3. User A uploads File A
            file_a_bytes = create_pcap_bytes("10.0.0.1", "10.0.0.2", count=4)
            upload_a = await client_a.post(
                "/api/analyze",
                files={"file": ("capture_a.pcap", file_a_bytes, "application/vnd.tcpdump.pcap")},
            )
            assert upload_a.status_code == 201
            analysis_a_id = upload_a.json()["analysis_id"]

            # 4. User B uploads File B
            file_b_bytes = create_pcap_bytes("192.168.100.1", "192.168.100.2", count=7)
            upload_b = await client_b.post(
                "/api/analyze",
                files={"file": ("capture_b.pcap", file_b_bytes, "application/vnd.tcpdump.pcap")},
            )
            assert upload_b.status_code == 201
            analysis_b_id = upload_b.json()["analysis_id"]

            # 5. User A sees only File A in /api/analyses
            list_a = await client_a.get("/api/analyses")
            assert list_a.status_code == 200
            analyses_a = list_a.json()
            assert any(s["analysis_id"] == analysis_a_id for s in analyses_a)
            assert not any(s["analysis_id"] == analysis_b_id for s in analyses_a)

            # 6. User B sees only File B in /api/analyses
            list_b = await client_b.get("/api/analyses")
            assert list_b.status_code == 200
            analyses_b = list_b.json()
            assert any(s["analysis_id"] == analysis_b_id for s in analyses_b)
            assert not any(s["analysis_id"] == analysis_a_id for s in analyses_b)

            # 7. User B CANNOT retrieve File A by IDOR URL manipulation
            # 7a. Statistics endpoint
            stats_idor = await client_b.get(f"/api/analysis/{analysis_a_id}/statistics")
            assert stats_idor.status_code in [403, 404]

            # 7b. Packets endpoint
            packets_idor = await client_b.get(f"/api/analysis/{analysis_a_id}/packets")
            assert packets_idor.status_code in [403, 404]

            # 7c. Session metadata endpoint
            session_idor = await client_b.get(f"/api/analysis/{analysis_a_id}")
            assert session_idor.status_code in [403, 404]

            # 8. User B CANNOT download/export or delete User A's records
            # 8a. CSV Export
            export_idor = await client_b.get(f"/api/analysis/{analysis_a_id}/export")
            assert export_idor.status_code in [403, 404]

            # 8b. Delete operation
            delete_idor = await client_b.delete(f"/api/analysis/{analysis_a_id}")
            assert delete_idor.status_code in [403, 404]

            # Verify User A's record was NOT deleted
            stats_a = await client_a.get(f"/api/analysis/{analysis_a_id}/statistics")
            assert stats_a.status_code == 200
            assert stats_a.json()["total_packets"] == 4

            # 9. User B cannot see User A's dashboard statistics
            dash_a = await client_a.get("/api/dashboard/stats")
            assert dash_a.status_code == 200
            data_a = dash_a.json()
            assert data_a["total_uploads"] == 1
            assert data_a["total_packets"] == 4
            assert data_a["user"]["email"] == "usera@packetlens.org"

            dash_b = await client_b.get("/api/dashboard/stats")
            assert dash_b.status_code == 200
            data_b = dash_b.json()
            assert data_b["total_uploads"] == 1
            assert data_b["total_packets"] == 7
            assert data_b["user"]["email"] == "userb@packetlens.org"

            # 10. Unauthenticated requests cannot access protected endpoints
            unauth_client = AsyncClient(transport=transport, base_url="http://test")
            assert (await unauth_client.get("/api/auth/me")).status_code == 401
            assert (await unauth_client.get("/api/analyses")).status_code == 401
            assert (await unauth_client.get("/api/dashboard/stats")).status_code == 401
            assert (await unauth_client.get(f"/api/analysis/{analysis_a_id}/statistics")).status_code == 401
            assert (await unauth_client.get(f"/api/analysis/{analysis_a_id}/packets")).status_code == 401
            assert (await unauth_client.get(f"/api/analysis/{analysis_a_id}/export")).status_code == 401
            assert (await unauth_client.delete(f"/api/analysis/{analysis_a_id}")).status_code == 401
            assert (await unauth_client.post("/api/analyze")).status_code == 401

            # 11. Logout invalidates the session
            logout_a = await client_a.post("/api/auth/logout")
            assert logout_a.status_code == 200
            assert (await client_a.get("/api/auth/me")).status_code == 401
            assert (await client_a.get("/api/analyses")).status_code == 401

            # 12. Invalid credentials and duplicate registrations handled safely
            bad_pw = await client_a.post("/api/auth/login", json={
                "email": "usera@packetlens.org",
                "password": "WrongPassword#999",
            })
            assert bad_pw.status_code == 401
            assert "Invalid email or password." in bad_pw.json()["detail"]

            duplicate_reg = await client_a.post("/api/auth/register", json={
                "full_name": "User Alpha Copy",
                "email": "usera@packetlens.org",
                "password": "PasswordAlpha#2026",
                "confirm_password": "PasswordAlpha#2026",
            })
            assert duplicate_reg.status_code == 409
            assert "already exists" in duplicate_reg.json()["detail"].lower()
