"""API integration tests for PacketLens FastAPI endpoints."""

import io
import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app
from app.core.database import init_db


@pytest.fixture(autouse=True)
def setup_test_db():
    """Ensure database tables are initialized before tests run."""
    init_db()


@pytest.mark.anyio
async def test_health_endpoint():
    """Verifies that GET /api/health returns 200 and operational status."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert "PacketLens" in data["app"]
        assert "version" in data
        assert "timestamp" in data


@pytest.mark.anyio
async def test_root_endpoint():
    """Verifies that GET / returns API welcome and docs link."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert data["docs_url"] == "/docs"


async def authenticate(client: AsyncClient, email: str = "analyst_api_test@packetlens.org"):
    """Registers or logs in the test client to establish an authenticated session cookie."""
    reg_res = await client.post(
        "/api/auth/register",
        json={
            "full_name": "Test Analyst",
            "email": email,
            "password": "SecurePassword#2026",
            "confirm_password": "SecurePassword#2026",
        },
    )
    if reg_res.status_code != 201:
        login_res = await client.post(
            "/api/auth/login",
            json={
                "email": email,
                "password": "SecurePassword#2026",
            },
        )
        assert login_res.status_code == 200


@pytest.mark.anyio
async def test_analyze_invalid_file(corrupted_file_path):
    """Verifies that uploading a non-PCAP file returns 400 Bad Request."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        await authenticate(client)
        with open(corrupted_file_path, "rb") as f:
            files = {"file": ("corrupted.pcap", f.read(), "application/octet-stream")}
            response = await client.post("/api/analyze", files=files)
            assert response.status_code == 400
            assert "Invalid capture header" in response.json()["detail"]


@pytest.mark.anyio
async def test_full_analysis_workflow(synthetic_pcap_path):
    """
    Tests end-to-end workflow:
    1. POST /api/analyze (upload and dissect PCAP)
    2. GET /api/analysis/{id}/statistics (retrieve computed metrics)
    3. GET /api/analysis/{id}/packets (paginated packets & filter by protocol)
    4. GET /api/analysis/{id}/export (download CSV summary)
    5. GET /api/analyses (list user's sessions)
    6. GET /api/dashboard/stats (user aggregate stats)
    7. DELETE /api/analysis/{id} (delete capture)
    """
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        await authenticate(client)

        # Step 1: Upload and analyze
        with open(synthetic_pcap_path, "rb") as f:
            file_bytes = f.read()

        files = {"file": ("test_capture.pcap", file_bytes, "application/vnd.tcpdump.pcap")}
        upload_resp = await client.post("/api/analyze", files=files)
        assert upload_resp.status_code == 201
        upload_data = upload_resp.json()

        analysis_id = upload_data["analysis_id"]
        assert analysis_id is not None
        assert upload_data["filename"] == "test_capture.pcap"
        assert upload_data["file_format"] == "PCAP"
        assert upload_data["total_packets"] == 11
        assert "statistics" in upload_data

        # Step 2: Retrieve Statistics
        stats_resp = await client.get(f"/api/analysis/{analysis_id}/statistics")
        assert stats_resp.status_code == 200
        stats_data = stats_resp.json()
        assert stats_data["total_packets"] == 11
        assert "ARP" in stats_data["protocol_distribution"]
        assert "DNS" in stats_data["protocol_distribution"]

        # Step 3: Retrieve Paginated Packets (Page 1, 5 per page)
        packets_resp = await client.get(f"/api/analysis/{analysis_id}/packets?page=1&page_size=5")
        assert packets_resp.status_code == 200
        packets_data = packets_resp.json()
        assert packets_data["page"] == 1
        assert packets_data["page_size"] == 5
        assert packets_data["total_matched"] == 11
        assert packets_data["total_pages"] == 3
        assert len(packets_data["packets"]) == 5

        # Step 4: Filter by protocol (ARP)
        arp_resp = await client.get(f"/api/analysis/{analysis_id}/packets?protocol=ARP")
        assert arp_resp.status_code == 200
        arp_data = arp_resp.json()
        assert arp_data["total_matched"] == 2
        for pkt in arp_data["packets"]:
            assert pkt["highest_protocol"] == "ARP" or pkt["network_protocol"] == "ARP"

        # Step 5: Filter by IP address (8.8.8.8)
        ip_resp = await client.get(f"/api/analysis/{analysis_id}/packets?ip=8.8.8.8")
        assert ip_resp.status_code == 200
        ip_data = ip_resp.json()
        assert ip_data["total_matched"] == 2

        # Step 6: Export CSV
        csv_resp = await client.get(f"/api/analysis/{analysis_id}/export")
        assert csv_resp.status_code == 200
        assert "text/csv" in csv_resp.headers["content-type"]
        assert "attachment" in csv_resp.headers["content-disposition"]
        csv_content = csv_resp.text
        assert "Packet #" in csv_content
        assert "Timestamp (ISO)" in csv_content
        assert "Who has 192.168.1.1" in csv_content

        # Step 7: List sessions
        list_resp = await client.get("/api/analyses")
        assert list_resp.status_code == 200
        sessions = list_resp.json()
        assert any(s["analysis_id"] == analysis_id for s in sessions)

        # Step 8: Dashboard stats
        dash_resp = await client.get("/api/dashboard/stats")
        assert dash_resp.status_code == 200
        dash_data = dash_resp.json()
        assert dash_data["total_uploads"] >= 1
        assert dash_data["total_packets"] >= 11

        # Step 9: Delete capture
        del_resp = await client.delete(f"/api/analysis/{analysis_id}")
        assert del_resp.status_code == 200
        assert "deleted successfully" in del_resp.json()["message"]


@pytest.mark.anyio
async def test_nonexistent_analysis_returns_404():
    """Verifies that querying a non-existent analysis ID returns 404 Not Found."""
    fake_id = "00000000-0000-0000-0000-000000000000"
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        await authenticate(client)

        r1 = await client.get(f"/api/analysis/{fake_id}/statistics")
        assert r1.status_code == 404

        r2 = await client.get(f"/api/analysis/{fake_id}/packets")
        assert r2.status_code == 404

        r3 = await client.get(f"/api/analysis/{fake_id}/export")
        assert r3.status_code == 404
