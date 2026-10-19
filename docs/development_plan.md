# PacketLens — BTech Development Plan & Milestone Checklist

## Project Vision & Scope
**PacketLens** is a full-stack network traffic analysis system built for academic demonstration, network diagnostics, and security forensics. It provides in-depth packet dissection (.pcap/.pcapng), multi-layer protocol breakdown, traffic flow statistics, and an executive visualization dashboard.

---

## Phase-by-Phase Roadmap

### Phase 1: Environment Setup & Project Foundation (Current Phase)
- [x] Inspect empty workspace directory.
- [x] Define standardized project architecture and repository structure.
- [x] Configure `.gitignore` for Python, Node, database, and PCAP artifacts.
- [x] Specify pinned Python dependencies in `backend/requirements.txt`.
- [x] Create backend environment template (`.env.example`).
- [x] Setup module package structures (`__init__.py` files).
- [x] Create comprehensive architecture document (`docs/architecture.md`).
- [x] Create master project checklist and roadmap (`docs/development_plan.md`).
- [x] Create main repository documentation (`README.md`).

### Phase 2: Core Packet Parsing Engine (Backend)
- [x] Implement file validation service (`services/validator.py`):
  - File extension check (`.pcap`, `.pcapng`).
  - Magic byte validation (`0xa1b2c3d4`, `0xd4c3b2a1`, `0x0a0d0d0a`).
  - File size bounds checking (configurable max upload limit).
- [x] Implement Scapy parsing engine (`services/pcap_parser.py`):
  - Layer 2 extraction: Ethernet (MAC addresses, type), ARP (opcodes, target/sender IPs and MACs).
  - Layer 3 extraction: IPv4 (src, dst, TTL, flags, version), IPv6 (src, dst, next header, hop limit).
  - Layer 4 extraction: TCP (ports, flags, seq, ack, window), UDP (ports, length), ICMP / ICMPv6 (types, codes).
  - Layer 7 extraction: DNS queries/answers, HTTP request/response headers.
- [x] Implement synthetic PCAP generator fixture for tests (`tests/conftest.py`).
- [x] Build unit test suite for parser (`tests/test_parser.py`) validating all protocol layers.
- [x] Build unit tests for file validator (`tests/test_validator.py`).
- [x] Build unit tests for statistics calculation (`tests/test_stats.py`).
- [x] Create standalone CLI inspector utility (`app/inspect_pcap.py`).

### Phase 3: Analytics & Aggregation Engine (Pandas + Scapy)
- [x] Implement statistical analyzer (`services/statistics.py`) using Pandas DataFrames:
  - Overall session metrics (total packets, total bytes, duration, average packet size, bitrate).
  - Protocol breakdown (distribution counts and percentage for TCP, UDP, DNS, ICMP, ARP, IPv4, IPv6).
  - Top Talkers analysis (Top Source IPs and Top Destination IPs by packet count & byte volume).
  - Top IP Conversations / Network Flows (Source IP <-> Dest IP pairs).
  - Zero-division safe defaults for 0-packet captures.
- [x] Build unit tests for statistics calculation (`tests/test_stats.py`).

### Phase 4: Database Models & FastAPI REST API
- [x] Configure database engine and session maker (`core/database.py`).
- [x] Define SQLAlchemy database models (`models/capture.py`):
  - `AnalysisSession`: session metadata, format, file size, totals, statistics JSON.
  - `PacketEntry`: indexed packet entries for search, filter, and pagination.
- [x] Define Pydantic request/response schemas (`schemas/api.py` and `schemas/pcap.py`).
- [x] Implement REST endpoints:
  - `GET /api/health`: Operational status and API version.
  - `POST /api/analyze`: Multipart upload, validation, streaming dissection, aggregation, and DB storage.
  - `GET /api/analysis/{analysis_id}/statistics`: Retrieve computed metrics and protocol distribution.
  - `GET /api/analysis/{analysis_id}/packets`: Paginated packet inspection with protocol, IP, and port filtering.
  - `GET /api/analysis/{analysis_id}/export`: Download dissected packets as CSV.
  - `GET /api/analyses`: List recent capture analysis sessions.
- [x] Implement integration tests for API endpoints using `httpx.AsyncClient` (`tests/test_api.py`).
- [x] Configure CORS for local React development server (`http://localhost:5173`).

### Phase 5: Modern Frontend Web Dashboard (React + Vite + Tailwind + Recharts)
- [x] Scaffold React + Vite frontend application in `frontend/`.
- [x] Setup Tailwind CSS v3 styling and cyber dark navy theme with cyan accents.
- [x] Implement dashboard layout & navigation:
  - Header with system status, active session switcher, and CSV export.
  - Sidebar navigation (Traffic Dashboard, Packet Inspector, Captures History).
- [x] Build UI Components:
  - `UploadModal`: Drag-and-drop file upload with progress bar, validation alerts, and loading spinner.
  - `StatsCards`: 4 executive metric cards (Total Packets, Total Volume, Unique IP Hosts, Dominant Protocol).
  - `ProtocolChart`: Recharts interactive donut chart showing real protocol shares.
  - `TrafficTimelineChart`: Recharts area chart showing traffic volume over time with custom tooltips.
  - `FlowsView`: Top communicating endpoints (Talkers) and top bidirectional IP conversations (Flows).
  - `PacketTable`: Filterable, paginated table with protocol pill filters, IP/port/text search, and pagination.
  - `PacketDetailsModal`: Deep layer-by-layer dissection tree (Ethernet -> IP/ARP -> TCP/UDP/ICMP -> Application).
- [x] Connect frontend to FastAPI backend using typed API service layer (`services/api.js`) and environment variables (`.env`).
- [x] Production build verification (`npm run build`) passed with zero errors.

### Phase 6: System Hardening, Integration & Academic Presentation Prep
- [ ] Verify complete end-to-end user workflow: Upload -> Parse -> Analyze -> Visualize -> Export.
- [ ] Benchmark parser performance with realistic PCAP sizes (1,000 to 50,000 packets).
- [ ] Prepare sample captures suite in `backend/sample_data/`.
- [ ] Finalize BTech documentation:
  - Project Report synopsis / abstract.
  - System architecture and sequence diagrams.
  - Viva voice Q&A preparation guide (Scapy vs Wireshark/libpcap, TCP flags, bandwidth calculation, Pandas aggregation).
