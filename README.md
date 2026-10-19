# PacketLens — Network Traffic Analyzer

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Scapy](https://img.shields.io/badge/Scapy-2.5+-red?style=for-the-badge)](https://scapy.net/)
[![Pandas](https://img.shields.io/badge/Pandas-2.2+-150458?style=for-the-badge&logo=pandas&logoColor=white)](https://pandas.pydata.org/)
[![React](https://img.shields.io/badge/React-18+-61DAFB?style=for-the-badge&logo=react&logoColor=black)](https://react.dev/)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind_CSS-3.4+-38B2AC?style=for-the-badge&logo=tailwind-css&logoColor=white)](https://tailwindcss.com/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge)](LICENSE)

**PacketLens** is a full-featured network traffic analysis platform designed to inspect, dissect, and visualize packet capture files (`.pcap` and `.pcapng`). It processes raw packet data, extracts multi-layer protocol metadata (ARP, IPv4, IPv6, TCP, UDP, ICMP, DNS, HTTP), computes traffic analytics using Pandas, and presents the insights in an interactive web dashboard.

---

## Key Features

- **Multi-Format PCAP Dissection**: Supports both legacy `.pcap` (libpcap) and modern `.pcapng` files.
- **Deep Protocol Inspection**:
  - **L2 Data Link**: Ethernet frames, ARP requests and replies.
  - **L3 Network**: IPv4 (TTL, flags, fragment offsets) and IPv6 (next header, hop limit).
  - **L4 Transport**: TCP (flags: SYN, ACK, FIN, RST, PSH, URG, window size), UDP, ICMP / ICMPv6.
  - **L7 Application**: DNS query/response extraction, HTTP method and URI parsing.
- **Statistical Traffic Analytics**:
  - Overall throughput, average packet size, and bandwidth utilization.
  - Protocol distribution percentages and packet counts.
  - Top Talkers (most active source and destination IP addresses).
  - IP conversations (flows) and active port service mapping.
  - Time-series traffic density (packets/sec and bytes/sec).
- **Security & Anomaly Detection Signals**:
  - High SYN-to-ACK ratios indicative of SYN flood or port scanning activity.
  - Abnormal ICMP volumes and DNS query tunneling signals.
- **FastAPI REST API**:
  - Secure multipart file upload with magic byte validation.
  - Paginated packet listing with filtering by protocol, IP, and port.
  - Individual packet detailed layer dissection and raw hex dump.
  - Export capabilities in JSON and CSV formats.
- **Interactive UI Dashboard**:
  - Executive summary KPI cards.
  - Interactive Recharts donut, bar, and timeline charts.
  - Searchable, filterable packet table with expandable protocol headers.

---

## Technology Stack

| Layer | Technology | Purpose |
| :--- | :--- | :--- |
| **Backend Framework** | [FastAPI](https://fastapi.tiangolo.com/) | High-performance asynchronous REST API |
| **Packet Parsing** | [Scapy](https://scapy.net/) | Low-level packet dissection and protocol field extraction |
| **Data Analytics** | [Pandas](https://pandas.pydata.org/) | Matrix aggregations, flow metrics, and time-series binning |
| **Database** | [SQLite](https://www.sqlite.org/) via SQLAlchemy | Lightweight, portable persistence for capture history |
| **Data Validation** | [Pydantic v2](https://docs.pydantic.dev/) | Strict request/response validation and serialization |
| **Testing** | [Pytest](https://pytest.org/) & HTTPX | Unit tests for parser/analytics & API integration testing |
| **Frontend UI** | [React](https://react.dev/) + [Vite](https://vitejs.dev/) | Fast client-side dashboard framework |
| **Styling** | [Tailwind CSS](https://tailwindcss.com/) | Modern dark-mode glassmorphic interface |
| **Visualizations** | [Recharts](https://recharts.org/) | Responsive charts for protocols, timelines, and top talkers |

---

## Directory Structure

```text
packet-lens/
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py              # FastAPI application entry point
│   │   ├── core/                # Configuration and database connection
│   │   │   ├── __init__.py
│   │   │   ├── config.py
│   │   │   └── database.py
│   │   ├── models/              # SQLAlchemy database models
│   │   │   ├── __init__.py
│   │   │   └── capture.py
│   │   ├── schemas/             # Pydantic validation schemas
│   │   │   ├── __init__.py
│   │   │   └── pcap.py
│   │   ├── services/            # Core business logic & engines
│   │   │   ├── __init__.py
│   │   │   ├── validator.py     # File magic-bytes & size validation
│   │   │   ├── pcap_parser.py   # Scapy-based parsing engine
│   │   │   └── statistics.py    # Pandas statistical analytics
│   │   └── api/                 # REST endpoints
│   │       ├── __init__.py
│   │       ├── router.py
│   │       └── v1/
│   │           ├── __init__.py
│   │           ├── upload.py
│   │           ├── analysis.py
│   │           └── export.py
│   ├── tests/                   # Pytest test suite
│   │   ├── __init__.py
│   │   ├── conftest.py
│   │   ├── test_parser.py
│   │   ├── test_stats.py
│   │   └── test_api.py
│   ├── sample_data/             # Authorized test PCAPs & guidelines
│   │   └── README.md
│   ├── requirements.txt         # Production backend dependencies
│   └── .env.example             # Configuration template
├── frontend/                    # React + Vite application (Phase 5)
├── docs/                        # Architectural diagrams & development roadmap
│   ├── architecture.md
│   └── development_plan.md
├── .gitignore                   # Ignore rules for virtualenv, DB, & PCAP files
└── README.md                    # Project documentation
```

---

## Prerequisites

- **Python**: Version 3.10, 3.11, or 3.12
- **Node.js**: Version 18+ and `npm` (for Phase 5 frontend)
- **Operating System**: Windows, macOS, or Linux

---

## Quickstart Setup Guide

### 1. Create and Activate a Python Virtual Environment

From the project root directory (`packet lens/`):

**On Windows (PowerShell):**
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

*(If PowerShell script execution is restricted, run `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser` or use Command Prompt: `.\.venv\Scripts\activate.bat`)*

**On macOS / Linux:**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 2. Install Backend Dependencies
```bash
pip install --upgrade pip
pip install -r backend/requirements.txt
```

### 3. Verify the Installation
Run the test runner to ensure all modules load cleanly:
```bash
pytest backend/tests
```

---

## Development Milestones

For the detailed phase-by-phase execution plan and BTech project checklist, refer to [docs/development_plan.md](file:///c:/Users/ARFAT/Desktop/packet%20lens/docs/development_plan.md) and [docs/architecture.md](file:///c:/Users/ARFAT/Desktop/packet%20lens/docs/architecture.md).
