# PacketLens — System Architecture & Design Specification

## 1. System Overview

**PacketLens** is an end-to-end network traffic analysis platform designed to process, parse, analyze, and visualize packet capture files (`.pcap` and `.pcapng`). Built with an asynchronous Python FastAPI backend, Scapy parsing engine, Pandas analytical processor, SQLite database, and a React + Vite + Tailwind CSS dashboard.

```mermaid
flowchart TD
    subgraph Client ["Frontend (React + Vite + Tailwind CSS + Recharts)"]
        UI_Upload["Drag & Drop PCAP Uploader"]
        UI_Dash["Executive Metrics & Overview"]
        UI_Charts["Interactive Protocol & Bandwidth Charts"]
        UI_Table["Filterable Packet Inspection Table"]
        UI_Details["Hex/Raw & Decoded Layer Inspector"]
    end

    subgraph API ["Backend API (FastAPI)"]
        Router["FastAPI Router /api/v1"]
        Val["File Validator (Magic bytes & Size)"]
        Endpoints["Upload / Stats / Packets / Export"]
    end

    subgraph Engine ["Processing Engine"]
        Parser["Scapy Packet Parser (.pcap & .pcapng)"]
        Extractor["Layer-by-Layer Metadata Extractor"]
        Analytics["Pandas Aggregator & Flow Analyzer"]
    end

    subgraph Storage ["Persistence Layer"]
        DB[(SQLite Database via SQLAlchemy)]
        RawFiles[("Capture Storage (backend/uploads)")]
    end

    UI_Upload -->|Multipart File Upload| Router
    Router --> Val
    Val -->|Store Temp File| RawFiles
    Val --> Parser
    Parser --> Extractor
    Extractor --> Analytics
    Analytics -->|Save Session & Packet Summaries| DB
    DB --> Endpoints
    Endpoints -->|JSON REST Responses| UI_Dash
    Endpoints -->|JSON REST Responses| UI_Charts
    Endpoints -->|Paginated Packet Logs| UI_Table
    Endpoints -->|Packet Tree| UI_Details
```

---

## 2. Core Protocol Stack Coverage

PacketLens inspects the standard OSI & TCP/IP network model layers:

| Layer | Protocol | Key Fields Extracted |
| :--- | :--- | :--- |
| **Data Link (L2)** | Ethernet, ARP | Source/Dest MAC, Hardware type, Protocol type, ARP opcode (request/reply) |
| **Network (L3)** | IPv4 | Source/Dest IP, TTL, IP Flags (DF, MF), Fragment Offset, Version, IHL, Total Length |
| **Network (L3)** | IPv6 | Source/Dest IPv6, Next Header, Hop Limit, Traffic Class, Flow Label |
| **Transport (L4)** | TCP | Source/Dest Port, Sequence/Ack Numbers, Flags (SYN, ACK, FIN, RST, PSH, URG), Window Size |
| **Transport (L4)** | UDP | Source/Dest Port, Length, Checksum |
| **Transport (L4)** | ICMP / ICMPv6 | Type, Code, Sequence, Checksum (Echo Request/Reply, Unreachable, Redirect) |
| **Application (L7)** | DNS | Query Name, Query Type (A, AAAA, MX, TXT), Response Code, Answer Records |
| **Application (L7)** | HTTP | Method (GET, POST), Host, URI, Status Code, Content-Type (when unencrypted) |

---

## 3. Data Processing Pipeline

```mermaid
sequenceDiagram
    autonumber
    actor User as Network Analyst
    participant Frontend as React Dashboard
    participant API as FastAPI Backend
    participant Validator as Input Validator
    participant Scapy as Scapy Parser Engine
    participant Pandas as Pandas Analytics Engine
    participant DB as SQLite Database

    User->>Frontend: Selects & uploads file.pcap
    Frontend->>API: POST /api/v1/captures/upload (Multipart)
    API->>Validator: Validate extension, magic bytes, file size
    Validator-->>API: Validated safe
    API->>Scapy: Parse packet stream (PcapReader)
    loop Every Packet
        Scapy->>Scapy: Extract L2, L3, L4, L7 header attributes
    end
    Scapy-->>Pandas: Parsed packet list / records
    Pandas->>Pandas: Calculate protocol distribution, top talkers, bandwidth over time, flow stats
    Pandas-->>DB: Persist CaptureSession, PacketRecords, and ProtocolMetrics
    DB-->>API: Session ID & Analytics Summary
    API-->>Frontend: HTTP 201 Created (Session ID, Summary Stats)
    Frontend->>User: Displays interactive metrics, charts, & packet tables
```

---

## 4. Security & Robustness Considerations

1. **Magic Bytes Validation**: Ensure uploaded files match genuine PCAP (`0xa1b2c3d4`, `0xd4c3b2a1`) or PCAPNG (`0x0a0d0d0a`) magic headers rather than solely trusting file extensions.
2. **Resource Exhaustion Prevention**: Use streaming reader (`scapy.utils.PcapReader`) instead of loading gigabyte-sized files all at once into RAM with `rdpcap`.
3. **Strict Path Traversal Protection**: Store uploaded captures using sanitized UUID filenames inside isolated storage (`backend/uploads/`).
4. **Offline Only Safe Parsing**: No live promiscuous mode socket creation required during analysis mode, allowing testing in any standard user environment without root/admin driver dependencies.
