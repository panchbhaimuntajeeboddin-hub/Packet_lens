"""Pydantic data models for packet dissection, capture sessions, and traffic statistics."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class PacketRecord(BaseModel):
    """Normalized structured representation of a single dissected packet."""

    packet_num: int = Field(..., description="1-based index of the packet in the capture sequence")
    timestamp: float = Field(..., description="Epoch timestamp of packet capture")
    timestamp_iso: str = Field(..., description="ISO 8601 formatted timestamp string")
    length: int = Field(..., description="Captured packet length in bytes")

    # Layer 2 - Data Link
    src_mac: Optional[str] = Field(None, description="Source MAC address")
    dst_mac: Optional[str] = Field(None, description="Destination MAC address")

    # Layer 3 - Network
    network_protocol: Optional[str] = Field(None, description="Network layer protocol (IPv4, IPv6, ARP)")
    src_ip: Optional[str] = Field(None, description="Source IP address or ARP sender IP")
    dst_ip: Optional[str] = Field(None, description="Destination IP address or ARP target IP")
    ip_version: Optional[int] = Field(None, description="IP version (4 or 6)")
    ttl: Optional[int] = Field(None, description="Time To Live (IPv4) or Hop Limit (IPv6)")

    # Layer 4 - Transport
    transport_protocol: Optional[str] = Field(None, description="Transport layer protocol (TCP, UDP, ICMP, ICMPv6)")
    src_port: Optional[int] = Field(None, description="Source port (TCP/UDP)")
    dst_port: Optional[int] = Field(None, description="Destination port (TCP/UDP)")
    tcp_flags: Optional[List[str]] = Field(None, description="Active TCP flags (e.g. ['SYN', 'ACK'])")
    icmp_type: Optional[int] = Field(None, description="ICMP message type")
    icmp_code: Optional[int] = Field(None, description="ICMP message subcode")

    # Layer 7 - Application
    application_protocol: Optional[str] = Field(None, description="Identified application protocol (DNS, HTTP)")
    dns_query: Optional[str] = Field(None, description="Queried DNS domain name if applicable")
    dns_query_type: Optional[str] = Field(None, description="Queried DNS record type (A, AAAA, MX, etc.)")

    # Overall Summary
    highest_protocol: str = Field(..., description="Highest identified protocol in the packet stack")
    info: str = Field(..., description="Human-readable packet summary line")


class EndpointStatistic(BaseModel):
    """Traffic statistics for a single communicating host/IP."""
    ip: str = Field(..., description="IP address of the host")
    packet_count: int = Field(..., description="Total packets associated with this endpoint")
    byte_count: int = Field(..., description="Total bytes associated with this endpoint")
    percentage_packets: float = Field(..., description="Share of total packet count")
    percentage_bytes: float = Field(..., description="Share of total bytes")


class ConversationStatistic(BaseModel):
    """Traffic statistics for a two-way IP communication pair."""
    source_ip: str
    destination_ip: str
    packet_count: int
    byte_count: int


class TrafficStatistics(BaseModel):
    """Comprehensive traffic volume, protocol distribution, and endpoint analytics."""

    total_packets: int = Field(0, description="Total number of packets in capture")
    total_bytes: int = Field(0, description="Total size of all packets in bytes")
    capture_start_time: Optional[str] = Field(None, description="ISO timestamp of earliest packet")
    capture_end_time: Optional[str] = Field(None, description="ISO timestamp of latest packet")
    duration_seconds: float = Field(0.0, description="Total duration of capture session")
    avg_packet_size: float = Field(0.0, description="Average packet size in bytes")
    bitrate_bps: float = Field(0.0, description="Average bitrate in bits per second")

    # Protocol Analytics
    protocol_distribution: Dict[str, int] = Field(
        default_factory=dict,
        description="Raw packet count per protocol (e.g. {'TCP': 150, 'UDP': 40})"
    )
    protocol_percentages: Dict[str, float] = Field(
        default_factory=dict,
        description="Percentage breakdown per protocol"
    )

    # Endpoints
    unique_ips: List[str] = Field(default_factory=list, description="Unique IP addresses observed")
    total_unique_ips: int = Field(0, description="Count of distinct IP addresses")
    top_source_ips: List[EndpointStatistic] = Field(
        default_factory=list,
        description="Top talkers by transmitted traffic"
    )
    top_destination_ips: List[EndpointStatistic] = Field(
        default_factory=list,
        description="Top listeners by received traffic"
    )
    top_conversations: List[ConversationStatistic] = Field(
        default_factory=list,
        description="Top bidirectional communication flows"
    )


class CaptureAnalysisResult(BaseModel):
    """Complete analysis output containing file metadata, statistics, and parsed packets."""

    filename: str
    file_size_bytes: int
    file_format: str = Field(..., description="Detected format: PCAP or PCAPNG")
    statistics: TrafficStatistics
    packets: List[PacketRecord] = Field(default_factory=list)
