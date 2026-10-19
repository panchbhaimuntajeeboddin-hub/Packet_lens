"""SQLAlchemy ORM models for capture analysis sessions and dissected packet entries."""

from datetime import datetime, timezone
from sqlalchemy import (
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import relationship

from app.core.database import Base


class AnalysisSession(Base):
    """Represents an analyzed network capture file session."""

    __tablename__ = "analysis_sessions"

    id = Column(String(36), primary_key=True, index=True)
    owner_user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=True, index=True)
    filename = Column(String(255), nullable=False)
    file_format = Column(String(10), nullable=False)  # PCAP or PCAPNG
    file_size_bytes = Column(Integer, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    total_packets = Column(Integer, default=0, nullable=False)
    total_bytes = Column(Integer, default=0, nullable=False)
    duration_seconds = Column(Float, default=0.0, nullable=False)
    statistics_json = Column(Text, nullable=False)  # JSON serialized TrafficStatistics

    # Relationship to owning user
    owner = relationship("User", back_populates="analyses")

    # One-to-many relationship with packet entries
    packets = relationship(
        "PacketEntry",
        back_populates="session",
        cascade="all, delete-orphan",
        order_by="PacketEntry.packet_num",
    )


class PacketEntry(Base):
    """Represents an individual dissected packet within an analysis session."""

    __tablename__ = "packet_entries"

    id = Column(Integer, primary_key=True, autoincrement=True)
    analysis_id = Column(String(36), ForeignKey("analysis_sessions.id", ondelete="CASCADE"), nullable=False, index=True)
    packet_num = Column(Integer, nullable=False)
    timestamp = Column(Float, nullable=False)
    timestamp_iso = Column(String(32), nullable=False)
    length = Column(Integer, nullable=False)

    # Layer 2
    src_mac = Column(String(24), nullable=True)
    dst_mac = Column(String(24), nullable=True)

    # Layer 3
    network_protocol = Column(String(16), nullable=True, index=True)
    src_ip = Column(String(64), nullable=True, index=True)
    dst_ip = Column(String(64), nullable=True, index=True)
    ip_version = Column(Integer, nullable=True)
    ttl = Column(Integer, nullable=True)

    # Layer 4
    transport_protocol = Column(String(16), nullable=True, index=True)
    src_port = Column(Integer, nullable=True, index=True)
    dst_port = Column(Integer, nullable=True, index=True)
    tcp_flags = Column(String(64), nullable=True)
    icmp_type = Column(Integer, nullable=True)
    icmp_code = Column(Integer, nullable=True)

    # Layer 7
    application_protocol = Column(String(16), nullable=True, index=True)
    dns_query = Column(String(255), nullable=True)
    dns_query_type = Column(String(16), nullable=True)

    # Overall Summary
    highest_protocol = Column(String(16), nullable=False, index=True)
    info = Column(Text, nullable=False)

    # Relationship back to parent session
    session = relationship("AnalysisSession", back_populates="packets")


# Composite indexes for high-speed filter queries
Index("idx_analysis_protocol", PacketEntry.analysis_id, PacketEntry.highest_protocol)
Index("idx_analysis_src_ip", PacketEntry.analysis_id, PacketEntry.src_ip)
Index("idx_analysis_dst_ip", PacketEntry.analysis_id, PacketEntry.dst_ip)
