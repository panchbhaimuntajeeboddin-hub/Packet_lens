"""Pydantic schemas for REST API requests and responses."""

from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field

from app.schemas.pcap import PacketRecord, TrafficStatistics


class HealthResponse(BaseModel):
    """API health status response."""
    status: str = Field("ok", description="Operational status")
    app: str = Field("PacketLens", description="Application name")
    version: str = Field("0.1.0", description="Application version")
    timestamp: str


class AnalyzeResponse(BaseModel):
    """Response returned upon successful PCAP upload and analysis."""
    analysis_id: str = Field(..., description="Unique UUID for this analysis session")
    filename: str = Field(..., description="Sanitized original filename")
    file_format: str = Field(..., description="Detected format: PCAP or PCAPNG")
    file_size_bytes: int = Field(..., description="File size in bytes")
    total_packets: int = Field(..., description="Number of packets analyzed")
    total_bytes: int = Field(..., description="Total volume in bytes")
    duration_seconds: float = Field(..., description="Duration of the packet capture")
    created_at: str = Field(..., description="ISO timestamp when capture was analyzed")
    statistics: TrafficStatistics = Field(..., description="Aggregated traffic metrics")


class PaginatedPacketsResponse(BaseModel):
    """Paginated list of dissected packet records with query metadata."""
    analysis_id: str
    page: int = Field(..., ge=1, description="Current page number (1-based)")
    page_size: int = Field(..., ge=1, le=1000, description="Items per page")
    total_matched: int = Field(..., description="Total packets matching current filters")
    total_pages: int = Field(..., description="Total pages available")
    packets: List[PacketRecord] = Field(default_factory=list, description="Dissected packet list for current page")
