"""FastAPI API endpoints for PacketLens network traffic analysis."""

import csv
import io
import json
import logging
import os
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, status
from fastapi.responses import Response
from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.config import settings
from app.core.database import get_db
from app.models.capture import AnalysisSession, PacketEntry
from app.models.user import User
from app.schemas.api import (
    AnalyzeResponse,
    HealthResponse,
    PaginatedPacketsResponse,
)
from app.schemas.pcap import PacketRecord, TrafficStatistics
from app.services.pcap_parser import parse_pcap_file
from app.services.statistics import calculate_traffic_statistics
from app.services.validator import (
    CaptureValidationError,
    validate_capture_file,
)

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/health", response_model=HealthResponse, tags=["System"])
def get_health():
    """Returns the operational health and version status of the PacketLens API."""
    return HealthResponse(
        status="ok",
        app=settings.PROJECT_NAME,
        version=settings.VERSION,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


@router.post(
    "/analyze",
    response_model=AnalyzeResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Analysis"],
)
async def analyze_capture(
    file: UploadFile = File(..., description="PCAP or PCAPNG packet capture file"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Upload and analyze a network packet capture file (.pcap or .pcapng).

    Performs file validation, streaming packet dissection, statistical aggregation,
    and database storage. Automatically associates capture with the authenticated analyst.
    """
    if not file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No filename provided in upload.",
        )

    # Sanitize filename (prevent path traversal)
    clean_filename = Path(file.filename).name

    # Prepare isolated temporary directory for file processing
    upload_dir = Path(settings.TEMP_UPLOAD_DIR)
    upload_dir.mkdir(parents=True, exist_ok=True)
    temp_file_id = str(uuid.uuid4())
    temp_file_path = upload_dir / f"{temp_file_id}_{clean_filename}"

    file_size = 0
    try:
        # Stream file to disk in chunks to enforce size bounds
        with open(temp_file_path, "wb") as buffer:
            while chunk := await file.read(1024 * 64):  # 64 KB chunks
                file_size += len(chunk)
                if file_size > settings.MAX_UPLOAD_SIZE_BYTES:
                    max_mb = settings.MAX_UPLOAD_SIZE_BYTES / (1024 * 1024)
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail=f"Uploaded file exceeds maximum limit of {max_mb:.1f} MB.",
                    )
                buffer.write(chunk)

        # 1. Validate capture file header and format
        try:
            detected_format, validated_size = validate_capture_file(
                temp_file_path,
                max_size_bytes=settings.MAX_UPLOAD_SIZE_BYTES,
            )
        except CaptureValidationError as ve:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(ve),
            )

        # 2. Parse packet stream using Scapy engine
        try:
            dissected_packets = parse_pcap_file(temp_file_path)
        except Exception as pe:
            logger.error("Failed to parse packet capture: %s", pe, exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Unable to parse packet stream: {str(pe)}",
            )

        # 3. Compute Traffic Statistics with Pandas
        traffic_stats = calculate_traffic_statistics(dissected_packets)

        # 4. Persist Analysis Session in SQLite with authenticated ownership
        analysis_id = str(uuid.uuid4())
        session_record = AnalysisSession(
            id=analysis_id,
            owner_user_id=current_user.id,
            filename=clean_filename,
            file_format=detected_format,
            file_size_bytes=validated_size,
            created_at=datetime.now(timezone.utc),
            total_packets=traffic_stats.total_packets,
            total_bytes=traffic_stats.total_bytes,
            duration_seconds=traffic_stats.duration_seconds,
            statistics_json=traffic_stats.model_dump_json(),
        )
        db.add(session_record)

        # 5. Bulk insert dissected packet entries for indexed retrieval
        packet_entries = []
        for p in dissected_packets:
            flags_str = ",".join(p.tcp_flags) if p.tcp_flags else None
            packet_entries.append(
                PacketEntry(
                    analysis_id=analysis_id,
                    packet_num=p.packet_num,
                    timestamp=p.timestamp,
                    timestamp_iso=p.timestamp_iso,
                    length=p.length,
                    src_mac=p.src_mac,
                    dst_mac=p.dst_mac,
                    network_protocol=p.network_protocol,
                    src_ip=p.src_ip,
                    dst_ip=p.dst_ip,
                    ip_version=p.ip_version,
                    ttl=p.ttl,
                    transport_protocol=p.transport_protocol,
                    src_port=p.src_port,
                    dst_port=p.dst_port,
                    tcp_flags=flags_str,
                    icmp_type=p.icmp_type,
                    icmp_code=p.icmp_code,
                    application_protocol=p.application_protocol,
                    dns_query=p.dns_query,
                    dns_query_type=p.dns_query_type,
                    highest_protocol=p.highest_protocol,
                    info=p.info,
                )
            )

        if packet_entries:
            db.bulk_save_objects(packet_entries)
        db.commit()

        return AnalyzeResponse(
            analysis_id=session_record.id,
            filename=session_record.filename,
            file_format=session_record.file_format,
            file_size_bytes=session_record.file_size_bytes,
            total_packets=session_record.total_packets,
            total_bytes=session_record.total_bytes,
            duration_seconds=session_record.duration_seconds,
            created_at=session_record.created_at.isoformat(),
            statistics=traffic_stats,
        )

    finally:
        # Strictly ensure temporary file cleanup on completion or failure
        if temp_file_path.exists():
            try:
                temp_file_path.unlink()
            except Exception as e:
                logger.warning("Could not delete temporary file %s: %s", temp_file_path, e)


@router.get(
    "/analysis/{analysis_id}",
    response_model=dict,
    tags=["Analysis"],
)
def get_analysis_session(
    analysis_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Retrieves full analysis metadata and summary statistics for an authorized analyst."""
    session_record = (
        db.query(AnalysisSession)
        .filter(
            AnalysisSession.id == analysis_id,
            AnalysisSession.owner_user_id == current_user.id,
        )
        .first()
    )
    if not session_record:
        # Check if record exists for another user to distinguish or deny securely
        exists_for_other = db.query(AnalysisSession).filter(AnalysisSession.id == analysis_id).first()
        if exists_for_other:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: You do not own this analysis session.",
            )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis session '{analysis_id}' not found.",
        )

    stats_dict = json.loads(session_record.statistics_json)
    return {
        "analysis_id": session_record.id,
        "filename": session_record.filename,
        "file_format": session_record.file_format,
        "file_size_bytes": session_record.file_size_bytes,
        "total_packets": session_record.total_packets,
        "total_bytes": session_record.total_bytes,
        "duration_seconds": session_record.duration_seconds,
        "created_at": session_record.created_at.isoformat(),
        "statistics": stats_dict,
    }


@router.get(
    "/analysis/{analysis_id}/statistics",
    response_model=TrafficStatistics,
    tags=["Analysis"],
)
def get_analysis_statistics(
    analysis_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Retrieves computed traffic statistics and protocol distributions for an analysis session."""
    session_record = (
        db.query(AnalysisSession)
        .filter(
            AnalysisSession.id == analysis_id,
            AnalysisSession.owner_user_id == current_user.id,
        )
        .first()
    )
    if not session_record:
        exists_for_other = db.query(AnalysisSession).filter(AnalysisSession.id == analysis_id).first()
        if exists_for_other:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: You do not own this analysis session.",
            )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis session '{analysis_id}' not found.",
        )

    stats_dict = json.loads(session_record.statistics_json)
    return TrafficStatistics(**stats_dict)


@router.get(
    "/analysis/{analysis_id}/packets",
    response_model=PaginatedPacketsResponse,
    tags=["Analysis"],
)
def get_analysis_packets(
    analysis_id: str,
    page: int = Query(1, ge=1, description="Page number (1-based)"),
    page_size: int = Query(50, ge=1, le=500, description="Items per page (max 500)"),
    protocol: Optional[str] = Query(None, description="Filter by protocol (e.g. TCP, UDP, DNS, ICMP, ARP)"),
    ip: Optional[str] = Query(None, description="Filter by Source or Destination IP address"),
    port: Optional[int] = Query(None, description="Filter by Source or Destination Port"),
    search: Optional[str] = Query(None, description="Full-text search in packet summary info or query domain"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Retrieves paginated dissected packets with real-time filtering options.
    Strictly verifies authenticated ownership before returning packet entries.
    """
    session_record = (
        db.query(AnalysisSession)
        .filter(
            AnalysisSession.id == analysis_id,
            AnalysisSession.owner_user_id == current_user.id,
        )
        .first()
    )
    if not session_record:
        exists_for_other = db.query(AnalysisSession).filter(AnalysisSession.id == analysis_id).first()
        if exists_for_other:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: You do not own this analysis session.",
            )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis session '{analysis_id}' not found.",
        )

    query = db.query(PacketEntry).filter(PacketEntry.analysis_id == analysis_id)

    # Protocol filter (case-insensitive)
    if protocol:
        clean_proto = protocol.strip().upper()
        query = query.filter(
            or_(
                PacketEntry.highest_protocol == clean_proto,
                PacketEntry.transport_protocol == clean_proto,
                PacketEntry.application_protocol == clean_proto,
                PacketEntry.network_protocol == clean_proto,
            )
        )

    # IP address filter (matches either src or dst)
    if ip:
        clean_ip = ip.strip()
        query = query.filter(
            or_(
                PacketEntry.src_ip == clean_ip,
                PacketEntry.dst_ip == clean_ip,
            )
        )

    # Port filter (matches either src or dst)
    if port is not None:
        query = query.filter(
            or_(
                PacketEntry.src_port == port,
                PacketEntry.dst_port == port,
            )
        )

    # Search query
    if search:
        search_pattern = f"%{search.strip()}%"
        query = query.filter(
            or_(
                PacketEntry.info.ilike(search_pattern),
                PacketEntry.dns_query.ilike(search_pattern),
                PacketEntry.src_ip.ilike(search_pattern),
                PacketEntry.dst_ip.ilike(search_pattern),
            )
        )

    total_matched = query.count()
    total_pages = max(1, (total_matched + page_size - 1) // page_size)

    # Apply pagination and ordering
    packet_entries = (
        query.order_by(PacketEntry.packet_num)
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    # Convert ORM models to Pydantic PacketRecords
    records: List[PacketRecord] = []
    for pe in packet_entries:
        flags_list = pe.tcp_flags.split(",") if pe.tcp_flags else None
        records.append(
            PacketRecord(
                packet_num=pe.packet_num,
                timestamp=pe.timestamp,
                timestamp_iso=pe.timestamp_iso,
                length=pe.length,
                src_mac=pe.src_mac,
                dst_mac=pe.dst_mac,
                network_protocol=pe.network_protocol,
                src_ip=pe.src_ip,
                dst_ip=pe.dst_ip,
                ip_version=pe.ip_version,
                ttl=pe.ttl,
                transport_protocol=pe.transport_protocol,
                src_port=pe.src_port,
                dst_port=pe.dst_port,
                tcp_flags=flags_list,
                icmp_type=pe.icmp_type,
                icmp_code=pe.icmp_code,
                application_protocol=pe.application_protocol,
                dns_query=pe.dns_query,
                dns_query_type=pe.dns_query_type,
                highest_protocol=pe.highest_protocol,
                info=pe.info,
            )
        )

    return PaginatedPacketsResponse(
        analysis_id=analysis_id,
        page=page,
        page_size=page_size,
        total_matched=total_matched,
        total_pages=total_pages,
        packets=records,
    )


@router.get(
    "/analysis/{analysis_id}/export",
    tags=["Analysis"],
)
def export_analysis_csv(
    analysis_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Exports all dissected packets for an authorized session as a downloadable CSV file."""
    session_record = (
        db.query(AnalysisSession)
        .filter(
            AnalysisSession.id == analysis_id,
            AnalysisSession.owner_user_id == current_user.id,
        )
        .first()
    )
    if not session_record:
        exists_for_other = db.query(AnalysisSession).filter(AnalysisSession.id == analysis_id).first()
        if exists_for_other:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: You do not own this analysis session.",
            )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis session '{analysis_id}' not found.",
        )

    packets = (
        db.query(PacketEntry)
        .filter(PacketEntry.analysis_id == analysis_id)
        .order_by(PacketEntry.packet_num)
        .all()
    )

    # Generate CSV in-memory
    output = io.StringIO()
    writer = csv.writer(output)

    # CSV Header Row
    writer.writerow([
        "Packet #",
        "Timestamp (ISO)",
        "Length (Bytes)",
        "Highest Protocol",
        "Network Protocol",
        "Source IP",
        "Source Port",
        "Destination IP",
        "Destination Port",
        "Transport Protocol",
        "TCP Flags",
        "Info",
    ])

    for p in packets:
        writer.writerow([
            p.packet_num,
            p.timestamp_iso,
            p.length,
            p.highest_protocol,
            p.network_protocol or "",
            p.src_ip or p.src_mac or "",
            p.src_port or "",
            p.dst_ip or p.dst_mac or "",
            p.dst_port or "",
            p.transport_protocol or "",
            p.tcp_flags or "",
            p.info,
        ])

    csv_data = output.getvalue()
    filename_prefix = Path(session_record.filename).stem
    download_name = f"packetlens_{filename_prefix}_{analysis_id[:8]}.csv"

    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="{download_name}"',
            "Content-Type": "text/csv; charset=utf-8",
        },
    )


@router.delete(
    "/analysis/{analysis_id}",
    tags=["Analysis"],
)
def delete_analysis_session(
    analysis_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Deletes an analysis session and its dissected packet entries.
    Strictly verifies that the authenticated user owns the record.
    """
    session_record = db.query(AnalysisSession).filter(AnalysisSession.id == analysis_id).first()
    if not session_record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis session '{analysis_id}' not found.",
        )

    if session_record.owner_user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: You do not have permission to delete this analysis session.",
        )

    db.delete(session_record)
    db.commit()
    logger.info("Analyst %s deleted capture session %s", current_user.email, analysis_id)

    return {
        "message": "Capture analysis session deleted successfully.",
        "analysis_id": analysis_id,
    }


@router.get(
    "/analyses",
    response_model=List[dict],
    tags=["Analysis"],
)
def list_analysis_sessions(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Lists analyzed capture sessions belonging exclusively to the authenticated user."""
    sessions = (
        db.query(AnalysisSession)
        .filter(AnalysisSession.owner_user_id == current_user.id)
        .order_by(AnalysisSession.created_at.desc())
        .limit(50)
        .all()
    )
    return [
        {
            "analysis_id": s.id,
            "filename": s.filename,
            "file_format": s.file_format,
            "file_size_bytes": s.file_size_bytes,
            "total_packets": s.total_packets,
            "total_bytes": s.total_bytes,
            "duration_seconds": s.duration_seconds,
            "created_at": s.created_at.isoformat(),
        }
        for s in sessions
    ]


@router.get(
    "/dashboard/stats",
    tags=["Dashboard"],
)
def get_user_dashboard_statistics(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Computes aggregated executive dashboard metrics strictly across the
    authenticated user's own private captures.
    """
    # 1. Total uploads count
    total_uploads = (
        db.query(AnalysisSession)
        .filter(AnalysisSession.owner_user_id == current_user.id)
        .count()
    )

    # 2. Total packets analyzed
    total_packets = (
        db.query(func.coalesce(func.sum(AnalysisSession.total_packets), 0))
        .filter(AnalysisSession.owner_user_id == current_user.id)
        .scalar()
    )

    # 3. Total bytes analyzed
    total_bytes = (
        db.query(func.coalesce(func.sum(AnalysisSession.total_bytes), 0))
        .filter(AnalysisSession.owner_user_id == current_user.id)
        .scalar()
    )

    # 4. Total duration analyzed
    total_duration = (
        db.query(func.coalesce(func.sum(AnalysisSession.duration_seconds), 0.0))
        .filter(AnalysisSession.owner_user_id == current_user.id)
        .scalar()
    )

    # 5. Recent uploads
    recent_sessions = (
        db.query(AnalysisSession)
        .filter(AnalysisSession.owner_user_id == current_user.id)
        .order_by(AnalysisSession.created_at.desc())
        .limit(10)
        .all()
    )

    recent_uploads_data = [
        {
            "analysis_id": s.id,
            "filename": s.filename,
            "file_format": s.file_format,
            "file_size_bytes": s.file_size_bytes,
            "total_packets": s.total_packets,
            "total_bytes": s.total_bytes,
            "duration_seconds": s.duration_seconds,
            "created_at": s.created_at.isoformat(),
        }
        for s in recent_sessions
    ]

    return {
        "user": {
            "id": current_user.id,
            "full_name": current_user.full_name,
            "email": current_user.email,
        },
        "total_uploads": int(total_uploads),
        "total_packets": int(total_packets),
        "total_bytes": int(total_bytes),
        "total_duration_seconds": float(total_duration),
        "recent_uploads": recent_uploads_data,
    }
