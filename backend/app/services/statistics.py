"""Statistical analysis engine using Pandas for computing traffic metrics from packet records."""

from typing import List
import pandas as pd

from app.schemas.pcap import (
    ConversationStatistic,
    EndpointStatistic,
    PacketRecord,
    TrafficStatistics,
)


def calculate_traffic_statistics(packets: List[PacketRecord], top_n: int = 5) -> TrafficStatistics:
    """
    Computes summary traffic metrics, protocol distribution, and endpoint analytics
    from a collection of dissected PacketRecord objects.

    Handles empty captures safely without ZeroDivisionError.
    """
    if not packets:
        return TrafficStatistics(
            total_packets=0,
            total_bytes=0,
            capture_start_time=None,
            capture_end_time=None,
            duration_seconds=0.0,
            avg_packet_size=0.0,
            bitrate_bps=0.0,
            protocol_distribution={},
            protocol_percentages={},
            unique_ips=[],
            total_unique_ips=0,
            top_source_ips=[],
            top_destination_ips=[],
            top_conversations=[],
        )

    # Convert packet records to a Pandas DataFrame for vectorized analytics
    records = [p.model_dump() for p in packets]
    df = pd.DataFrame(records)

    total_packets = len(df)
    total_bytes = int(df["length"].sum())

    # Time metrics
    min_ts = float(df["timestamp"].min())
    max_ts = float(df["timestamp"].max())
    duration_seconds = max(0.0, max_ts - min_ts)

    start_iso = df.loc[df["timestamp"].idxmin()]["timestamp_iso"] if total_packets > 0 else None
    end_iso = df.loc[df["timestamp"].idxmax()]["timestamp_iso"] if total_packets > 0 else None

    avg_packet_size = round(total_bytes / total_packets, 2) if total_packets > 0 else 0.0
    bitrate_bps = (
        round((total_bytes * 8.0) / duration_seconds, 2)
        if duration_seconds > 0.0
        else 0.0
    )

    # Protocol breakdown
    protocol_counts = df["highest_protocol"].value_counts().to_dict()
    protocol_distribution = {str(k): int(v) for k, v in protocol_counts.items()}
    protocol_percentages = {
        str(k): round((int(v) / total_packets) * 100.0, 2)
        for k, v in protocol_counts.items()
    }

    # Unique IPs extraction
    src_ips = set(df["src_ip"].dropna())
    dst_ips = set(df["dst_ip"].dropna())
    all_ips = sorted(list(src_ips.union(dst_ips)))
    total_unique_ips = len(all_ips)

    # Top Source IPs
    top_source_ips: List[EndpointStatistic] = []
    if "src_ip" in df.columns:
        src_df = df[df["src_ip"].notna()]
        if not src_df.empty:
            src_grouped = (
                src_df.groupby("src_ip")
                .agg(packet_count=("packet_num", "count"), byte_count=("length", "sum"))
                .reset_index()
                .sort_values(by=["packet_count", "byte_count"], ascending=False)
                .head(top_n)
            )
            for _, row in src_grouped.iterrows():
                top_source_ips.append(
                    EndpointStatistic(
                        ip=str(row["src_ip"]),
                        packet_count=int(row["packet_count"]),
                        byte_count=int(row["byte_count"]),
                        percentage_packets=round((int(row["packet_count"]) / total_packets) * 100.0, 2),
                        percentage_bytes=round((int(row["byte_count"]) / total_bytes) * 100.0, 2) if total_bytes > 0 else 0.0,
                    )
                )

    # Top Destination IPs
    top_destination_ips: List[EndpointStatistic] = []
    if "dst_ip" in df.columns:
        dst_df = df[df["dst_ip"].notna()]
        if not dst_df.empty:
            dst_grouped = (
                dst_df.groupby("dst_ip")
                .agg(packet_count=("packet_num", "count"), byte_count=("length", "sum"))
                .reset_index()
                .sort_values(by=["packet_count", "byte_count"], ascending=False)
                .head(top_n)
            )
            for _, row in dst_grouped.iterrows():
                top_destination_ips.append(
                    EndpointStatistic(
                        ip=str(row["dst_ip"]),
                        packet_count=int(row["packet_count"]),
                        byte_count=int(row["byte_count"]),
                        percentage_packets=round((int(row["packet_count"]) / total_packets) * 100.0, 2),
                        percentage_bytes=round((int(row["byte_count"]) / total_bytes) * 100.0, 2) if total_bytes > 0 else 0.0,
                    )
                )

    # Top Conversations (Source -> Destination pairs)
    top_conversations: List[ConversationStatistic] = []
    conv_df = df[df["src_ip"].notna() & df["dst_ip"].notna()]
    if not conv_df.empty:
        conv_grouped = (
            conv_df.groupby(["src_ip", "dst_ip"])
            .agg(packet_count=("packet_num", "count"), byte_count=("length", "sum"))
            .reset_index()
            .sort_values(by=["packet_count", "byte_count"], ascending=False)
            .head(top_n)
        )
        for _, row in conv_grouped.iterrows():
            top_conversations.append(
                ConversationStatistic(
                    source_ip=str(row["src_ip"]),
                    destination_ip=str(row["dst_ip"]),
                    packet_count=int(row["packet_count"]),
                    byte_count=int(row["byte_count"]),
                )
            )

    return TrafficStatistics(
        total_packets=total_packets,
        total_bytes=total_bytes,
        capture_start_time=start_iso,
        capture_end_time=end_iso,
        duration_seconds=duration_seconds,
        avg_packet_size=avg_packet_size,
        bitrate_bps=bitrate_bps,
        protocol_distribution=protocol_distribution,
        protocol_percentages=protocol_percentages,
        unique_ips=all_ips,
        total_unique_ips=total_unique_ips,
        top_source_ips=top_source_ips,
        top_destination_ips=top_destination_ips,
        top_conversations=top_conversations,
    )
