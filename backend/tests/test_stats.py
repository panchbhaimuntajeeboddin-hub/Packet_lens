"""Unit tests for Pandas-based traffic statistics calculation."""

import pytest
from app.services.pcap_parser import parse_pcap_file
from app.services.statistics import calculate_traffic_statistics


def test_statistics_empty_packet_list():
    """Verifies that an empty packet list yields safe zeroed metrics without crashing."""
    stats = calculate_traffic_statistics([])
    assert stats.total_packets == 0
    assert stats.total_bytes == 0
    assert stats.duration_seconds == 0.0
    assert stats.avg_packet_size == 0.0
    assert stats.bitrate_bps == 0.0
    assert stats.protocol_distribution == {}
    assert stats.unique_ips == []
    assert stats.top_source_ips == []
    assert stats.top_destination_ips == []
    assert stats.top_conversations == []


def test_statistics_synthetic_pcap(synthetic_pcap_path):
    """Verifies end-to-end traffic statistics computation on synthetic packets."""
    packets = parse_pcap_file(synthetic_pcap_path)
    stats = calculate_traffic_statistics(packets, top_n=5)

    assert stats.total_packets == 11
    assert stats.total_bytes > 0
    assert stats.avg_packet_size > 0

    # Protocol distribution checks
    assert "ARP" in stats.protocol_distribution
    assert "DNS" in stats.protocol_distribution
    assert "ICMP" in stats.protocol_distribution
    assert "TCP" in stats.protocol_distribution or "HTTP" in stats.protocol_distribution

    # Percentages sum approximately to 100%
    pct_sum = sum(stats.protocol_percentages.values())
    assert 99.0 <= pct_sum <= 101.0

    # Unique IPs check
    assert "192.168.1.100" in stats.unique_ips
    assert "8.8.8.8" in stats.unique_ips
    assert "1.1.1.1" in stats.unique_ips
    assert "93.184.216.34" in stats.unique_ips
    assert stats.total_unique_ips >= 4

    # Top talkers check
    top_src_ips = [ep.ip for ep in stats.top_source_ips]
    assert "192.168.1.100" in top_src_ips

    # Conversations check
    assert len(stats.top_conversations) > 0
    conv_pairs = [(c.source_ip, c.destination_ip) for c in stats.top_conversations]
    assert ("192.168.1.100", "8.8.8.8") in conv_pairs or ("8.8.8.8", "192.168.1.100") in conv_pairs
