"""Unit tests for Scapy-based streaming packet parser."""

import pytest
from app.services.pcap_parser import parse_pcap_file, parse_packets_stream


def test_parse_synthetic_pcap_count(synthetic_pcap_path):
    """Verifies that all 11 synthetic packets are extracted accurately."""
    packets = parse_pcap_file(synthetic_pcap_path)
    assert len(packets) == 11
    # Check that sequence numbering is 1-indexed and sequential
    assert [p.packet_num for p in packets] == list(range(1, 12))


def test_parse_arp_packets(synthetic_pcap_path):
    """Verifies dissection of ARP Request and ARP Reply."""
    packets = parse_pcap_file(synthetic_pcap_path)
    arp_packets = [p for p in packets if p.network_protocol == "ARP"]
    assert len(arp_packets) == 2

    # ARP Request
    req = arp_packets[0]
    assert req.highest_protocol == "ARP"
    assert req.src_ip == "192.168.1.100"
    assert req.dst_ip == "192.168.1.1"
    assert "Who has 192.168.1.1" in req.info

    # ARP Reply
    reply = arp_packets[1]
    assert reply.highest_protocol == "ARP"
    assert reply.src_ip == "192.168.1.1"
    assert reply.dst_ip == "192.168.1.100"
    assert "192.168.1.1 is at" in reply.info


def test_parse_dns_packets(synthetic_pcap_path):
    """Verifies DNS query and response dissection."""
    packets = parse_pcap_file(synthetic_pcap_path)
    dns_packets = [p for p in packets if p.application_protocol == "DNS"]
    assert len(dns_packets) == 2

    query = dns_packets[0]
    assert query.highest_protocol == "DNS"
    assert query.dns_query == "example.com"
    assert query.dns_query_type == "A"
    assert query.src_port == 54321
    assert query.dst_port == 53
    assert "Standard query" in query.info

    resp = dns_packets[1]
    assert resp.highest_protocol == "DNS"
    assert resp.src_ip == "8.8.8.8"
    assert resp.dst_ip == "192.168.1.100"
    assert "Standard query response" in resp.info


def test_parse_tcp_flags_and_handshake(synthetic_pcap_path):
    """Verifies TCP 3-way handshake dissection and TCP flags decoding."""
    packets = parse_pcap_file(synthetic_pcap_path)
    # Packets 5, 6, 7 are SYN, SYN-ACK, ACK
    syn = packets[4]
    assert syn.transport_protocol == "TCP"
    assert syn.tcp_flags == ["SYN"]
    assert syn.src_port == 49152
    assert syn.dst_port == 80

    syn_ack = packets[5]
    assert syn_ack.transport_protocol == "TCP"
    assert "SYN" in syn_ack.tcp_flags
    assert "ACK" in syn_ack.tcp_flags

    ack = packets[6]
    assert ack.transport_protocol == "TCP"
    assert ack.tcp_flags == ["ACK"]


def test_parse_http_packet(synthetic_pcap_path):
    """Verifies HTTP GET request detection."""
    packets = parse_pcap_file(synthetic_pcap_path)
    http_packets = [p for p in packets if p.application_protocol == "HTTP"]
    assert len(http_packets) >= 1
    http = http_packets[0]
    assert http.transport_protocol == "TCP"
    assert http.dst_port == 80


def test_parse_icmp_ping_pong(synthetic_pcap_path):
    """Verifies ICMP echo request and reply."""
    packets = parse_pcap_file(synthetic_pcap_path)
    icmp_packets = [p for p in packets if p.transport_protocol == "ICMP"]
    assert len(icmp_packets) == 2

    ping = icmp_packets[0]
    assert ping.highest_protocol == "ICMP"
    assert ping.icmp_type == 8  # Echo Request
    assert ping.icmp_code == 0
    assert "request" in ping.info.lower()

    pong = icmp_packets[1]
    assert pong.highest_protocol == "ICMP"
    assert pong.icmp_type == 0  # Echo Reply
    assert pong.icmp_code == 0
    assert "reply" in pong.info.lower()


def test_parse_ipv6_packet(synthetic_pcap_path):
    """Verifies IPv6 network layer dissection."""
    packets = parse_pcap_file(synthetic_pcap_path)
    ipv6_packets = [p for p in packets if p.network_protocol == "IPv6"]
    assert len(ipv6_packets) == 1
    p6 = ipv6_packets[0]
    assert p6.ip_version == 6
    assert p6.src_ip == "2001:db8::1"
    assert p6.dst_ip == "2001:db8::2"


def test_parse_streaming_limit(synthetic_pcap_path):
    """Verifies that max_packets limits the parsed output stream."""
    stream_packets = list(parse_packets_stream(synthetic_pcap_path, max_packets=4))
    assert len(stream_packets) == 4
    assert stream_packets[-1].packet_num == 4


def test_parse_empty_pcap(empty_pcap_path):
    """Verifies that a valid PCAP file with 0 packets returns an empty list without error."""
    packets = parse_pcap_file(empty_pcap_path)
    assert packets == []
