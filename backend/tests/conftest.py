"""Pytest fixtures for generating synthetic, authorized network packet captures."""

import os
import tempfile
import pytest
from scapy.all import wrpcap
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.dns import DNS, DNSQR, DNSRR


def generate_synthetic_packets():
    """Generates a diverse set of synthetic network packets covering L2, L3, L4, and L7."""
    packets = []

    # 1. ARP Request & Reply
    arp_req = Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=1,
        hwsrc="00:11:22:33:44:55",
        psrc="192.168.1.100",
        hwdst="00:00:00:00:00:00",
        pdst="192.168.1.1",
    )
    arp_rep = Ether(src="aa:bb:cc:dd:ee:ff", dst="00:11:22:33:44:55") / ARP(
        op=2,
        hwsrc="aa:bb:cc:dd:ee:ff",
        psrc="192.168.1.1",
        hwdst="00:11:22:33:44:55",
        pdst="192.168.1.100",
    )
    packets.extend([arp_req, arp_rep])

    # 2. DNS Query (UDP port 53)
    dns_query = (
        Ether(src="00:11:22:33:44:55", dst="aa:bb:cc:dd:ee:ff")
        / IP(src="192.168.1.100", dst="8.8.8.8")
        / UDP(sport=54321, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="example.com", qtype="A"))
    )
    # DNS Response
    dns_resp = (
        Ether(src="aa:bb:cc:dd:ee:ff", dst="00:11:22:33:44:55")
        / IP(src="8.8.8.8", dst="192.168.1.100")
        / UDP(sport=53, dport=54321)
        / DNS(
            qr=1,
            aa=1,
            qd=DNSQR(qname="example.com", qtype="A"),
            an=DNSRR(rrname="example.com", type="A", rdata="93.184.216.34", ttl=300),
        )
    )
    packets.extend([dns_query, dns_resp])

    # 3. TCP 3-Way Handshake
    syn = (
        Ether(src="00:11:22:33:44:55", dst="aa:bb:cc:dd:ee:ff")
        / IP(src="192.168.1.100", dst="93.184.216.34")
        / TCP(sport=49152, dport=80, flags="S", seq=1000)
    )
    syn_ack = (
        Ether(src="aa:bb:cc:dd:ee:ff", dst="00:11:22:33:44:55")
        / IP(src="93.184.216.34", dst="192.168.1.100")
        / TCP(sport=80, dport=49152, flags="SA", seq=5000, ack=1001)
    )
    ack = (
        Ether(src="00:11:22:33:44:55", dst="aa:bb:cc:dd:ee:ff")
        / IP(src="192.168.1.100", dst="93.184.216.34")
        / TCP(sport=49152, dport=80, flags="A", seq=1001, ack=5001)
    )
    packets.extend([syn, syn_ack, ack])

    # 4. HTTP GET Request over TCP
    http_get = (
        Ether(src="00:11:22:33:44:55", dst="aa:bb:cc:dd:ee:ff")
        / IP(src="192.168.1.100", dst="93.184.216.34")
        / TCP(sport=49152, dport=80, flags="PA", seq=1001, ack=5001)
        / b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: PacketLens/1.0\r\n\r\n"
    )
    packets.append(http_get)

    # 5. ICMP Echo Request (Ping) and Reply
    icmp_ping = (
        Ether(src="00:11:22:33:44:55", dst="aa:bb:cc:dd:ee:ff")
        / IP(src="192.168.1.100", dst="1.1.1.1")
        / ICMP(type=8, code=0, id=1, seq=1)
    )
    icmp_reply = (
        Ether(src="aa:bb:cc:dd:ee:ff", dst="00:11:22:33:44:55")
        / IP(src="1.1.1.1", dst="192.168.1.100")
        / ICMP(type=0, code=0, id=1, seq=1)
    )
    packets.extend([icmp_ping, icmp_reply])

    # 6. IPv6 TCP packet
    ipv6_pkt = (
        Ether(src="00:11:22:33:44:55", dst="aa:bb:cc:dd:ee:ff")
        / IPv6(src="2001:db8::1", dst="2001:db8::2")
        / TCP(sport=50000, dport=443, flags="S", seq=10)
    )
    packets.append(ipv6_pkt)

    return packets


@pytest.fixture(scope="session")
def synthetic_capture_packets():
    """Pytest fixture returning the synthetic packets."""
    return generate_synthetic_packets()


@pytest.fixture
def synthetic_pcap_path(synthetic_capture_packets, tmp_path):
    """Writes synthetic packets to a temporary .pcap file."""
    pcap_file = tmp_path / "synthetic_test.pcap"
    wrpcap(str(pcap_file), synthetic_capture_packets)
    return pcap_file


@pytest.fixture
def empty_pcap_path(tmp_path):
    """Writes an empty .pcap file (valid PCAP header, but 0 packets)."""
    pcap_file = tmp_path / "empty_valid.pcap"
    wrpcap(str(pcap_file), [])
    return pcap_file


@pytest.fixture
def corrupted_file_path(tmp_path):
    """Creates a corrupted file with .pcap extension but non-PCAP content."""
    corrupted_file = tmp_path / "corrupted.pcap"
    corrupted_file.write_bytes(b"This is completely invalid non-pcap raw text content.")
    return corrupted_file


@pytest.fixture
def zero_byte_file_path(tmp_path):
    """Creates a 0-byte file."""
    zero_file = tmp_path / "zero_bytes.pcap"
    zero_file.write_bytes(b"")
    return zero_file
