import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator, List, Optional
import scapy.all as scapy_all

# Suppress benign Scapy runtime warnings about libpcap (offline PCAP reading does not require Npcap)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
scapy_all.conf.verb = 0

from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6EchoReply
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.packet import Packet
from scapy.utils import PcapReader

from app.schemas.pcap import PacketRecord

# Standard DNS Query Types mapping
DNS_QTYPES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    255: "ANY",
}

# TCP Flag mapping
TCP_FLAG_MAP = {
    "F": "FIN",
    "S": "SYN",
    "R": "RST",
    "P": "PSH",
    "A": "ACK",
    "U": "URG",
    "E": "ECE",
    "C": "CWR",
}


def _extract_tcp_flags(tcp_layer: TCP) -> List[str]:
    """Decodes TCP flags into human-readable list (e.g. ['SYN', 'ACK'])."""
    flags = []
    flag_str = str(tcp_layer.flags)
    for char, name in TCP_FLAG_MAP.items():
        if char in flag_str:
            flags.append(name)
    return flags


def _build_info_summary(
    record: dict,
    pkt: Packet,
    dns_layer: Optional[DNS] = None,
    tcp_layer: Optional[TCP] = None,
    udp_layer: Optional[UDP] = None,
    icmp_layer: Optional[ICMP] = None,
    arp_layer: Optional[ARP] = None,
) -> str:
    """Constructs a concise, readable summary line for the packet."""
    if dns_layer:
        qd = None
        if dns_layer.qd:
            try:
                qd = dns_layer.qd[0] if hasattr(dns_layer.qd, "__getitem__") else dns_layer.qd
            except Exception:
                qd = dns_layer.qd

        if dns_layer.qr == 0 and qd:
            # Query
            qname = qd.qname.decode("utf-8", errors="replace") if hasattr(qd.qname, "decode") else str(qd.qname)
            qtype = DNS_QTYPES.get(qd.qtype, str(qd.qtype))
            return f"Standard query {hex(dns_layer.id)} {qtype} {qname.rstrip('.')}"
        elif dns_layer.qr == 1:
            # Response
            rcode_desc = "NoError" if dns_layer.rcode == 0 else f"RCode={dns_layer.rcode}"
            ancount = dns_layer.ancount
            return f"Standard query response {hex(dns_layer.id)} {rcode_desc} (Answers: {ancount})"

    if arp_layer:
        op = "Who has " if arp_layer.op == 1 else "Is at "
        if arp_layer.op == 1:
            return f"Who has {arp_layer.pdst}? Tell {arp_layer.psrc}"
        elif arp_layer.op == 2:
            return f"{arp_layer.psrc} is at {arp_layer.hwsrc}"
        return f"ARP opcode {arp_layer.op}"

    if icmp_layer:
        type_names = {
            0: "Echo (ping) reply",
            3: "Destination unreachable",
            8: "Echo (ping) request",
            11: "Time-to-live exceeded",
        }
        name = type_names.get(icmp_layer.type, f"Type {icmp_layer.type}")
        return f"ICMP {name} (code={icmp_layer.code})"

    if tcp_layer:
        flags_str = ", ".join(record.get("tcp_flags") or [])
        flags_repr = f"[{flags_str}]" if flags_str else ""
        return f"{record.get('src_port')} -> {record.get('dst_port')} {flags_repr} Seq={tcp_layer.seq} Ack={tcp_layer.ack} Win={tcp_layer.window}".strip()

    if udp_layer:
        return f"{record.get('src_port')} -> {record.get('dst_port')} Len={udp_layer.len}"

    if record.get("network_protocol"):
        return f"{record.get('network_protocol')} packet from {record.get('src_ip')} to {record.get('dst_ip')}"

    return "Raw / Unrecognized frame"


def dissect_packet(pkt: Packet, packet_num: int) -> PacketRecord:
    """
    Dissects a single Scapy packet into a structured PacketRecord.

    Extracts Layer 2, Layer 3, Layer 4, and Layer 7 protocol metadata.
    """
    ts = float(pkt.time)
    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    ts_iso = dt.isoformat()
    length = len(pkt)

    rec: dict = {
        "packet_num": packet_num,
        "timestamp": ts,
        "timestamp_iso": ts_iso,
        "length": length,
        "src_mac": None,
        "dst_mac": None,
        "network_protocol": None,
        "src_ip": None,
        "dst_ip": None,
        "ip_version": None,
        "ttl": None,
        "transport_protocol": None,
        "src_port": None,
        "dst_port": None,
        "tcp_flags": None,
        "icmp_type": None,
        "icmp_code": None,
        "application_protocol": None,
        "dns_query": None,
        "dns_query_type": None,
        "highest_protocol": "Unknown",
        "info": "",
    }

    # Layer 2: Ethernet
    if Ether in pkt:
        rec["src_mac"] = pkt[Ether].src
        rec["dst_mac"] = pkt[Ether].dst
        rec["highest_protocol"] = "Ethernet"

    # Layer 2/3: ARP
    arp_layer = pkt[ARP] if ARP in pkt else None
    if arp_layer:
        rec["network_protocol"] = "ARP"
        rec["src_ip"] = arp_layer.psrc
        rec["dst_ip"] = arp_layer.pdst
        rec["src_mac"] = arp_layer.hwsrc
        rec["dst_mac"] = arp_layer.hwdst
        rec["highest_protocol"] = "ARP"

    # Layer 3: IPv4
    elif IP in pkt:
        ip = pkt[IP]
        rec["network_protocol"] = "IPv4"
        rec["ip_version"] = 4
        rec["src_ip"] = ip.src
        rec["dst_ip"] = ip.dst
        rec["ttl"] = ip.ttl
        rec["highest_protocol"] = "IPv4"

    # Layer 3: IPv6
    elif IPv6 in pkt:
        ip6 = pkt[IPv6]
        rec["network_protocol"] = "IPv6"
        rec["ip_version"] = 6
        rec["src_ip"] = ip6.src
        rec["dst_ip"] = ip6.dst
        rec["ttl"] = ip6.hlim
        rec["highest_protocol"] = "IPv6"

    # Layer 4: Transport Protocols
    tcp_layer = pkt[TCP] if TCP in pkt else None
    udp_layer = pkt[UDP] if UDP in pkt else None
    icmp_layer = pkt[ICMP] if ICMP in pkt else None

    if tcp_layer:
        rec["transport_protocol"] = "TCP"
        rec["src_port"] = tcp_layer.sport
        rec["dst_port"] = tcp_layer.dport
        rec["tcp_flags"] = _extract_tcp_flags(tcp_layer)
        rec["highest_protocol"] = "TCP"
    elif udp_layer:
        rec["transport_protocol"] = "UDP"
        rec["src_port"] = udp_layer.sport
        rec["dst_port"] = udp_layer.dport
        rec["highest_protocol"] = "UDP"
    elif icmp_layer:
        rec["transport_protocol"] = "ICMP"
        rec["icmp_type"] = icmp_layer.type
        rec["icmp_code"] = icmp_layer.code
        rec["highest_protocol"] = "ICMP"
    elif ICMPv6EchoRequest in pkt or ICMPv6EchoReply in pkt:
        rec["transport_protocol"] = "ICMPv6"
        rec["highest_protocol"] = "ICMPv6"

    # Layer 7: Application Protocols
    dns_layer = pkt[DNS] if DNS in pkt else None
    if dns_layer:
        rec["application_protocol"] = "DNS"
        rec["highest_protocol"] = "DNS"
        if dns_layer.qd:
            try:
                qd = dns_layer.qd[0] if hasattr(dns_layer.qd, "__getitem__") else dns_layer.qd
                qname = qd.qname
                rec["dns_query"] = (
                    qname.decode("utf-8", errors="replace").rstrip(".")
                    if hasattr(qname, "decode")
                    else str(qname).rstrip(".")
                )
                rec["dns_query_type"] = DNS_QTYPES.get(qd.qtype, str(qd.qtype))
            except Exception:
                rec["dns_query"] = None

    # HTTP detection heuristic (payload inspection or port 80/8080)
    elif rec["transport_protocol"] == "TCP" and (rec["src_port"] in (80, 8080) or rec["dst_port"] in (80, 8080)):
        rec["application_protocol"] = "HTTP"
        rec["highest_protocol"] = "HTTP"

    rec["info"] = _build_info_summary(
        record=rec,
        pkt=pkt,
        dns_layer=dns_layer,
        tcp_layer=tcp_layer,
        udp_layer=udp_layer,
        icmp_layer=icmp_layer,
        arp_layer=arp_layer,
    )

    return PacketRecord(**rec)


def parse_packets_stream(
    file_path: str | Path,
    max_packets: Optional[int] = None
) -> Generator[PacketRecord, None, None]:
    """
    Streamingly parses packets from a .pcap or .pcapng file without loading the entire
    file into memory at once.

    Yields:
        PacketRecord for each successfully parsed packet.
    """
    path_str = str(file_path)
    count = 0

    with PcapReader(path_str) as reader:
        for pkt in reader:
            count += 1
            try:
                yield dissect_packet(pkt, count)
            except Exception as e:
                # Dissection error on malformed packet: produce fallback record
                ts = float(pkt.time) if hasattr(pkt, "time") else 0.0
                dt = datetime.fromtimestamp(ts, tz=timezone.utc)
                yield PacketRecord(
                    packet_num=count,
                    timestamp=ts,
                    timestamp_iso=dt.isoformat(),
                    length=len(pkt),
                    highest_protocol="Malformed",
                    info=f"Malformed packet dissection error: {str(e)}",
                )

            if max_packets is not None and count >= max_packets:
                break


def parse_pcap_file(
    file_path: str | Path,
    max_packets: Optional[int] = None
) -> List[PacketRecord]:
    """
    Convenience method to parse a capture file into a list of PacketRecords.
    """
    return list(parse_packets_stream(file_path, max_packets=max_packets))
