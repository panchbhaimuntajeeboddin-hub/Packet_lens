"""CLI utility to test and inspect PCAP files using the PacketLens parsing engine."""

import argparse
import logging
import sys
from pathlib import Path

# Suppress benign Scapy runtime warning about libpcap on offline parsing
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Add backend directory to sys.path if run directly
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from app.services.validator import validate_capture_file
from app.services.pcap_parser import parse_pcap_file
from app.services.statistics import calculate_traffic_statistics


def print_banner():
    print("=" * 80)
    print("  PacketLens — Network Traffic Dissection Engine (Phase 2 Test CLI)")
    print("=" * 80)


def inspect_file(file_path: str, max_packets: int = 50):
    print_banner()
    path = Path(file_path)
    print(f"[*] Validating capture file: {path.name} ({path.resolve()})")

    try:
        fmt, size = validate_capture_file(path)
        print(f"[+] Format: {fmt} | File Size: {size:,} bytes")
    except Exception as e:
        print(f"[!] Validation failed: {e}")
        sys.exit(1)

    print(f"[*] Dissecting packets (streaming reader, max={max_packets})...")
    packets = parse_pcap_file(path, max_packets=max_packets)
    print(f"[+] Successfully dissected {len(packets)} packets.\n")

    # Table of first packets
    print("-" * 80)
    print(f"{'#':<4} {'Protocol':<10} {'Source':<22} {'Destination':<22} {'Length':<6} {'Info'}")
    print("-" * 80)
    for p in packets[:15]:
        src = f"{p.src_ip or p.src_mac or 'N/A'}"
        if p.src_port:
            src += f":{p.src_port}"
        dst = f"{p.dst_ip or p.dst_mac or 'N/A'}"
        if p.dst_port:
            dst += f":{p.dst_port}"

        print(f"{p.packet_num:<4} {p.highest_protocol:<10} {src[:21]:<22} {dst[:21]:<22} {p.length:<6} {p.info[:40]}")
    if len(packets) > 15:
        print(f"... and {len(packets) - 15} more packets.")
    print("-" * 80)

    # Compute Statistics
    stats = calculate_traffic_statistics(packets)
    print("\n[+] TRAFFIC SUMMARY METRICS:")
    print(f"    Total Packets      : {stats.total_packets}")
    print(f"    Total Bytes        : {stats.total_bytes:,} bytes")
    print(f"    Average Packet Size: {stats.avg_packet_size} bytes")
    print(f"    Session Duration   : {stats.duration_seconds:.4f} seconds")
    print(f"    Average Bitrate    : {stats.bitrate_bps:,.2f} bps")
    print(f"    Unique IP Hosts    : {stats.total_unique_ips}")

    print("\n[+] PROTOCOL BREAKDOWN:")
    for proto, count in stats.protocol_distribution.items():
        pct = stats.protocol_percentages.get(proto, 0.0)
        bar = "#" * int(pct // 5)
        print(f"    {proto:<12} : {count:>5} packets ({pct:>5.1f}%)  [{bar:<20}]")

    if stats.top_source_ips:
        print("\n[+] TOP COMMUNICATING HOSTS (Talkers):")
        for ep in stats.top_source_ips:
            print(f"    {ep.ip:<18} -> {ep.packet_count:>4} packets ({ep.percentage_packets:>5.1f}%) | {ep.byte_count:>6} bytes")

    if stats.top_conversations:
        print("\n[+] TOP IP CONVERSATIONS:")
        for conv in stats.top_conversations:
            print(f"    {conv.source_ip} <---> {conv.destination_ip} ({conv.packet_count} packets, {conv.byte_count} bytes)")
    print("\n" + "=" * 80)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PacketLens Network Capture Dissector CLI")
    parser.add_argument("pcap_path", nargs="?", help="Path to .pcap or .pcapng file")
    parser.add_argument("--limit", type=int, default=50, help="Max packets to dissect")

    args = parser.parse_args()

    if not args.pcap_path:
        # Generate a temporary synthetic PCAP for instant testing demonstration
        print("[!] No file path provided. Generating a synthetic test PCAP in backend/sample_data/demo.pcap...")
        from scapy.all import wrpcap
        from tests.conftest import generate_synthetic_packets

        sample_dir = backend_dir / "sample_data"
        sample_dir.mkdir(parents=True, exist_ok=True)
        demo_file = sample_dir / "demo.pcap"

        # Generate synthetic packet list
        pkts = generate_synthetic_packets()
        wrpcap(str(demo_file), pkts)
        print(f"[+] Created synthetic demo file: {demo_file}")
        inspect_file(str(demo_file), max_packets=args.limit)
    else:
        inspect_file(args.pcap_path, max_packets=args.limit)
