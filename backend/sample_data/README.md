# Sample PCAP Captures Directory

This directory is designated for **authorized, safe, and synthetic packet capture files** (`.pcap` and `.pcapng`) used for testing and demonstration in PacketLens.

## Safety & Ethics Guidelines (Rule #11)
- **Do not commit raw, sensitive, or personal network captures** containing real credentials, tokens, proprietary traffic, or private internal IP addresses.
- **Authorized Sources**:
  1. Synthetic captures generated locally using Scapy (used in unit & integration tests).
  2. Publicly available educational samples from the [Wireshark Sample Captures Wiki](https://wiki.wireshark.org/SampleCaptures).
  3. Redacted or sanitized test PCAPs.

## Captures to Include for Development:
- `http_traffic.pcap`: Standard HTTP GET/POST requests over TCP and IPv4.
- `dns_queries.pcap`: DNS queries and responses over UDP port 53.
- `arp_requests.pcap`: Address Resolution Protocol broadcast and unicast packets.
- `ipv6_traffic.pcapng`: Modern IPv6 ICMPv6 and TCP traffic in PCAPNG format.
- `mixed_sample.pcap`: A blend of TCP, UDP, ICMP, ARP, and DNS packets for dashboard validation.

*(Actual `.pcap` files in this directory are gitignored to keep the repository lightweight).*
