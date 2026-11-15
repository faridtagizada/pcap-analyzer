"""Core PCAP analysis logic (using scapy)."""
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple

from scapy.all import PcapReader, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DNSQR

SYN = 0x02
ACK = 0x10
WELL_KNOWN = 1024   # ports below this belong to a service, never to a client


@dataclass
class Stats:
    file: str = ""
    total_packets: int = 0
    total_bytes: int = 0
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    protocols: Counter = field(default_factory=Counter)
    src_ips: Counter = field(default_factory=Counter)
    dst_ips: Counter = field(default_factory=Counter)
    conversations: Counter = field(default_factory=Counter)
    # The two port counters measure different things, so they are kept apart:
    tcp_ports: Counter = field(default_factory=Counter)   # connection attempts (SYN) per destination port
    udp_ports: Counter = field(default_factory=Counter)   # packets per service port, both directions
    dns_queries: Counter = field(default_factory=Counter)
    port_scanners: Dict[str, int] = field(default_factory=dict)

    @property
    def duration(self) -> float:
        if self.start_time is None or self.end_time is None:
            return 0.0
        return self.end_time - self.start_time

    @property
    def dst_ports(self) -> Counter:
        """TCP and UDP ports in one counter. Only kept for older code: use tcp_ports / udp_ports."""
        return self.tcp_ports + self.udp_ports

    def to_dict(self, top: int = 10) -> dict:
        return {
            "file": self.file,
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "duration_sec": round(self.duration, 3),
            "protocols": dict(self.protocols.most_common()),
            "top_src_ips": dict(self.src_ips.most_common(top)),
            "top_dst_ips": dict(self.dst_ips.most_common(top)),
            "top_conversations": {f"{a} <-> {b}": n for (a, b), n
                                  in self.conversations.most_common(top)},
            "top_tcp_ports": {str(p): n for p, n in self.tcp_ports.most_common(top)},
            "top_udp_ports": {str(p): n for p, n in self.udp_ports.most_common(top)},
            "top_dns_queries": dict(self.dns_queries.most_common(top)),
            "suspected_port_scanners": self.port_scanners,
        }


def _has_icmpv6(pkt) -> bool:
    # scapy has one class per ICMPv6 message (ICMPv6EchoRequest, ICMPv6ND_NS, ...)
    return any(layer.__name__.startswith("ICMPv6") for layer in pkt.layers())


def classify(pkt) -> str:
    """Returns the highest-level protocol of the packet."""
    if pkt.haslayer(DNS):
        return "DNS"
    if pkt.haslayer(TCP):
        return "TCP"
    if pkt.haslayer(UDP):
        return "UDP"
    if pkt.haslayer(ICMP):
        return "ICMP"
    if _has_icmpv6(pkt):
        return "ICMPv6"
    if pkt.haslayer(ARP):
        return "ARP"
    return "Other"


def _printable(text: str) -> str:
    """Names come out of the capture file: control characters must not reach the terminal."""
    return "".join(ch if ch.isprintable() else "?" for ch in text)


def _udp_service_port(flows: Dict[Tuple, int], src: str, sport: int, dst: str, dport: int) -> int:
    """UDP has no handshake, so the service port has to be guessed.

    A well-known port on one side wins, so DNS queries and replies both count as 53.
    Otherwise the port that was contacted first is the service. Taking the lower number
    named the client's port whenever the service port is the higher one (WireGuard on
    51820, a client on 40000).
    """
    key = tuple(sorted(((str(src), int(sport)), (str(dst), int(dport)))))
    if key not in flows:
        low, high = sorted((int(sport), int(dport)))
        flows[key] = low if low < WELL_KNOWN <= high else int(dport)
    return flows[key]


def analyze(path: str, scan_threshold: int = 15) -> Stats:
    """Reads a PCAP file and returns statistics.

    scan_threshold: how many distinct ports a source IP has to send SYNs to
    on the same target before it is counted as a port scan.
    """
    stats = Stats(file=path)
    syn_targets = defaultdict(set)      # (src, dst) -> {ports}
    udp_flows: Dict[Tuple, int] = {}    # the two endpoints of a UDP exchange -> its service port

    with PcapReader(path) as reader:
        for pkt in reader:
            stats.total_packets += 1
            # wirelen is the size on the wire. len(pkt) rebuilds the packet and only gives
            # what was captured, which is less when the capture used a snap length.
            stats.total_bytes += getattr(pkt, "wirelen", None) or len(pkt)
            ts = float(pkt.time)
            if stats.start_time is None or ts < stats.start_time:
                stats.start_time = ts
            if stats.end_time is None or ts > stats.end_time:
                stats.end_time = ts

            stats.protocols[classify(pkt)] += 1

            ip = pkt[IP] if pkt.haslayer(IP) else (pkt[IPv6] if pkt.haslayer(IPv6) else None)
            if ip is not None:
                stats.src_ips[ip.src] += 1
                stats.dst_ips[ip.dst] += 1
                stats.conversations[tuple(sorted((ip.src, ip.dst)))] += 1

            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                flags = int(tcp.flags)
                # Only connection attempts (SYN without ACK) count as targeted ports.
                # Server replies carry the client's ephemeral port as dport, so they are skipped.
                if flags & SYN and not flags & ACK:
                    stats.tcp_ports[tcp.dport] += 1
                    if ip is not None:
                        syn_targets[(ip.src, ip.dst)].add(tcp.dport)
            elif pkt.haslayer(UDP):
                udp = pkt[UDP]
                src, dst = (ip.src, ip.dst) if ip is not None else ("?", "?")
                stats.udp_ports[_udp_service_port(udp_flows, src, udp.sport, dst, udp.dport)] += 1

            if pkt.haslayer(DNSQR) and pkt.haslayer(DNS) and pkt[DNS].qr == 0:
                name = pkt[DNSQR].qname
                if isinstance(name, bytes):
                    name = name.decode("utf-8", errors="replace")
                stats.dns_queries[_printable(str(name).rstrip("."))] += 1

    for (src, dst), ports in syn_targets.items():
        if len(ports) >= scan_threshold:
            stats.port_scanners[f"{src} -> {dst}"] = len(ports)
    return stats
