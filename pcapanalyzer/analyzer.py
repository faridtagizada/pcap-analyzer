"""PCAP analizinin əsas məntiqi (scapy ilə)."""
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Dict, Optional

from scapy.all import PcapReader, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DNSQR

SYN = 0x02
ACK = 0x10


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
    dst_ports: Counter = field(default_factory=Counter)
    dns_queries: Counter = field(default_factory=Counter)
    port_scanners: Dict[str, int] = field(default_factory=dict)

    @property
    def duration(self) -> float:
        if self.start_time is None or self.end_time is None:
            return 0.0
        return self.end_time - self.start_time

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
            "top_dst_ports": {str(p): n for p, n in self.dst_ports.most_common(top)},
            "top_dns_queries": dict(self.dns_queries.most_common(top)),
            "suspected_port_scanners": self.port_scanners,
        }


def classify(pkt) -> str:
    """Paketin ən yüksək səviyyəli protokolunu qaytarır."""
    if pkt.haslayer(DNS):
        return "DNS"
    if pkt.haslayer(TCP):
        return "TCP"
    if pkt.haslayer(UDP):
        return "UDP"
    if pkt.haslayer(ICMP):
        return "ICMP"
    if pkt.haslayer(ARP):
        return "ARP"
    return "Other"


def analyze(path: str, scan_threshold: int = 15) -> Stats:
    """PCAP faylını oxuyub statistika qaytarır.

    scan_threshold: bir mənbə IP-nin eyni hədəfdə neçə fərqli porta SYN
    göndərdikdə port scan sayılacağı.
    """
    stats = Stats(file=path)
    syn_targets = defaultdict(set)   # (src, dst) -> {portlar}

    with PcapReader(path) as reader:
        for pkt in reader:
            stats.total_packets += 1
            stats.total_bytes += len(pkt)
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
                stats.dst_ports[tcp.dport] += 1
                flags = int(tcp.flags)
                if ip is not None and flags & SYN and not flags & ACK:
                    syn_targets[(ip.src, ip.dst)].add(tcp.dport)
            elif pkt.haslayer(UDP):
                stats.dst_ports[pkt[UDP].dport] += 1

            if pkt.haslayer(DNSQR) and pkt.haslayer(DNS) and pkt[DNS].qr == 0:
                name = pkt[DNSQR].qname
                if isinstance(name, bytes):
                    name = name.decode("utf-8", errors="replace")
                stats.dns_queries[name.rstrip(".")] += 1

    for (src, dst), ports in syn_targets.items():
        if len(ports) >= scan_threshold:
            stats.port_scanners[f"{src} -> {dst}"] = len(ports)
    return stats
