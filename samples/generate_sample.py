"""Generates a synthetic PCAP for tests and demos: normal traffic + DNS + a port scan."""
import sys
from scapy.all import Ether, IP, TCP, UDP, ICMP, DNS, DNSQR, wrpcap


def build():
    pkts, t = [], 1_700_000_000.0

    def add(p):
        nonlocal t
        p.time = t
        t += 0.05
        pkts.append(p)

    client, server, dns_srv, attacker = "192.168.1.10", "93.184.216.34", "8.8.8.8", "10.0.0.66"
    # Normal web traffic
    for i in range(10):
        add(Ether()/IP(src=client, dst=server)/TCP(sport=40000+i, dport=443, flags="S"))
        add(Ether()/IP(src=server, dst=client)/TCP(sport=443, dport=40000+i, flags="SA"))
        add(Ether()/IP(src=client, dst=server)/TCP(sport=40000+i, dport=443, flags="A"))
    # DNS
    for name in ["example.com", "example.com", "github.com", "akm.az"]:
        add(Ether()/IP(src=client, dst=dns_srv)/UDP(sport=5353, dport=53)/DNS(rd=1, qd=DNSQR(qname=name)))
    # ICMP
    for _ in range(3):
        add(Ether()/IP(src=client, dst=server)/ICMP())
    # Port scan: SYNs to 30 different ports
    for port in range(1, 31):
        add(Ether()/IP(src=attacker, dst=client)/TCP(sport=54321, dport=port, flags="S"))
    return pkts


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "samples/sample.pcap"
    wrpcap(out, build())
    print(f"Written: {out}")
