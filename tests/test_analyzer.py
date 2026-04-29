import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "samples"))

from generate_sample import build            # noqa: E402
from scapy.all import wrpcap, Ether, IP, TCP, UDP, DNS, DNSQR  # noqa: E402
import json  # noqa: E402
from pcapanalyzer.analyzer import analyze    # noqa: E402
from pcapanalyzer.cli import main            # noqa: E402
from pcapanalyzer.analyzer import Stats      # noqa: E402
from pcapanalyzer.report import save_json    # noqa: E402


@pytest.fixture(scope="module")
def pcap(tmp_path_factory):
    path = str(tmp_path_factory.mktemp("pcap") / "t.pcap")
    wrpcap(path, build())
    return path


def test_totals(pcap):
    s = analyze(pcap)
    assert s.total_packets == 30 + 4 + 3 + 30
    assert s.duration > 0


def test_protocols(pcap):
    s = analyze(pcap)
    assert s.protocols["DNS"] == 4
    assert s.protocols["ICMP"] == 3
    assert s.protocols["TCP"] == 60


def test_dns_queries(pcap):
    s = analyze(pcap)
    assert s.dns_queries["example.com"] == 2
    assert s.dns_queries["akm.az"] == 1


def test_port_scan_detected(pcap):
    s = analyze(pcap)
    assert s.port_scanners == {"10.0.0.66 -> 192.168.1.10": 30}


def test_scan_threshold_high(pcap):
    assert analyze(pcap, scan_threshold=100).port_scanners == {}


def test_cli_outputs(pcap, tmp_path):
    j, c, g = tmp_path / "o.json", tmp_path / "o.csv", tmp_path / "o.png"
    assert main([pcap, "--json", str(j), "--csv", str(c), "--chart", str(g)]) == 0
    assert j.stat().st_size > 0 and c.stat().st_size > 0 and g.stat().st_size > 0


def test_missing_file():
    assert main(["missing.pcap"]) == 1


def test_dst_ports_are_service_ports(pcap):
    s = analyze(pcap)
    # HTTPS connection attempts: 10 SYNs from the client to 443
    assert s.dst_ports[443] == 10
    # DNS: the lower port (53) is used for both queries and replies
    assert s.dst_ports[53] == 4
    # Ephemeral client ports (40000+) from server SYN-ACK replies must not be counted
    assert 40000 not in s.dst_ports


def test_scan_threshold_is_inclusive(pcap):
    # the scan has exactly 30 distinct ports, so a threshold of 30 must flag it
    assert analyze(pcap, scan_threshold=30).port_scanners == {"10.0.0.66 -> 192.168.1.10": 30}
    assert analyze(pcap, scan_threshold=31).port_scanners == {}


def test_json_respects_top(pcap, tmp_path):
    out = tmp_path / "o.json"
    save_json(analyze(pcap), str(out), top=2)
    data = json.loads(out.read_text(encoding="utf-8"))
    assert len(data["top_dst_ports"]) == 2
    assert len(data["top_src_ips"]) == 2


def test_cli_rejects_zero_top():
    with pytest.raises(SystemExit):
        main(["missing.pcap", "--top", "0"])


def test_empty_capture(tmp_path):
    path = str(tmp_path / "empty.pcap")
    wrpcap(path, [])
    s = analyze(path)
    assert s.total_packets == 0
    assert s.duration == 0.0
    assert s.port_scanners == {}


def test_udp_ports_use_service_port(tmp_path):
    path = str(tmp_path / "udp.pcap")
    pkts = []
    for i in range(3):
        p = Ether() / IP(src="10.1.1.1", dst="8.8.4.4") / UDP(sport=50000 + i, dport=53) / DNS(rd=1, qd=DNSQR(qname="a.test"))
        p.time = 1_700_000_000.0 + i
        pkts.append(p)
    wrpcap(path, pkts)
    s = analyze(path)
    assert s.dst_ports[53] == 3
    assert 50000 not in s.dst_ports
