import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "samples"))

from generate_sample import build            # noqa: E402
from scapy.all import wrpcap                 # noqa: E402
from pcapanalyzer.analyzer import analyze    # noqa: E402
from pcapanalyzer.cli import main            # noqa: E402


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
    assert main(["yoxdur.pcap"]) == 1
