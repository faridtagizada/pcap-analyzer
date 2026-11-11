import csv
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "samples"))

from generate_sample import build, eth, MAC_SRC, MAC_DST    # noqa: E402
from scapy.all import wrpcap, Ether, IP, IPv6, TCP, UDP, DNS, DNSQR, ICMPv6EchoRequest, Raw  # noqa: E402
from pcapanalyzer.analyzer import analyze                  # noqa: E402
from pcapanalyzer.cli import main                          # noqa: E402
from pcapanalyzer.report import save_csv, save_json        # noqa: E402


@pytest.fixture(scope="module")
def pcap(tmp_path_factory):
    path = str(tmp_path_factory.mktemp("pcap") / "t.pcap")
    wrpcap(path, build())
    return path


def write(tmp_path, name, pkts):
    """Writes the packets one second apart and returns the file name."""
    path = str(tmp_path / name)
    for i, p in enumerate(pkts):
        p.time = 1_700_000_000.0 + i
    wrpcap(path, pkts)
    return path


def read_csv(path):
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.reader(f))


def dns_query(name, sport=40000):
    return eth() / IP(src="10.1.1.1", dst="8.8.4.4") / UDP(sport=sport, dport=53) / DNS(rd=1, qd=DNSQR(qname=name))


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


def test_ports_are_service_ports(pcap):
    s = analyze(pcap)
    # HTTPS connection attempts: 10 SYNs from the client to 443
    assert s.tcp_ports[443] == 10
    # DNS: the well-known port (53) is used for both queries and replies
    assert s.udp_ports[53] == 4
    # Ephemeral client ports (40000+) from server SYN-ACK replies must not be counted
    assert 40000 not in s.tcp_ports


def test_scan_threshold_is_inclusive(pcap):
    # the scan has exactly 30 distinct ports, so a threshold of 30 must flag it
    assert analyze(pcap, scan_threshold=30).port_scanners == {"10.0.0.66 -> 192.168.1.10": 30}
    assert analyze(pcap, scan_threshold=31).port_scanners == {}


def test_json_respects_top(pcap, tmp_path):
    out = tmp_path / "o.json"
    save_json(analyze(pcap), str(out), top=2)
    data = json.loads(out.read_text(encoding="utf-8"))
    assert len(data["top_tcp_ports"]) == 2
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
    s = analyze(write(tmp_path, "udp.pcap", [dns_query("a.test", sport=50000 + i) for i in range(3)]))
    assert s.udp_ports[53] == 3
    assert 50000 not in s.udp_ports


# --- ports -----------------------------------------------------------------

def test_udp_service_port_can_be_the_higher_one(tmp_path):
    # WireGuard: the client talks from 40000 to the service on 51820 and gets answers back
    out = eth() / IP(src="10.1.1.1", dst="10.2.2.2") / UDP(sport=40000, dport=51820) / Raw(b"hello")
    back = eth() / IP(src="10.2.2.2", dst="10.1.1.1") / UDP(sport=51820, dport=40000) / Raw(b"hi")
    s = analyze(write(tmp_path, "wg.pcap", [out, back, out.copy(), back.copy()]))
    assert s.udp_ports[51820] == 4
    assert 40000 not in s.udp_ports


def test_tcp_and_udp_ports_are_counted_separately(tmp_path):
    syn = eth() / IP(src="10.1.1.1", dst="8.8.4.4") / TCP(sport=40000, dport=53, flags="S")
    s = analyze(write(tmp_path, "both.pcap", [syn, dns_query("a.test", sport=40001)]))
    assert s.tcp_ports[53] == 1
    assert s.udp_ports[53] == 1
    assert s.dst_ports[53] == 2      # the old combined view is still there


# --- sizes and protocols ---------------------------------------------------

def test_size_is_the_length_on_the_wire(tmp_path):
    # taken with a snap length: 54 bytes are in the file, 1500 were on the wire
    p = eth() / IP(src="10.1.1.1", dst="10.2.2.2") / TCP(sport=40000, dport=80, flags="S")
    p.wirelen = 1500
    assert analyze(write(tmp_path, "snap.pcap", [p])).total_bytes == 1500


def test_icmpv6_has_its_own_row(tmp_path):
    p = eth() / IPv6(src="2001:db8::1", dst="2001:db8::2") / ICMPv6EchoRequest()
    s = analyze(write(tmp_path, "v6.pcap", [p]))
    assert s.protocols["ICMPv6"] == 1
    assert "Other" not in s.protocols


# --- names from the capture are data, not text to trust -------------------

def test_dns_names_are_made_printable(tmp_path):
    s = analyze(write(tmp_path, "esc.pcap", [dns_query("bad\x1b[2Jname.test")]))
    assert list(s.dns_queries) == ["bad?[2Jname.test"]


def test_csv_does_not_start_a_cell_with_a_formula(tmp_path):
    out = tmp_path / "o.csv"
    save_csv(analyze(write(tmp_path, "f.pcap", [dns_query("=cmd.test")])), str(out))
    assert ["dns_query", "'=cmd.test", "1"] in read_csv(out)


# --- outputs ---------------------------------------------------------------

def test_csv_has_what_the_json_has(pcap, tmp_path):
    out = tmp_path / "o.csv"
    save_csv(analyze(pcap), str(out), top=2)
    rows = read_csv(out)
    categories = [r[0] for r in rows[1:]]
    assert ["summary", "total_packets", "67"] in rows
    assert ["port_scan", "10.0.0.66 -> 192.168.1.10", "30"] in rows
    assert "conversation" in categories
    assert categories.count("src_ip") == 2      # --top applies to the CSV as well


def test_cli_creates_the_output_folder(pcap, tmp_path):
    out = tmp_path / "new" / "deeper" / "o.json"
    assert main([pcap, "--json", str(out)]) == 0
    assert out.stat().st_size > 0


def test_cli_write_errors_are_messages(pcap, tmp_path, capsys):
    (tmp_path / "plain_file").write_text("x")
    assert main([pcap, "--json", str(tmp_path / "plain_file" / "o.json")]) == 1
    assert main([pcap, "--chart", str(tmp_path / "chart.txt")]) == 1    # matplotlib has no .txt writer
    assert "could not write the output" in capsys.readouterr().err


def test_cli_damaged_file(tmp_path, capsys):
    bad = tmp_path / "bad.pcap"
    bad.write_bytes(b"this is not a capture file")
    assert main([str(bad)]) == 1
    assert "could not read the file" in capsys.readouterr().err


# --- sample ----------------------------------------------------------------

def test_sample_does_not_depend_on_the_machine():
    assert {(p[Ether].src, p[Ether].dst) for p in build()} == {(MAC_SRC, MAC_DST)}
