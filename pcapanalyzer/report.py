"""Output of the results: terminal, JSON, CSV, chart."""
import csv
import json
from .analyzer import Stats

FORMULA_START = ("=", "+", "-", "@", "\t", "\r")


def _section(title: str, rows, headers=("Value", "Count")) -> None:
    print(f"\n== {title} ==")
    if not rows:
        print("  (empty)")
        return
    w = max(len(headers[0]), max(len(str(k)) for k, _ in rows)) + 2
    print(f"  {headers[0]:<{w}}{headers[1]}")
    for k, v in rows:
        print(f"  {str(k):<{w}}{v}")


def print_report(s: Stats, top: int = 10) -> None:
    print(f"File: {s.file}")
    print(f"Packets: {s.total_packets} | Size: {s.total_bytes} bytes | Duration: {s.duration:.2f} s")
    _section("Protocols", s.protocols.most_common(), ("Protocol", "Packets"))
    _section("Top source IPs", s.src_ips.most_common(top), ("IP", "Packets"))
    _section("Top destination IPs", s.dst_ips.most_common(top), ("IP", "Packets"))
    _section("Top conversations", [(f"{a} <-> {b}", n) for (a, b), n in s.conversations.most_common(top)], ("Pair", "Packets"))
    # Two tables, because the numbers are not comparable: a SYN is one connection attempt,
    # a UDP packet is one packet of an exchange (either direction).
    _section("Top TCP destination ports", s.tcp_ports.most_common(top), ("Port", "Connection attempts (SYN)"))
    _section("Top UDP service ports", s.udp_ports.most_common(top), ("Port", "Packets"))
    _section("DNS queries", s.dns_queries.most_common(top), ("Domain", "Queries"))
    print("\n== Suspicious activity ==")
    if s.port_scanners:
        for k, n in s.port_scanners.items():
            print(f"  [!] Possible port scan: {k} ({n} distinct ports)")
    else:
        print("  Nothing suspicious detected.")


def save_json(s: Stats, path: str, top: int = 10) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(s.to_dict(top), f, indent=2, ensure_ascii=False)


def _csv_cell(value) -> str:
    """A cell that starts with = + - or @ is run as a formula by Excel and LibreOffice.

    DNS names come from the capture, so a leading apostrophe keeps such a cell plain text.
    """
    text = str(value)
    return "'" + text if text.startswith(FORMULA_START) else text


def save_csv(s: Stats, path: str, top: int = 10) -> None:
    """Writes the same content as the JSON report: totals, top tables, conversations, scans."""
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["category", "key", "count"])
        w.writerow(["summary", "total_packets", s.total_packets])
        w.writerow(["summary", "total_bytes", s.total_bytes])
        w.writerow(["summary", "duration_sec", round(s.duration, 3)])
        for k, n in s.protocols.most_common():
            w.writerow(["protocol", _csv_cell(k), n])
        for name, counter in (("src_ip", s.src_ips), ("dst_ip", s.dst_ips),
                              ("tcp_port", s.tcp_ports), ("udp_port", s.udp_ports),
                              ("dns_query", s.dns_queries)):
            for k, n in counter.most_common(top):
                w.writerow([name, _csv_cell(k), n])
        for (a, b), n in s.conversations.most_common(top):
            w.writerow(["conversation", _csv_cell(f"{a} <-> {b}"), n])
        for k, n in s.port_scanners.items():
            w.writerow(["port_scan", _csv_cell(k), n])


def save_chart(s: Stats, path: str, top: int = 10) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig, axes = plt.subplots(1, 2, figsize=(12, 5))
    protos = s.protocols.most_common()
    if protos:
        axes[0].pie([n for _, n in protos], labels=[k for k, _ in protos], autopct="%1.0f%%")
    axes[0].set_title("Protocol distribution")
    ips = s.src_ips.most_common(top)
    if ips:
        axes[1].barh([k for k, _ in ips][::-1], [n for _, n in ips][::-1])
    axes[1].set_title(f"Top {top} source IPs")
    axes[1].set_xlabel("Packets")
    try:
        fig.tight_layout()
        fig.savefig(path, dpi=120)
    finally:
        plt.close(fig)
