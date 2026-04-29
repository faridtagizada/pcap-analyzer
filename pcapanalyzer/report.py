"""Output of the results: terminal, JSON, CSV, chart."""
import csv
import json
from .analyzer import Stats


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
    _section("Top destination ports", s.dst_ports.most_common(top), ("Port", "Packets"))
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


def save_csv(s: Stats, path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["category", "key", "count"])
        for name, counter in (("protocol", s.protocols), ("src_ip", s.src_ips),
                              ("dst_ip", s.dst_ips), ("dst_port", s.dst_ports),
                              ("dns_query", s.dns_queries)):
            for k, n in counter.most_common():
                w.writerow([name, k, n])


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
    fig.tight_layout()
    fig.savefig(path, dpi=120)
    plt.close(fig)
