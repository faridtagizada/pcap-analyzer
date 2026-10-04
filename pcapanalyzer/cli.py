"""Komanda sətri interfeysi."""
import argparse
import os
import sys

from . import __version__
from .analyzer import analyze
from .report import print_report, save_json, save_csv, save_chart


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="pcapanalyzer",
                                description="PCAP faylı üzrə şəbəkə trafiki statistikası və sadə aşkarlama.")
    p.add_argument("pcap", help="PCAP / PCAPNG faylı")
    p.add_argument("--top", type=int, default=10, help="Hər cədvəldə neçə sətir (default: 10)")
    p.add_argument("--scan-threshold", type=int, default=15,
                   help="Port scan üçün fərqli port sayı həddi (default: 15)")
    p.add_argument("--json", metavar="FAYL", help="Nəticəni JSON-a yaz")
    p.add_argument("--csv", metavar="FAYL", help="Nəticəni CSV-yə yaz")
    p.add_argument("--chart", metavar="FAYL.png", help="Qrafik yarat (matplotlib lazımdır)")
    p.add_argument("-v", "--version", action="version", version=__version__)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if not os.path.isfile(args.pcap):
        print(f"Xəta: fayl tapılmadı: {args.pcap}", file=sys.stderr)
        return 1
    try:
        stats = analyze(args.pcap, args.scan_threshold)
    except Exception as exc:  # pozulmuş / dəstəklənməyən fayl
        print(f"Xəta: fayl oxuna bilmədi: {exc}", file=sys.stderr)
        return 1

    print_report(stats, args.top)
    if args.json:
        save_json(stats, args.json)
        print(f"\n[+] JSON yazıldı: {args.json}")
    if args.csv:
        save_csv(stats, args.csv)
        print(f"[+] CSV yazıldı: {args.csv}")
    if args.chart:
        save_chart(stats, args.chart, args.top)
        print(f"[+] Qrafik yazıldı: {args.chart}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
