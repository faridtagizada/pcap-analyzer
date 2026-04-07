"""Command-line interface."""
import argparse
import os
import sys

from . import __version__
from .analyzer import analyze
from .report import print_report, save_json, save_csv, save_chart


def _positive_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not an integer: {value!r}")
    if number < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return number


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="pcapanalyzer",
                                description="Network traffic statistics and simple detection for a PCAP file.")
    p.add_argument("pcap", help="PCAP / PCAPNG file")
    p.add_argument("--top", type=_positive_int, default=10, help="Rows per table (default: 10)")
    p.add_argument("--scan-threshold", type=_positive_int, default=15,
                   help="Number of distinct ports that counts as a port scan (default: 15)")
    p.add_argument("--json", metavar="FILE", help="Write the results to JSON")
    p.add_argument("--csv", metavar="FILE", help="Write the results to CSV")
    p.add_argument("--chart", metavar="FILE.png", help="Create a chart (needs matplotlib)")
    p.add_argument("-v", "--version", action="version", version=__version__)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if not os.path.isfile(args.pcap):
        print(f"Error: file not found: {args.pcap}", file=sys.stderr)
        return 1
    try:
        stats = analyze(args.pcap, args.scan_threshold)
    except Exception as exc:  # corrupted / unsupported file
        print(f"Error: could not read the file: {exc}", file=sys.stderr)
        return 1

    print_report(stats, args.top)
    if args.json:
        save_json(stats, args.json, args.top)
        print(f"\n[+] JSON written: {args.json}")
    if args.csv:
        save_csv(stats, args.csv)
        print(f"[+] CSV written: {args.csv}")
    if args.chart:
        save_chart(stats, args.chart, args.top)
        print(f"[+] Chart written: {args.chart}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
