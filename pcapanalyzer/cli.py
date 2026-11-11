"""Command-line interface."""
import argparse
import os
import struct
import sys

from scapy.error import Scapy_Exception

from . import __version__
from .analyzer import analyze
from .report import print_report, save_json, save_csv, save_chart


def _positive_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not an integer: {value!r}") from None
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


def _prepare(path: str) -> None:
    """Creates the folder an output file goes into."""
    folder = os.path.dirname(path)
    if folder:
        os.makedirs(folder, exist_ok=True)


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if not os.path.isfile(args.pcap):
        print(f"Error: file not found: {args.pcap}", file=sys.stderr)
        return 1
    # Only the errors a damaged or unsupported file causes are caught here. Anything else is
    # a bug in this program and should show its traceback instead of "could not read the file".
    try:
        stats = analyze(args.pcap, args.scan_threshold)
    except (Scapy_Exception, OSError, EOFError, struct.error) as exc:
        print(f"Error: could not read the file: {exc}", file=sys.stderr)
        return 1

    print_report(stats, args.top)
    # The report is on the screen by now; a file that cannot be written ends with a message.
    try:
        if args.json:
            _prepare(args.json)
            save_json(stats, args.json, args.top)
            print(f"\n[+] JSON written: {args.json}")
        if args.csv:
            _prepare(args.csv)
            save_csv(stats, args.csv, args.top)
            print(f"[+] CSV written: {args.csv}")
        if args.chart:
            _prepare(args.chart)
            save_chart(stats, args.chart, args.top)
            print(f"[+] Chart written: {args.chart}")
    except ImportError:
        print("Error: --chart needs matplotlib (pip install -r requirements-chart.txt)", file=sys.stderr)
        return 1
    except (OSError, ValueError) as exc:   # ValueError: matplotlib does not know the file extension
        print(f"Error: could not write the output: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
