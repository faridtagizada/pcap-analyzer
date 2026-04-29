# pcap-analyzer

A simple network traffic analyzer written in Python with **scapy**. It reads a PCAP or PCAPNG file, prints protocol and IP statistics, lists DNS queries and flags port scan attempts. Results can go to the terminal, JSON, CSV or a chart.

## What it does

- Totals: packet count, size and duration
- Protocol breakdown (TCP, UDP, ICMP, DNS, ARP)
- Most active source and destination IPs, and the busiest conversations
- Most targeted ports
- A list of DNS queries
- Port scan detection: a source IP that sends SYNs to at least N different ports on the same target (15 by default)
- Large files are read as a stream with `PcapReader`
- Output to the terminal, JSON, CSV or a PNG chart

## Install

```bash
git clone https://github.com/<your-username>/pcap-analyzer.git
cd pcap-analyzer
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
# generate a sample PCAP and analyze it
python samples/generate_sample.py
python -m pcapanalyzer samples/sample.pcap

# analyze your own capture (tcpdump / Wireshark)
sudo tcpdump -i eth0 -c 500 -w capture.pcap
python -m pcapanalyzer capture.pcap --top 5

# JSON + CSV + chart
python -m pcapanalyzer capture.pcap --json out.json --csv out.csv --chart out.png

# change how sensitive the port scan detection is
python -m pcapanalyzer capture.pcap --scan-threshold 25
```

| Option | Description | Default |
|---|---|---|
| `--top N` | Rows per table | 10 |
| `--scan-threshold N` | Distinct ports needed to call it a port scan | 15 |
| `--json FILE` | Write JSON | none |
| `--csv FILE` | Write CSV | none |
| `--chart FILE.png` | Write a chart | none |

Part of the output for `samples/sample.pcap`:

```
== Protocols ==
  Protocol  Packets
  TCP       60
  DNS       4
  ICMP      3

== Suspicious activity ==
  [!] Possible port scan: 10.0.0.66 -> 192.168.1.10 (30 distinct ports)
```

## Layout

```
pcap-analyzer/
├── pcapanalyzer/
│   ├── __init__.py
│   ├── __main__.py   # enables `python -m pcapanalyzer`
│   ├── analyzer.py   # PCAP analysis with scapy
│   ├── report.py     # terminal / JSON / CSV / chart
│   └── cli.py        # argparse CLI
├── samples/
│   ├── generate_sample.py
│   └── sample.pcap
├── tests/test_analyzer.py
├── requirements.txt
└── requirements-dev.txt
```

## Tests

```bash
pip install -r requirements-dev.txt
pytest -v
```

## Limitations

- Only SYN-based port scans are detected (no UDP scans, no slow scans).
- The content of encrypted traffic (HTTPS) is not analyzed, only the metadata.
- IPv6 is supported at a basic level.
- Port scan detection is heuristic: several clients behind one NAT address that connect to many ports on the same server can be reported as a scan.

## TODO

- traffic over time (packets per second)
- SYN flood and ARP spoofing detection
- extracting HTTP requests
- GeoIP / IP reputation lookups

## License

MIT
