# DNSWatch
A lightweight Python-based DNS traffic analysis and threat detection tool. DNSWatch reads standard packet capture files (PCAP/PCAPNG), extracts structured DNS data, scores each domain across seven detection features, and produces analyst-friendly outputs including a scored CSV report and a four-panel visual dashboard.

## Requirements
- Python 3.12
- tshark (Wireshark command-line tool) — must be installed separately
  - Windows: https://www.wireshark.org/download.html
  - macOS: brew install wireshark
- Python dependencies:
  pip install pandas tldextract matplotlib

## How to run

**Step 1 — Extract DNS data from a PCAP file:**
python src/main.py data/your_capture.pcap

**Step 2 — Run detection and scoring:**
python src/detect.py outputs/dns_events_your_capture.csv

## Outputs
All outputs are saved to the outputs/ folder:
- dns_events_*.csv — structured DNS event data
- alerts_*.csv — Suspicious and Dangerous domains only
- scored_*.csv — all domains with full scores
- dashboard_*.png — four-panel visual summary

## Project structure
dnswatch/
  src/
    main.py        — DNS extraction layer
    detect.py      — Detection and scoring layer
  data/            — Place your PCAP files here
  outputs/         — All generated outputs land here
