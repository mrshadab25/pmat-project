# PMAT — PDF Malware Analysis Toolkit v1.0

**Automated Static Analysis Engine for Malicious PDF Detection**
*Cybersecurity Project | For Educational Use Only*

---

## Overview

PMAT is a Python-based static analysis toolkit that automatically detects malicious
indicators in PDF files. It implements an 8-step analysis pipeline:

1. **PDF Loader**        — File validation, hashing (MD5/SHA1/SHA256)
2. **Metadata Extractor** — Author, dates, producer, anomaly detection
3. **Object Enumerator** — PDF object tree analysis, suspicious type detection
4. **Keyword Scanner**   — Attack keyword detection with weighted scoring
5. **Stream Decoder**    — FlateDecode/ASCIIHex/ASCII85/Base64 decoding
6. **IOC Extractor**     — URLs, IPs, CVEs, embedded files, emails
7. **JavaScript Analyzer** — JS extraction, obfuscation detection, deobfuscation
8. **Risk Scorer**       — Weighted 0-100 score → CLEAN/LOW/MEDIUM/HIGH/CRITICAL
9. **Report Generator**  — JSON + TXT structured reports with IOCs & mitigations

---

## Requirements

```bash
Python 3.8+
pip install pikepdf pdfminer.six pypdf
```

---

## Quick Start

```bash
# Generate test samples
python generate_samples.py

# Scan a single PDF
python pmat.py scan samples/sample_malicious_invoice.pdf

# Scan with custom output directory
python pmat.py scan invoice.pdf --output ./my_reports

# Batch scan an entire folder
python pmat.py batch ./samples/ --output ./reports

# Machine-readable JSON output
python pmat.py scan invoice.pdf --json
```

---

## Risk Severity Levels

| Score  | Severity | Meaning                                           |
|--------|----------|---------------------------------------------------|
| 90-100 | CRITICAL | Active exploit indicators — immediate IR response |
| 70-89  | HIGH     | Strong malicious indicators — treat as threat     |
| 40-69  | MEDIUM   | Suspicious content — further analysis required    |
| 10-39  | LOW      | Minor anomalies — monitor and investigate         |
| 0-9    | CLEAN    | No meaningful threats detected                    |

---

## Project Structure

```
pmat/
├── pmat.py              ← Main entry point (CLI)
├── generate_samples.py  ← Generate test PDFs
├── modules/
│   ├── loader.py        ← Step 1: File loader & hasher
│   ├── metadata.py      ← Step 2: Metadata extractor
│   ├── objects.py       ← Step 3: Object enumerator
│   ├── keywords.py      ← Step 4: Keyword scanner
│   ├── streams.py       ← Step 5: Stream decoder
│   ├── ioc.py           ← Step 6: IOC extractor
│   ├── javascript.py    ← Step 7: JavaScript analyzer
│   ├── scoring.py       ← Step 8: Risk scoring engine
│   └── reporter.py      ← Step 9: Report generator
├── utils/
│   └── display.py       ← Terminal color/display helpers
├── samples/             ← Test PDF samples
└── reports/             ← Generated analysis reports
```

---

## Sample Output

```
  RISK SCORE  : 82/100
  SEVERITY    : HIGH

  [CRITICAL] /JavaScript     count=3   (+10 pts)
  [HIGH]     /OpenAction     count=1   (+8 pts)
  [HIGH]     eval(           count=2   (+7 pts)
  [IOC]  URL: http://malicious-c2-server.ru/payload.exe
  [IOC]  Embedded file: invoice_attachment.exe
```

---

## Legal Notice

This toolkit is for **educational and authorized security research only**.
Do not use against systems or files you do not own or have explicit permission to analyze.
