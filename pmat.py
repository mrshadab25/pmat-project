#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║         PMAT — PDF Malware Analysis Toolkit  v1.0               ║
║         Automated Static Analysis for Malicious PDFs            ║
║         Cybersecurity Project | Educational Use Only            ║
╚══════════════════════════════════════════════════════════════════╝
"""

import argparse
import sys
import os
import json
import time
from pathlib import Path

# Add toolkit root to path
sys.path.insert(0, os.path.dirname(__file__))

from modules.loader      import PDFLoader
from modules.metadata    import MetadataExtractor
from modules.objects     import ObjectEnumerator
from modules.keywords    import KeywordScanner
from modules.streams     import StreamDecoder
from modules.ioc         import IOCExtractor
from modules.javascript  import JavaScriptAnalyzer
from modules.scoring     import RiskScorer
from modules.reporter    import ReportGenerator
from utils.display       import Banner, print_section, print_finding, Colors

# ──────────────────────────────────────────────────────────────────
VERSION = "1.0.0"
BANNER  = r"""
  ██████╗ ███╗   ███╗ █████╗ ████████╗
  ██╔══██╗████╗ ████║██╔══██╗╚══██╔══╝
  ██████╔╝██╔████╔██║███████║   ██║   
  ██╔═══╝ ██║╚██╔╝██║██╔══██║   ██║   
  ██║     ██║ ╚═╝ ██║██║  ██║   ██║   
  ╚═╝     ╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   
  PDF Malware Analysis Toolkit v{version}
  Automated Static Analysis Engine
""".format(version=VERSION)
# ──────────────────────────────────────────────────────────────────


def analyze_pdf(pdf_path: str, output_dir: str = "reports",
                verbose: bool = False, json_only: bool = False) -> dict:
    """
    Run the full 8-step PMAT analysis pipeline on a PDF file.
    Returns the complete analysis result dictionary.
    """
    start_time = time.time()
    results = {}

    if not json_only:
        print(Colors.CYAN + BANNER + Colors.RESET)

    # ── STEP 1: Load & validate PDF ──────────────────────────────
    print_section("STEP 1", "Loading PDF & Extracting File Information", json_only)
    loader = PDFLoader(pdf_path)
    load_result = loader.load()
    results["file_info"] = load_result

    if not load_result["valid"]:
        print_finding("ERROR", f"Cannot open PDF: {load_result['error']}", "critical", json_only)
        return results

    if not json_only:
        print_finding("OK", f"File: {load_result['filename']}", "clean", json_only)
        print_finding("OK", f"Size: {load_result['size_human']}", "clean", json_only)
        print_finding("OK", f"MD5:    {load_result['md5']}", "clean", json_only)
        print_finding("OK", f"SHA256: {load_result['sha256']}", "clean", json_only)

    # ── STEP 2: Metadata ─────────────────────────────────────────
    print_section("STEP 2", "Metadata Extraction & Anomaly Detection", json_only)
    meta_ext = MetadataExtractor(pdf_path, load_result)
    meta_result = meta_ext.extract()
    results["metadata"] = meta_result

    if not json_only:
        for k, v in meta_result["fields"].items():
            if v:
                print_finding("INFO", f"{k:20s}: {v}", "info", json_only)
        for anomaly in meta_result["anomalies"]:
            print_finding("WARN", anomaly, "medium", json_only)

    # ── STEP 3: Object Enumeration ───────────────────────────────
    print_section("STEP 3", "Object Enumeration & Structure Analysis", json_only)
    obj_enum = ObjectEnumerator(pdf_path)
    obj_result = obj_enum.enumerate()
    results["objects"] = obj_result

    if not json_only:
        print_finding("INFO", f"Total objects : {obj_result['total_objects']}", "info", json_only)
        print_finding("INFO", f"Total streams : {obj_result['total_streams']}", "info", json_only)
        print_finding("INFO", f"Pages         : {obj_result['page_count']}", "info", json_only)
        for obj in obj_result["suspicious_objects"]:
            print_finding("WARN", f"Suspicious object [{obj['id']}]: {obj['reason']}", "high", json_only)

    # ── STEP 4: Keyword Scan ─────────────────────────────────────
    print_section("STEP 4", "Keyword-Based Threat Detection", json_only)
    kw_scanner = KeywordScanner(pdf_path)
    kw_result = kw_scanner.scan()
    results["keywords"] = kw_result

    if not json_only:
        for kw in kw_result["found"]:
            sev = "critical" if kw["score"] >= 10 else ("high" if kw["score"] >= 7 else "medium")
            print_finding(kw["severity"], f"{kw['keyword']:20s}  count={kw['count']:2d}  (+{kw['score']} pts)", sev, json_only)
        if not kw_result["found"]:
            print_finding("CLEAN", "No suspicious keywords detected", "clean", json_only)

    # ── STEP 5: Stream Decoding ──────────────────────────────────
    print_section("STEP 5", "Stream Decoding & Content Extraction", json_only)
    decoder = StreamDecoder(pdf_path)
    stream_result = decoder.decode()
    results["streams"] = stream_result

    if not json_only:
        print_finding("INFO", f"Streams decoded    : {stream_result['decoded_count']}", "info", json_only)
        print_finding("INFO", f"Encoding types     : {', '.join(stream_result['encoding_types']) or 'none'}", "info", json_only)
        if stream_result["high_entropy_streams"]:
            print_finding("WARN", f"High-entropy streams (possible shellcode): {stream_result['high_entropy_streams']}", "high", json_only)

    # ── STEP 6: IOC Extraction ───────────────────────────────────
    print_section("STEP 6", "Indicator of Compromise (IOC) Extraction", json_only)
    ioc_ext = IOCExtractor(pdf_path, stream_result["decoded_text"])
    ioc_result = ioc_ext.extract()
    results["iocs"] = ioc_result

    if not json_only:
        for url in ioc_result["urls"]:
            print_finding("IOC", f"URL: {url}", "high", json_only)
        for ip in ioc_result["ips"]:
            print_finding("IOC", f"IP : {ip}", "high", json_only)
        for cve in ioc_result["cves"]:
            print_finding("IOC", f"CVE: {cve}", "critical", json_only)
        for ef in ioc_result["embedded_files"]:
            print_finding("IOC", f"Embedded file: {ef}", "critical", json_only)
        for email in ioc_result["emails"]:
            print_finding("IOC", f"Email: {email}", "medium", json_only)
        if not any([ioc_result["urls"], ioc_result["ips"], ioc_result["cves"],
                    ioc_result["embedded_files"]]):
            print_finding("CLEAN", "No network or file IOCs found", "clean", json_only)

    # ── STEP 7: JavaScript Analysis ──────────────────────────────
    print_section("STEP 7", "JavaScript Analysis & Obfuscation Detection", json_only)
    js_analyzer = JavaScriptAnalyzer(pdf_path, stream_result["decoded_text"], obj_result)
    js_result = js_analyzer.analyze()
    results["javascript"] = js_result

    if not json_only:
        print_finding("INFO", f"JS blocks found   : {js_result['js_block_count']}", "info", json_only)
        for pattern in js_result["obfuscation_patterns"]:
            print_finding("WARN", f"Obfuscation: {pattern}", "high", json_only)
        for action in js_result["auto_actions"]:
            print_finding("WARN", f"Auto-action: {action}", "high", json_only)
        if js_result["js_block_count"] == 0:
            print_finding("CLEAN", "No JavaScript detected", "clean", json_only)

    # ── STEP 8: Risk Scoring ─────────────────────────────────────
    print_section("STEP 8", "Risk Scoring & Severity Assessment", json_only)
    scorer = RiskScorer(results)
    score_result = scorer.score()
    results["risk"] = score_result

    if not json_only:
        sev_color = {
            "CRITICAL": Colors.RED + Colors.BOLD,
            "HIGH":     Colors.ORANGE + Colors.BOLD,
            "MEDIUM":   Colors.YELLOW + Colors.BOLD,
            "LOW":      Colors.BLUE,
            "CLEAN":    Colors.GREEN,
        }.get(score_result["severity"], "")
        print(f"\n  {sev_color}{'═'*54}")
        print(f"  RISK SCORE  : {score_result['score']}/100")
        print(f"  SEVERITY    : {score_result['severity']}")
        print(f"  {'═'*54}{Colors.RESET}\n")
        for detail in score_result["breakdown"]:
            print_finding("SCORE", detail, "info", json_only)

    # ── STEP 9: Generate Report ───────────────────────────────────
    print_section("STEP 9", "Generating Malware Analysis Report", json_only)
    elapsed = round(time.time() - start_time, 2)
    results["analysis_time_seconds"] = elapsed

    reporter = ReportGenerator(results, output_dir)
    report_paths = reporter.generate()
    results["report_paths"] = report_paths

    if not json_only:
        print_finding("OK", f"JSON report : {report_paths['json']}", "clean", json_only)
        print_finding("OK", f"TXT report  : {report_paths['txt']}", "clean", json_only)
        print(f"\n  {Colors.GRAY}Analysis completed in {elapsed}s{Colors.RESET}\n")

    return results


# ──────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        prog="pmat",
        description="PMAT — PDF Malware Analysis Toolkit v1.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python pmat.py scan invoice.pdf
  python pmat.py scan invoice.pdf --output ./reports
  python pmat.py scan invoice.pdf --json
  python pmat.py batch /folder/of/pdfs/ --output ./reports
        """
    )
    subparsers = parser.add_subparsers(dest="command")

    # scan command
    scan_p = subparsers.add_parser("scan", help="Analyze a single PDF file")
    scan_p.add_argument("pdf", help="Path to the PDF file")
    scan_p.add_argument("--output", "-o", default="reports", help="Output directory for reports")
    scan_p.add_argument("--json", action="store_true", help="JSON output only (machine-readable)")
    scan_p.add_argument("--verbose", "-v", action="store_true", help="Verbose output")

    # batch command
    batch_p = subparsers.add_parser("batch", help="Analyze all PDFs in a directory")
    batch_p.add_argument("directory", help="Directory containing PDF files")
    batch_p.add_argument("--output", "-o", default="reports", help="Output directory")
    batch_p.add_argument("--json", action="store_true", help="JSON output only")

    args = parser.parse_args()

    if args.command == "scan":
        if not os.path.isfile(args.pdf):
            print(f"[ERROR] File not found: {args.pdf}")
            sys.exit(1)
        result = analyze_pdf(args.pdf, args.output, args.verbose, args.json)
        if args.json:
            print(json.dumps(result, indent=2, default=str))

    elif args.command == "batch":
        if not os.path.isdir(args.directory):
            print(f"[ERROR] Directory not found: {args.directory}")
            sys.exit(1)
        pdfs = list(Path(args.directory).glob("*.pdf"))
        if not pdfs:
            print("[INFO] No PDF files found in directory.")
            sys.exit(0)
        print(f"\n[BATCH] Found {len(pdfs)} PDF file(s) to analyze...\n")
        summary = []
        for pdf in pdfs:
            print(f"\n{'='*60}")
            print(f"  Analyzing: {pdf.name}")
            print(f"{'='*60}")
            result = analyze_pdf(str(pdf), args.output, False, args.json)
            summary.append({
                "file": pdf.name,
                "score": result.get("risk", {}).get("score", 0),
                "severity": result.get("risk", {}).get("severity", "UNKNOWN"),
            })
        print(f"\n{'='*60}")
        print("  BATCH SUMMARY")
        print(f"{'='*60}")
        for s in sorted(summary, key=lambda x: x["score"], reverse=True):
            print(f"  {s['severity']:10s} ({s['score']:3d}/100)  {s['file']}")
        print(f"{'='*60}\n")

    else:
        print(Colors.CYAN + BANNER + Colors.RESET)
        parser.print_help()


if __name__ == "__main__":
    main()
