"""
modules/reporter.py — STEP 9: Report Generation
Generates structured JSON and human-readable TXT malware analysis reports.
"""

import json
import os
import re
from datetime import datetime
from pathlib import Path


class ReportGenerator:
    """Generates JSON and plain-text malware analysis reports."""

    def __init__(self, results: dict, output_dir: str = "reports"):
        self.results    = results
        self.output_dir = output_dir
        Path(output_dir).mkdir(parents=True, exist_ok=True)

    def generate(self) -> dict:
        filename_base = self._safe_name(
            self.results.get("file_info", {}).get("filename", "unknown")
        )
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        base = f"{filename_base}_{ts}"

        json_path = os.path.join(self.output_dir, f"{base}_report.json")
        txt_path  = os.path.join(self.output_dir, f"{base}_report.txt")

        # Clean results for JSON serialisation (remove raw bytes etc.)
        clean = self._clean_for_json(self.results)
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(clean, f, indent=2, default=str)

        with open(txt_path, "w", encoding="utf-8") as f:
            f.write(self._build_txt_report(clean))

        return {"json": json_path, "txt": txt_path}

    # ──────────────────────────────────────────────────────────────
    def _build_txt_report(self, r: dict) -> str:
        lines = []
        fi    = r.get("file_info", {})
        risk  = r.get("risk", {})
        meta  = r.get("metadata", {})
        ioc   = r.get("iocs", {})
        js    = r.get("javascript", {})
        kw    = r.get("keywords", {})
        obj   = r.get("objects", {})
        ts    = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        def sep(char="═", n=66):
            return char * n

        lines += [
            sep(),
            "  PMAT — PDF MALWARE ANALYSIS TOOLKIT  v1.0",
            "  Automated Static Analysis Report",
            sep(),
            f"  Generated   : {ts}",
            f"  Analyst     : PMAT Automated Engine",
            sep("─"),
            "",
            "  [1] FILE INFORMATION",
            sep("─"),
            f"  Filename    : {fi.get('filename','N/A')}",
            f"  File Size   : {fi.get('size_human','N/A')}",
            f"  MD5         : {fi.get('md5','N/A')}",
            f"  SHA-1       : {fi.get('sha1','N/A')}",
            f"  SHA-256     : {fi.get('sha256','N/A')}",
            f"  PDF Version : {fi.get('pdf_version','N/A')}",
            f"  Valid PDF   : {fi.get('is_pdf','N/A')}",
            "",
            "  [2] RISK ASSESSMENT",
            sep("─"),
            f"  RISK SCORE  : {risk.get('score', 0)}/100",
            f"  SEVERITY    : {risk.get('severity', 'UNKNOWN')}",
            "",
            "  Score Breakdown:",
        ]
        for item in risk.get("breakdown", []):
            lines.append(f"    {item}")

        lines += ["", "  [3] METADATA", sep("─")]
        for k, v in meta.get("fields", {}).items():
            if v:
                lines.append(f"  {k:16s}: {v}")
        if meta.get("anomalies"):
            lines.append("\n  Metadata Anomalies:")
            for a in meta["anomalies"]:
                lines.append(f"    [!] {a}")

        lines += ["", "  [4] SUSPICIOUS KEYWORDS", sep("─")]
        if kw.get("found"):
            for item in kw["found"]:
                lines.append(f"  [{item['severity']:8s}] {item['keyword']:22s}  count={item['count']}  +{item['score']}pts")
        else:
            lines.append("  No suspicious keywords found.")

        lines += ["", "  [5] OBJECT ANALYSIS", sep("─"),
                  f"  Total Objects : {obj.get('total_objects',0)}",
                  f"  Total Streams : {obj.get('total_streams',0)}",
                  f"  Page Count    : {obj.get('page_count',0)}"]
        if obj.get("suspicious_objects"):
            lines.append("\n  Suspicious Objects:")
            for o in obj["suspicious_objects"]:
                lines.append(f"    [{o['severity']:8s}] obj#{o['id']:>4s}  {o['keyword']:20s}  {o['reason']}")
        if obj.get("filter_chains"):
            lines.append("\n  Multi-Filter Chains:")
            for fc in obj["filter_chains"]:
                lines.append(f"    [!] {fc}")

        lines += ["", "  [6] INDICATORS OF COMPROMISE (IOCs)", sep("─")]
        if ioc.get("cves"):
            lines.append("  CVEs Detected:")
            for c in ioc["cves"]:
                lines.append(f"    [CRITICAL] {c}")
        if ioc.get("urls"):
            lines.append("  URLs Found:")
            for u in ioc["urls"]:
                lines.append(f"    [URL] {u}")
        if ioc.get("ips"):
            lines.append("  IP Addresses:")
            for ip in ioc["ips"]:
                lines.append(f"    [IP]  {ip}")
        if ioc.get("emails"):
            lines.append("  Email Addresses:")
            for e in ioc["emails"]:
                lines.append(f"    [EMAIL] {e}")
        if ioc.get("embedded_files"):
            lines.append("  Embedded Files:")
            for ef in ioc["embedded_files"]:
                lines.append(f"    [FILE] {ef}")
        if not any([ioc.get("cves"), ioc.get("urls"), ioc.get("ips"),
                    ioc.get("embedded_files")]):
            lines.append("  No IOCs detected.")

        lines += ["", "  [7] JAVASCRIPT ANALYSIS", sep("─"),
                  f"  JS Blocks Found : {js.get('js_block_count',0)}"]
        if js.get("auto_actions"):
            lines.append("  Auto-Execute Actions:")
            for a in js["auto_actions"]:
                lines.append(f"    [!] {a}")
        if js.get("obfuscation_patterns"):
            lines.append("  Obfuscation Patterns:")
            for p in js["obfuscation_patterns"]:
                lines.append(f"    [!] {p}")
        if js.get("risk_indicators"):
            lines.append("  Risk Indicators:")
            for ri in js["risk_indicators"]:
                lines.append(f"    [!] {ri}")
        if js.get("js_blocks"):
            lines.append("  JS Snippets (first 3):")
            for snippet in js["js_blocks"][:3]:
                lines.append(f"    >>> {snippet[:120]!r}")

        lines += ["", "  [8] MITIGATION RECOMMENDATIONS", sep("─")]
        for i, mit in enumerate(risk.get("mitigations", []), 1):
            lines.append(f"  {i:2d}. {mit}")

        lines += [
            "",
            sep(),
            "  END OF REPORT — PMAT PDF Malware Analysis Toolkit",
            f"  Analysis time: {r.get('analysis_time_seconds','?')}s",
            sep(),
        ]
        return "\n".join(lines)

    def _clean_for_json(self, obj):
        if isinstance(obj, dict):
            return {k: self._clean_for_json(v) for k, v in obj.items()
                    if k not in ("_raw_bytes",)}
        if isinstance(obj, (list, tuple)):
            return [self._clean_for_json(i) for i in obj]
        if isinstance(obj, bytes):
            return obj.decode("latin-1", errors="replace")[:500]
        return obj

    @staticmethod
    def _safe_name(name: str) -> str:
        return re.sub(r"[^a-zA-Z0-9_\-]", "_", name)[:40]
