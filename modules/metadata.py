"""
modules/metadata.py — STEP 2: Metadata Extraction & Anomaly Detection
Extracts PDF document metadata and flags suspicious anomalies.
"""

import re
from datetime import datetime


class MetadataExtractor:
    """Extracts and analyses PDF metadata for suspicious indicators."""

    SUSPICIOUS_PRODUCERS = [
        "exploit", "shellcode", "payload", "metasploit", "msfvenom",
        "malkit", "injector", "crypter", "packer", "obfus"
    ]

    def __init__(self, path: str, load_result: dict):
        self.path = path
        self.raw = load_result.get("_raw_bytes", b"")

    def extract(self) -> dict:
        result = {
            "fields": {},
            "anomalies": [],
            "pdf_version": "unknown",
            "revision_count": 0,
        }

        # ── Try pikepdf first (most reliable) ──────────────────────
        try:
            import pikepdf
            with pikepdf.open(self.path, suppress_warnings=True) as pdf:
                meta = pdf.open_metadata()
                docinfo = pdf.docinfo

                def _str(val):
                    try:
                        return str(val).strip() if val else ""
                    except Exception:
                        return ""

                result["fields"] = {
                    "Title":        _str(docinfo.get("/Title")),
                    "Author":       _str(docinfo.get("/Author")),
                    "Subject":      _str(docinfo.get("/Subject")),
                    "Creator":      _str(docinfo.get("/Creator")),
                    "Producer":     _str(docinfo.get("/Producer")),
                    "CreationDate": _str(docinfo.get("/CreationDate")),
                    "ModDate":      _str(docinfo.get("/ModDate")),
                    "Keywords":     _str(docinfo.get("/Keywords")),
                }
                result["pdf_version"] = str(pdf.pdf_version)
                result["revision_count"] = len(pdf.root.get("/XRef", {}).get("/Prev", [])) if "/XRef" in pdf.root else 1

        except Exception:
            # Fallback: regex-based extraction from raw bytes
            result["fields"] = self._regex_extract()

        # ── Anomaly Detection ───────────────────────────────────────
        fields = result["fields"]

        # Mismatch between creation and modification dates
        created = fields.get("CreationDate", "")
        modified = fields.get("ModDate", "")
        if created and modified and created != modified:
            result["anomalies"].append(
                f"[DATE MISMATCH] Created: {created}  Modified: {modified} — possible tampering"
            )

        # Suspicious producer string
        producer = fields.get("Producer", "").lower()
        for kw in self.SUSPICIOUS_PRODUCERS:
            if kw in producer:
                result["anomalies"].append(
                    f"[SUSPICIOUS PRODUCER] Producer field contains '{kw}': {fields['Producer']}"
                )

        # Empty author / suspicious author
        author = fields.get("Author", "").strip()
        if not author:
            result["anomalies"].append("[METADATA] Author field is empty — common in automated/malicious PDFs")

        # Check for incremental updates (multiple %%EOF markers = possible injected content)
        eof_count = self.raw.count(b"%%EOF")
        if eof_count > 1:
            result["anomalies"].append(
                f"[INCREMENTAL UPDATE] {eof_count} %%EOF markers found — document may have been modified/injected"
            )
            result["revision_count"] = eof_count

        # Very large number of pages relative to file size (padding)
        try:
            import pikepdf
            with pikepdf.open(self.path, suppress_warnings=True) as pdf:
                pages = len(pdf.pages)
                size_kb = len(self.raw) / 1024
                if pages > 0 and size_kb / pages < 0.5:
                    result["anomalies"].append(
                        f"[ANOMALY] Very small average page size ({size_kb/pages:.1f} KB/page) — may indicate hidden content"
                    )
        except Exception:
            pass

        return result

    def _regex_extract(self) -> dict:
        """Fallback: extract metadata via regex on raw bytes."""
        text = self.raw.decode("latin-1", errors="replace")
        fields = {}
        for key in ["Title", "Author", "Subject", "Creator", "Producer",
                    "CreationDate", "ModDate", "Keywords"]:
            match = re.search(rf"/{key}\s*\(([^)]*)\)", text)
            fields[key] = match.group(1).strip() if match else ""
        return fields
