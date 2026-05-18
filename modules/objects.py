"""
modules/objects.py — STEP 3: Object Enumeration & Structure Analysis
Parses the PDF object tree and flags suspicious object types.
"""

import re


class ObjectEnumerator:
    """Enumerates all PDF objects and identifies suspicious entries."""

    # Objects that are commonly abused in malicious PDFs
    SUSPICIOUS_TYPES = {
        "/JavaScript":   ("HIGH",     "Embedded JavaScript code — can execute on open"),
        "/JS":           ("HIGH",     "JavaScript shorthand — executable code"),
        "/OpenAction":   ("HIGH",     "Action triggered automatically on document open"),
        "/Launch":       ("CRITICAL", "Launches external application or command"),
        "/EmbeddedFile": ("HIGH",     "File embedded inside PDF — possible payload"),
        "/XFA":          ("HIGH",     "XML Form Architecture — used in targeted exploits"),
        "/AcroForm":     ("MEDIUM",   "Acrobat form — may contain form-based attacks"),
        "/RichMedia":    ("MEDIUM",   "Rich media (Flash/video) — exploit surface"),
        "/AA":           ("MEDIUM",   "Additional Actions — auto-triggered events"),
        "/URI":          ("MEDIUM",   "External URL reference"),
        "/SubmitForm":   ("MEDIUM",   "Form submission action — data exfiltration risk"),
        "/ImportData":   ("MEDIUM",   "Imports data from external source"),
        "/GoToR":        ("LOW",      "Go-To Remote action — links to external document"),
        "/ObjStm":       ("LOW",      "Object stream — may hide objects from parsers"),
        "/Filter":       ("INFO",     "Stream filter — check for unusual encoding chains"),
    }

    def __init__(self, path: str):
        self.path = path
        self.raw = b""
        try:
            with open(path, "rb") as f:
                self.raw = f.read()
        except Exception:
            pass
        self.text = self.raw.decode("latin-1", errors="replace")

    def enumerate(self) -> dict:
        result = {
            "total_objects": 0,
            "total_streams": 0,
            "page_count": 0,
            "suspicious_objects": [],
            "object_types": {},
            "filter_chains": [],
        }

        # ── Count objects using pikepdf ────────────────────────────
        try:
            import pikepdf
            with pikepdf.open(self.path, suppress_warnings=True) as pdf:
                result["page_count"] = len(pdf.pages)

                obj_count = 0
                stream_count = 0

                for obj in pdf.objects:
                    if obj is None:
                        continue
                    obj_count += 1
                    if isinstance(obj, pikepdf.Stream):
                        stream_count += 1

                # Count by walking xref table approach via raw regex
                result["total_objects"]  = max(obj_count, self._count_objects_raw())
                result["total_streams"]  = stream_count

        except Exception:
            result["total_objects"] = self._count_objects_raw()
            result["total_streams"] = len(re.findall(rb"\bstream\b", self.raw))
            result["page_count"]    = len(re.findall(rb"/Type\s*/Page\b", self.raw))

        # ── Detect suspicious object types via raw regex ──────────
        found_types = {}
        for keyword, (severity, reason) in self.SUSPICIOUS_TYPES.items():
            pattern = keyword.replace("/", r"\/").encode()
            matches = re.findall(pattern, self.raw, re.IGNORECASE)
            if matches:
                count = len(matches)
                found_types[keyword] = count

                # Find which object IDs contain this keyword
                obj_ids = self._find_containing_objects(keyword.encode())

                result["suspicious_objects"].append({
                    "id":       obj_ids[0] if obj_ids else "unknown",
                    "keyword":  keyword,
                    "count":    count,
                    "severity": severity,
                    "reason":   reason,
                    "all_ids":  obj_ids[:5],  # limit to first 5
                })

        result["object_types"] = found_types

        # ── Detect filter chains (multiple encodings stacked) ──────
        filter_chains = re.findall(
            rb"/Filter\s*\[([^\]]+)\]",
            self.raw
        )
        for chain in filter_chains:
            decoded = chain.decode("latin-1", errors="replace").strip()
            if decoded.count("/") > 1:
                result["filter_chains"].append(f"Multi-filter chain: {decoded}")

        return result

    def _count_objects_raw(self) -> int:
        """Count 'X Y obj' patterns in raw PDF bytes."""
        matches = re.findall(rb"\d+\s+\d+\s+obj", self.raw)
        return len(matches)

    def _find_containing_objects(self, keyword: bytes) -> list:
        """Find object IDs (e.g. '14 0 obj') that contain the given keyword."""
        obj_pattern = re.compile(rb"(\d+)\s+(\d+)\s+obj(.*?)endobj", re.DOTALL)
        ids = []
        for match in obj_pattern.finditer(self.raw):
            if keyword.lower() in match.group(3).lower():
                ids.append(f"{match.group(1).decode()}")
        return ids
