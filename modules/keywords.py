"""
modules/keywords.py — STEP 4: Keyword-Based Threat Detection
Scans all PDF content for attack-related keywords and assigns risk weights.
"""

import re


class KeywordScanner:
    """
    Scans raw PDF bytes for known malicious keywords.
    Each keyword carries a severity level and a risk score contribution.
    """

    # (keyword, severity_label, score_points, description)
    KEYWORD_DB = [
        # Critical — direct code execution
        ("/JavaScript",    "CRITICAL", 10, "Embedded JavaScript execution"),
        ("/JS",            "CRITICAL", 10, "JavaScript shorthand"),
        ("/OpenAction",    "HIGH",      8, "Auto-execute on document open"),
        ("/Launch",        "CRITICAL", 10, "External process launch"),

        # High — payload delivery
        ("/EmbeddedFile",  "HIGH",      7, "Embedded file payload"),
        ("/XFA",           "HIGH",      6, "XFA form exploit surface"),
        ("/RichMedia",     "HIGH",      5, "Rich media exploit surface"),

        # Medium — suspicious structures
        ("/AcroForm",      "MEDIUM",    4, "Acrobat form (data exfil risk)"),
        ("/AA",            "MEDIUM",    4, "Additional Actions hook"),
        ("/SubmitForm",    "MEDIUM",    5, "Form data submission"),
        ("/ImportData",    "MEDIUM",    4, "External data import"),
        ("/GoToR",         "MEDIUM",    3, "Remote document reference"),
        ("/URI",           "MEDIUM",    3, "External URL reference"),

        # Stream obfuscation
        ("/ObjStm",        "LOW",       3, "Object stream (may hide objects)"),
        ("/ASCIIHexDecode","LOW",       2, "ASCII hex encoded stream"),
        ("/ASCII85Decode", "LOW",       2, "ASCII85 encoded stream"),

        # Known exploit strings
        ("getAnnots",      "HIGH",      8, "Known exploit method (CVE-2009-0927)"),
        ("getIcon",        "HIGH",      8, "Known exploit method"),
        ("spell.customDictionaryOpen", "CRITICAL", 10, "CVE-2009-0927 exploit string"),
        ("media.newPlayer", "CRITICAL", 10, "CVE-2009-4324 exploit string"),
        ("Collab.collectEmailInfo", "CRITICAL", 10, "CVE-2007-0478 exploit string"),
        ("util.printf",    "HIGH",      9, "CVE-2008-2992 format string exploit"),
        ("app.doc",        "MEDIUM",    4, "Document access via app object"),

        # Obfuscation indicators
        ("eval(",          "HIGH",      7, "Dynamic code evaluation"),
        ("unescape(",      "HIGH",      6, "String unescaping obfuscation"),
        ("String.fromCharCode", "HIGH", 6, "Char-code obfuscation"),
        ("this.exportDataObject", "HIGH", 8, "File export function"),
    ]

    def __init__(self, path: str):
        self.path = path
        self.raw = b""
        try:
            with open(path, "rb") as f:
                self.raw = f.read()
        except Exception:
            pass
        self.text = self.raw.decode("latin-1", errors="replace")

    def scan(self) -> dict:
        result = {
            "found": [],
            "total_score": 0,
            "scanned_bytes": len(self.raw),
        }

        # Also decode and scan any hex-encoded sections
        hex_decoded = self._decode_hex_sections(self.text)
        combined_text = self.text + "\n" + hex_decoded

        for keyword, severity, score, description in self.KEYWORD_DB:
            # Case-insensitive count
            count = combined_text.lower().count(keyword.lower())
            if count > 0:
                # Also find context snippets
                contexts = self._get_contexts(combined_text, keyword)
                result["found"].append({
                    "keyword":     keyword,
                    "severity":    severity,
                    "score":       score,
                    "count":       count,
                    "description": description,
                    "contexts":    contexts[:2],  # Up to 2 snippets
                })
                result["total_score"] += score

        # Deduplicate overlapping /JavaScript and /JS scores
        js_hits = [f for f in result["found"] if f["keyword"] in ("/JavaScript", "/JS")]
        if len(js_hits) == 2:
            result["total_score"] -= 10  # Only count once

        return result

    def _get_contexts(self, text: str, keyword: str, window: int = 60) -> list:
        """Extract short context snippets around each keyword hit."""
        snippets = []
        lower_text = text.lower()
        lower_kw   = keyword.lower()
        pos = 0
        while True:
            idx = lower_text.find(lower_kw, pos)
            if idx == -1:
                break
            start = max(0, idx - window)
            end   = min(len(text), idx + len(keyword) + window)
            snippet = text[start:end].replace("\n", " ").replace("\r", "").strip()
            snippets.append(snippet)
            pos = idx + len(keyword)
            if len(snippets) >= 3:
                break
        return snippets

    def _decode_hex_sections(self, text: str) -> str:
        """Decode hex-encoded strings like <68656c6c6f> found in PDF content."""
        decoded_parts = []
        for match in re.finditer(r"<([0-9a-fA-F\s]{4,})>", text):
            hex_str = match.group(1).replace(" ", "")
            try:
                if len(hex_str) % 2 == 0:
                    decoded_parts.append(bytes.fromhex(hex_str).decode("latin-1", errors="replace"))
            except Exception:
                pass
        return " ".join(decoded_parts)
