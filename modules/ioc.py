"""
modules/ioc.py — STEP 6: Indicator of Compromise (IOC) Extraction
Extracts URLs, IPs, CVEs, emails, embedded files, and other threat indicators.
"""

import re


class IOCExtractor:
    """
    Extracts all Indicators of Compromise from decoded PDF content.
    Deduplicates and categorises each IOC type.
    """

    # CVE patterns used in well-known PDF exploits
    KNOWN_PDF_CVES = {
        "CVE-2007-0478": "Adobe Acrobat/Reader Buffer Overflow",
        "CVE-2008-2992": "Adobe Reader util.printf() Stack Overflow",
        "CVE-2009-0927": "Adobe Reader getIcon() Stack Overflow (Collab object)",
        "CVE-2009-4324": "Adobe Reader media.newPlayer() Use-After-Free",
        "CVE-2010-0188": "Adobe Reader LibTIFF Integer Overflow",
        "CVE-2010-1240": "PDF Launch Action Social Engineering",
        "CVE-2013-2729": "Adobe Reader BMP RLE Heap Overflow",
        "CVE-2015-3073": "Adobe Reader Memory Corruption",
        "CVE-2018-4990": "Adobe Acrobat Double Free",
        "CVE-2019-7089": "Adobe Reader Information Disclosure",
        "CVE-2021-28550": "Adobe Acrobat Use-After-Free RCE",
    }

    # Exploit method → CVE mapping for implicit detection
    EXPLOIT_STRINGS = {
        "spell.customDictionaryOpen": "CVE-2009-0927",
        "media.newPlayer":            "CVE-2009-4324",
        "Collab.collectEmailInfo":    "CVE-2007-0478",
        "util.printf":                "CVE-2008-2992",
        "getIcon":                    "CVE-2009-0927",
        "this.exportDataObject":      "CVE-generic-exportDataObject",
    }

    def __init__(self, path: str, decoded_text: str):
        self.path         = path
        self.decoded_text = decoded_text
        self.raw          = b""
        try:
            with open(path, "rb") as f:
                self.raw = f.read()
        except Exception:
            pass
        self.raw_text = self.raw.decode("latin-1", errors="replace")
        self.full_text = self.raw_text + "\n" + decoded_text

    def extract(self) -> dict:
        result = {
            "urls":           [],
            "ips":            [],
            "emails":         [],
            "cves":           [],
            "embedded_files": [],
            "exploit_strings":[],
            "domains":        [],
            "total":          0,
        }

        # ── URLs ──────────────────────────────────────────────────
        url_pattern = re.compile(
            r'https?://[^\s\)\]\>"\'<\x00-\x1f]{4,}',
            re.IGNORECASE
        )
        result["urls"] = self._dedup(url_pattern.findall(self.full_text))

        # Also extract from /URI objects specifically
        uri_pattern = re.compile(r"/URI\s*\(([^)]+)\)", re.IGNORECASE)
        for match in uri_pattern.finditer(self.full_text):
            url = match.group(1).strip()
            if url not in result["urls"]:
                result["urls"].append(url)

        # ── IP Addresses ──────────────────────────────────────────
        ip_pattern = re.compile(
            r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
            r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
        )
        raw_ips = ip_pattern.findall(self.full_text)
        # Filter out PDF version strings like 1.4, and common non-IP patterns
        result["ips"] = self._dedup([
            ip for ip in raw_ips
            if not ip.startswith(("0.", "127.", "255.")) and ip != "0.0.0.0"
        ])

        # ── Email Addresses ───────────────────────────────────────
        email_pattern = re.compile(
            r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}',
            re.IGNORECASE
        )
        result["emails"] = self._dedup(email_pattern.findall(self.full_text))

        # ── CVE References ────────────────────────────────────────
        cve_pattern = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)
        explicit_cves = cve_pattern.findall(self.full_text)

        # Implicit CVE detection via exploit method names
        for method, cve in self.EXPLOIT_STRINGS.items():
            if method.lower() in self.full_text.lower():
                desc = self.KNOWN_PDF_CVES.get(cve, "Known exploit method")
                entry = f"{cve} (implicit — method '{method}' detected): {desc}"
                if entry not in result["cves"]:
                    result["cves"].append(entry)
                result["exploit_strings"].append(method)

        for cve in explicit_cves:
            cve_upper = cve.upper()
            desc = self.KNOWN_PDF_CVES.get(cve_upper, "CVE referenced in PDF")
            entry = f"{cve_upper}: {desc}"
            if entry not in result["cves"]:
                result["cves"].append(entry)

        # ── Embedded Files ────────────────────────────────────────
        # From /EmbeddedFile with /F filename
        ef_pattern = re.compile(
            r"/EmbeddedFile.*?/F\s*\(([^)]+)\)",
            re.IGNORECASE | re.DOTALL
        )
        for m in ef_pattern.finditer(self.full_text):
            fname = m.group(1).strip()
            if fname not in result["embedded_files"]:
                result["embedded_files"].append(fname)

        # Also check /Filespec objects
        fs_pattern = re.compile(r"/F\s*\(([^)]{3,100}\.(?:exe|dll|vbs|js|bat|ps1|sh|py|jar|cmd|scr|com|bin|dat))\)",
                                 re.IGNORECASE)
        for m in fs_pattern.finditer(self.full_text):
            fname = m.group(1).strip()
            if fname not in result["embedded_files"]:
                result["embedded_files"].append(fname)

        # ── Domains (extracted from URLs) ─────────────────────────
        domain_pattern = re.compile(r'https?://([^/\s\)\]>]+)', re.IGNORECASE)
        result["domains"] = self._dedup(domain_pattern.findall(" ".join(result["urls"])))

        # ── Totals ────────────────────────────────────────────────
        result["total"] = (len(result["urls"]) + len(result["ips"]) +
                           len(result["cves"]) + len(result["embedded_files"]))
        return result

    @staticmethod
    def _dedup(lst: list) -> list:
        seen = set()
        out  = []
        for item in lst:
            if item not in seen:
                seen.add(item)
                out.append(item)
        return out
