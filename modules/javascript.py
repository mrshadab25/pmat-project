"""
modules/javascript.py — STEP 7: JavaScript Analysis & Obfuscation Detection
Extracts, deobfuscates, and analyses JavaScript embedded in PDF files.
"""

import re
import base64


class JavaScriptAnalyzer:
    """
    Extracts JavaScript from PDF objects and detects obfuscation, exploit
    patterns, and auto-execute triggers.
    """

    OBFUSCATION_PATTERNS = [
        (r"\beval\s*\(",          "HIGH",     "eval() — dynamic code execution"),
        (r"\bunescape\s*\(",      "HIGH",     "unescape() — string obfuscation"),
        (r"String\.fromCharCode", "HIGH",     "String.fromCharCode() — char-code obfuscation"),
        (r"document\.write\s*\(", "MEDIUM",   "document.write() — dynamic DOM injection"),
        (r"\\x[0-9a-fA-F]{2}",   "MEDIUM",   "Hex character escapes in strings"),
        (r"\\u[0-9a-fA-F]{4}",   "MEDIUM",   "Unicode escapes in strings"),
        (r"atob\s*\(",            "HIGH",     "atob() — base64 decode in JS"),
        (r"decodeURIComponent\s*\(","MEDIUM", "decodeURIComponent() — URL decoding"),
        (r"setTimeout\s*\(",      "LOW",      "setTimeout() — delayed execution (sandbox evasion)"),
        (r"setInterval\s*\(",     "LOW",      "setInterval() — periodic execution"),
        (r"new\s+ActiveXObject",  "CRITICAL", "ActiveXObject — Windows COM/shell access"),
        (r"WScript\.Shell",       "CRITICAL", "WScript.Shell — shell command execution"),
        (r"powershell",           "CRITICAL", "PowerShell invocation detected"),
        (r"cmd\.exe",             "CRITICAL", "cmd.exe shell launch detected"),
        (r"\.exe[\"'\s]",         "HIGH",     "Executable file reference in JS"),
        (r"shellcode",            "CRITICAL", "Explicit 'shellcode' string reference"),
        (r"spray\s*\(",           "HIGH",     "Heap spray function — memory exploit technique"),
        (r"app\.openDoc\s*\(",    "HIGH",     "app.openDoc() — opens files via JS"),
        (r"this\.exportDataObject","HIGH",    "exportDataObject() — extracts embedded files"),
        (r"app\.launchURL\s*\(",  "HIGH",     "launchURL() — opens URLs from JS"),
        (r"this\.submitForm\s*\(","MEDIUM",   "submitForm() — data exfiltration"),
    ]

    AUTO_ACTIONS = [
        ("/OpenAction",  "CRITICAL", "Executes on document open"),
        ("/AA",          "HIGH",     "Additional Actions — event-triggered execution"),
        ("/Trigger",     "HIGH",     "Trigger action"),
        ("/WillClose",   "MEDIUM",   "WillClose event handler"),
        ("/WillSave",    "MEDIUM",   "WillSave event handler"),
        ("/DidSave",     "MEDIUM",   "DidSave event handler"),
        ("/WillPrint",   "MEDIUM",   "WillPrint event handler"),
    ]

    def __init__(self, path: str, decoded_text: str, obj_result: dict):
        self.path         = path
        self.decoded_text = decoded_text
        self.obj_result   = obj_result
        self.raw          = b""
        try:
            with open(path, "rb") as f:
                self.raw = f.read()
        except Exception:
            pass
        self.raw_text = self.raw.decode("latin-1", errors="replace")
        self.full_text = self.raw_text + "\n" + decoded_text

    def analyze(self) -> dict:
        result = {
            "js_block_count":      0,
            "js_blocks":           [],
            "obfuscation_patterns":[],
            "auto_actions":        [],
            "deobfuscated":        [],
            "risk_indicators":     [],
        }

        # ── Extract JS blocks ─────────────────────────────────────
        js_blocks = self._extract_js_blocks()
        result["js_block_count"] = len(js_blocks)
        result["js_blocks"]      = js_blocks[:5]  # Store up to 5

        # ── Detect obfuscation patterns ───────────────────────────
        combined = self.full_text
        for pattern, severity, description in self.OBFUSCATION_PATTERNS:
            if re.search(pattern, combined, re.IGNORECASE):
                entry = f"[{severity}] {description}"
                if entry not in result["obfuscation_patterns"]:
                    result["obfuscation_patterns"].append(entry)

        # ── Detect auto-execute actions ───────────────────────────
        for action_kw, severity, description in self.AUTO_ACTIONS:
            if action_kw.lower() in combined.lower():
                result["auto_actions"].append(f"[{severity}] {action_kw}: {description}")

        # ── Attempt simple deobfuscation ─────────────────────────
        for block in js_blocks[:3]:
            deobfuscated = self._simple_deobfuscate(block)
            if deobfuscated and deobfuscated != block:
                result["deobfuscated"].append({
                    "original_snippet": block[:100],
                    "deobfuscated":     deobfuscated[:300],
                })

        # ── Detect heap spray pattern ─────────────────────────────
        if self._detect_heap_spray(combined):
            result["risk_indicators"].append(
                "[CRITICAL] Heap spray pattern detected — common exploit memory preparation"
            )

        # ── Detect NOP sled or shellcode bytes ───────────────────
        if self._detect_shellcode_bytes():
            result["risk_indicators"].append(
                "[CRITICAL] High-frequency repeating byte patterns consistent with NOP sled / shellcode"
            )

        return result

    def _extract_js_blocks(self) -> list:
        """Extract JavaScript code blocks from raw PDF and decoded streams."""
        blocks = []

        # Method 1: /JS ( ... ) or /JS << ... >>
        js_parens = re.findall(
            r"/(?:JS|JavaScript)\s*\(([^)]{10,})\)",
            self.full_text, re.IGNORECASE
        )
        blocks.extend(js_parens)

        # Method 2: Stream content after /JavaScript entry
        js_stream = re.findall(
            r"/(?:JS|JavaScript)[^>]*>>[^<]*<<[^>]*>>\s*stream\s*(.*?)\s*endstream",
            self.full_text, re.IGNORECASE | re.DOTALL
        )
        blocks.extend([s.strip() for s in js_stream if len(s.strip()) > 10])

        # Method 3: Recognisable JS patterns in decoded streams
        js_patterns = re.findall(
            r"(?:function\s+\w+\s*\([^)]*\)\s*\{|var\s+\w+\s*=.{10,}|eval\s*\([^)]+\))",
            self.full_text, re.IGNORECASE
        )
        blocks.extend(js_patterns[:10])

        return [b.strip() for b in blocks if b.strip()]

    def _simple_deobfuscate(self, js_text: str) -> str:
        """Attempt basic deobfuscation: fromCharCode, hex escapes, simple eval."""
        result = js_text

        # Decode \xNN hex escapes
        result = re.sub(
            r"\\x([0-9a-fA-F]{2})",
            lambda m: chr(int(m.group(1), 16)),
            result
        )

        # Decode \uNNNN unicode escapes
        result = re.sub(
            r"\\u([0-9a-fA-F]{4})",
            lambda m: chr(int(m.group(1), 16)),
            result
        )

        # Resolve String.fromCharCode([...])
        def resolve_charcode(m):
            try:
                nums = [int(x.strip()) for x in m.group(1).split(",")]
                return "\"" + "".join(chr(n) for n in nums if 0 <= n < 65536) + "\""
            except Exception:
                return m.group(0)

        result = re.sub(
            r"String\.fromCharCode\s*\(([^)]+)\)",
            resolve_charcode,
            result
        )

        return result

    def _detect_heap_spray(self, text: str) -> bool:
        """Detect heap spray patterns (repeated strings/NOP sequences in JS)."""
        # Look for large string repetition: var x = "...".repeat(N) or similar
        patterns = [
            r'\.repeat\s*\(\s*\d{3,}\s*\)',
            r'for\s*\([^)]*\d{4,}[^)]*\).*?\+[=\+]',  # long loop building string
            r'"[\\x\w]{8,}".*?\*\s*\d{3,}',
        ]
        for p in patterns:
            if re.search(p, text, re.IGNORECASE | re.DOTALL):
                return True
        return False

    def _detect_shellcode_bytes(self) -> bool:
        """Detect repeating byte sequences (NOP 0x90 sled or similar) in raw bytes."""
        # NOP sled: long runs of 0x90
        if b"\x90" * 16 in self.raw:
            return True
        # Common shellcode prologue patterns
        for pattern in [b"\xeb\x0e", b"\x31\xc0\x50", b"\x55\x8b\xec"]:
            if self.raw.count(pattern) > 2:
                return True
        return False
