"""
modules/streams.py — STEP 5: Stream Decoding & Content Extraction
Decompresses and decodes all encoded PDF streams (FlateDecode, ASCIIHex, ASCII85, etc.)
"""

import re
import zlib
import base64
import math
import struct


class StreamDecoder:
    """
    Decodes all compressed/encoded streams inside a PDF.
    Detects high-entropy regions that may indicate shellcode or encrypted payloads.
    """

    def __init__(self, path: str):
        self.path = path
        self.raw = b""
        try:
            with open(path, "rb") as f:
                self.raw = f.read()
        except Exception:
            pass

    def decode(self) -> dict:
        result = {
            "decoded_count":        0,
            "failed_count":         0,
            "encoding_types":       set(),
            "high_entropy_streams": 0,
            "decoded_text":         "",
            "stream_details":       [],
        }

        all_text_parts = []

        # Add raw text (latin-1 decoded) as baseline
        raw_text = self.raw.decode("latin-1", errors="replace")
        all_text_parts.append(raw_text)

        # ── Extract and decode all streams ────────────────────────
        stream_pattern = re.compile(
            rb"(<<[^>]*>>)\s*stream\r?\n(.*?)\r?\nendstream",
            re.DOTALL
        )

        for i, match in enumerate(stream_pattern.finditer(self.raw)):
            header_bytes = match.group(1)
            stream_data  = match.group(2)
            header_text  = header_bytes.decode("latin-1", errors="replace")

            detail = {
                "index":    i,
                "size":     len(stream_data),
                "filters":  [],
                "decoded":  False,
                "text_snippet": "",
                "entropy":  0.0,
            }

            # Calculate entropy of raw stream
            detail["entropy"] = self._entropy(stream_data)
            if detail["entropy"] > 7.0 and len(stream_data) > 100:
                result["high_entropy_streams"] += 1

            # Determine filter(s)
            filters = self._extract_filters(header_text)
            detail["filters"] = filters

            # Attempt decoding through the filter chain
            decoded_data = stream_data
            success = True

            for filt in filters:
                result["encoding_types"].add(filt)
                decoded_data, ok = self._apply_filter(filt, decoded_data)
                if not ok:
                    success = False
                    break

            if success and decoded_data:
                detail["decoded"] = True
                result["decoded_count"] += 1
                decoded_text = decoded_data.decode("latin-1", errors="replace")
                detail["text_snippet"] = decoded_text[:200]
                all_text_parts.append(decoded_text)
            else:
                result["failed_count"] += 1

            result["stream_details"].append(detail)

        # ── Also try decoding base64 blobs ────────────────────────
        b64_decoded = self._decode_base64_blobs(raw_text)
        if b64_decoded:
            all_text_parts.extend(b64_decoded)

        result["encoding_types"] = sorted(list(result["encoding_types"]))
        result["decoded_text"]   = "\n".join(all_text_parts)
        return result

    def _extract_filters(self, header: str) -> list:
        """Extract filter list from stream dictionary header."""
        filters = []
        # /Filter /FlateDecode
        single = re.search(r"/Filter\s*/(\w+)", header)
        if single:
            filters.append(single.group(1))
        # /Filter [/FlateDecode /ASCIIHexDecode]
        array = re.search(r"/Filter\s*\[([^\]]+)\]", header)
        if array:
            found = re.findall(r"/(\w+)", array.group(1))
            filters.extend(found)
        return filters

    def _apply_filter(self, filter_name: str, data: bytes) -> tuple:
        """Apply a single PDF stream filter. Returns (decoded_bytes, success)."""
        try:
            fn = filter_name.lower().replace("decode", "").replace("filter", "")

            if fn in ("flate", "flat", "fl"):
                return zlib.decompress(data), True

            elif fn in ("asciihex", "ahx"):
                hex_str = data.decode("latin-1", errors="replace").replace(" ", "").replace("\n", "").rstrip(">")
                return bytes.fromhex(hex_str), True

            elif fn in ("ascii85", "a85"):
                return self._ascii85_decode(data), True

            elif fn in ("lzw",):
                # LZW not in stdlib — return as-is with flag
                return data, True

            elif fn in ("runlength", "rl"):
                return self._runlength_decode(data), True

            else:
                # Unknown filter — pass through
                return data, True

        except Exception:
            return data, False

    def _ascii85_decode(self, data: bytes) -> bytes:
        """Decode ASCII85 encoded stream."""
        s = data.decode("latin-1", errors="replace").strip()
        if s.endswith("~>"):
            s = s[:-2]
        result = bytearray()
        group = []
        for c in s:
            if c == "z":
                result.extend(b"\x00" * 4)
            elif "!" <= c <= "u":
                group.append(ord(c) - 33)
                if len(group) == 5:
                    val = (group[0]*85**4 + group[1]*85**3 +
                           group[2]*85**2 + group[3]*85 + group[4])
                    result.extend(struct.pack(">I", val))
                    group = []
        if group:
            group += [84] * (5 - len(group))
            val = (group[0]*85**4 + group[1]*85**3 +
                   group[2]*85**2 + group[3]*85 + group[4])
            n = len(group) - 1
            result.extend(struct.pack(">I", val)[:n])
        return bytes(result)

    def _runlength_decode(self, data: bytes) -> bytes:
        """Decode PDF RunLength encoded stream."""
        result = bytearray()
        i = 0
        while i < len(data):
            length = data[i]
            i += 1
            if length == 128:
                break
            elif length < 128:
                result.extend(data[i:i + length + 1])
                i += length + 1
            else:
                if i < len(data):
                    result.extend([data[i]] * (257 - length))
                    i += 1
        return bytes(result)

    def _decode_base64_blobs(self, text: str) -> list:
        """Find and decode base64-encoded blobs in the PDF text."""
        decoded = []
        # Look for base64 patterns (long strings of base64 chars)
        pattern = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
        for match in pattern.finditer(text):
            b64 = match.group(0)
            try:
                dec = base64.b64decode(b64 + "==").decode("latin-1", errors="replace")
                if any(c.isprintable() for c in dec[:20]):
                    decoded.append(dec)
            except Exception:
                pass
        return decoded[:20]  # cap to avoid huge output

    @staticmethod
    def _entropy(data: bytes) -> float:
        """Calculate Shannon entropy of a byte sequence (0.0 - 8.0)."""
        if not data:
            return 0.0
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        n = len(data)
        entropy = 0.0
        for f in freq:
            if f > 0:
                p = f / n
                entropy -= p * math.log2(p)
        return entropy
