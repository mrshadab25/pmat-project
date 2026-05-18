"""
modules/loader.py — STEP 1: PDF File Loader & Hash Generator
Validates the file, computes hashes, reads raw bytes for downstream modules.
"""

import os
import hashlib
import struct
from pathlib import Path


class PDFLoader:
    """Loads a PDF file, validates its header, and computes file hashes."""

    def __init__(self, path: str):
        self.path = path
        self.raw_bytes = b""

    def load(self) -> dict:
        result = {
            "path": self.path,
            "filename": os.path.basename(self.path),
            "valid": False,
            "error": None,
            "size_bytes": 0,
            "size_human": "0 B",
            "md5": "",
            "sha1": "",
            "sha256": "",
            "pdf_header": "",
            "is_pdf": False,
        }

        # File existence check
        if not os.path.isfile(self.path):
            result["error"] = f"File not found: {self.path}"
            return result

        # Read raw bytes
        try:
            with open(self.path, "rb") as f:
                self.raw_bytes = f.read()
        except Exception as e:
            result["error"] = str(e)
            return result

        size = len(self.raw_bytes)
        result["size_bytes"] = size
        result["size_human"] = self._human_size(size)

        # Check PDF magic header  %PDF-
        header = self.raw_bytes[:8].decode("latin-1", errors="replace")
        result["pdf_header"] = header
        if not self.raw_bytes.startswith(b"%PDF-"):
            result["error"] = f"Not a valid PDF (header: {header!r})"
            result["is_pdf"] = False
            # Still continue — some malformed PDFs still contain useful data
        else:
            result["is_pdf"] = True

        # Extract PDF version
        try:
            version_line = self.raw_bytes[:10].decode("latin-1")
            result["pdf_version"] = version_line[5:8].strip()
        except Exception:
            result["pdf_version"] = "unknown"

        # Compute hashes
        result["md5"]    = hashlib.md5(self.raw_bytes).hexdigest()
        result["sha1"]   = hashlib.sha1(self.raw_bytes).hexdigest()
        result["sha256"] = hashlib.sha256(self.raw_bytes).hexdigest()
        result["valid"]  = True

        # Store raw bytes reference for other modules
        result["_raw_bytes"] = self.raw_bytes
        return result

    @staticmethod
    def _human_size(size: int) -> str:
        for unit in ["B", "KB", "MB", "GB"]:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"
