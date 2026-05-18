"""
modules/scoring.py — STEP 8: Risk Scoring & Severity Assessment
Aggregates all findings into a final risk score (0–100) with severity tier.
"""


class RiskScorer:
    """
    Weighted risk scoring engine.
    Aggregates findings from all analysis modules into a final severity tier.
    """

    SEVERITY_TIERS = [
        (90, "CRITICAL"),
        (70, "HIGH"),
        (40, "MEDIUM"),
        (10, "LOW"),
        (0,  "CLEAN"),
    ]

    def __init__(self, results: dict):
        self.results = results

    def score(self) -> dict:
        score      = 0
        breakdown  = []
        indicators = []

        # ── Keyword scores ─────────────────────────────────────────
        kw = self.results.get("keywords", {})
        kw_score = min(kw.get("total_score", 0), 40)  # cap at 40 pts from keywords
        if kw_score > 0:
            breakdown.append(f"Keyword scan          : +{kw_score} pts  ({len(kw.get('found',[]))} suspicious keywords)")
            score += kw_score
            for kw_item in kw.get("found", []):
                indicators.append(f"Keyword: {kw_item['keyword']} ({kw_item['severity']})")

        # ── IOC scores ────────────────────────────────────────────
        ioc = self.results.get("iocs", {})

        cve_score = len(ioc.get("cves", [])) * 15
        cve_score = min(cve_score, 30)
        if cve_score:
            breakdown.append(f"CVE references        : +{cve_score} pts  ({len(ioc['cves'])} CVE(s) detected)")
            score += cve_score
            indicators.append(f"CVEs detected: {', '.join(ioc['cves'][:3])}")

        ef_score = len(ioc.get("embedded_files", [])) * 12
        ef_score = min(ef_score, 24)
        if ef_score:
            breakdown.append(f"Embedded executables  : +{ef_score} pts  ({len(ioc['embedded_files'])} embedded file(s))")
            score += ef_score
            indicators.append(f"Embedded files: {', '.join(ioc['embedded_files'][:3])}")

        url_score = min(len(ioc.get("urls", [])) * 3, 12)
        if url_score:
            breakdown.append(f"External URLs         : +{url_score} pts  ({len(ioc['urls'])} URL(s) found)")
            score += url_score

        ip_score = min(len(ioc.get("ips", [])) * 4, 12)
        if ip_score:
            breakdown.append(f"IP addresses          : +{ip_score} pts  ({len(ioc['ips'])} IP(s) found)")
            score += ip_score

        # ── JavaScript scores ─────────────────────────────────────
        js = self.results.get("javascript", {})

        js_block_score = min(js.get("js_block_count", 0) * 5, 15)
        if js_block_score:
            breakdown.append(f"JavaScript blocks     : +{js_block_score} pts  ({js['js_block_count']} JS block(s))")
            score += js_block_score

        obfus_score = min(len(js.get("obfuscation_patterns", [])) * 4, 20)
        if obfus_score:
            breakdown.append(f"Obfuscation patterns  : +{obfus_score} pts  ({len(js['obfuscation_patterns'])} pattern(s))")
            score += obfus_score

        auto_score = min(len(js.get("auto_actions", [])) * 5, 15)
        if auto_score:
            breakdown.append(f"Auto-execute actions  : +{auto_score} pts  ({len(js['auto_actions'])} action(s))")
            score += auto_score

        for ri in js.get("risk_indicators", []):
            if "heap spray" in ri.lower():
                breakdown.append("Heap spray detected   : +15 pts")
                score += 15
                indicators.append("Heap spray technique detected")
            elif "shellcode" in ri.lower():
                breakdown.append("Shellcode bytes       : +10 pts")
                score += 10
                indicators.append("Shellcode byte pattern detected")

        # ── Stream scores ─────────────────────────────────────────
        streams = self.results.get("streams", {})
        entropy_score = min(streams.get("high_entropy_streams", 0) * 5, 15)
        if entropy_score:
            breakdown.append(f"High-entropy streams  : +{entropy_score} pts  ({streams['high_entropy_streams']} stream(s))")
            score += entropy_score

        # ── Metadata anomalies ────────────────────────────────────
        meta = self.results.get("metadata", {})
        meta_score = min(len(meta.get("anomalies", [])) * 3, 9)
        if meta_score:
            breakdown.append(f"Metadata anomalies    : +{meta_score} pts  ({len(meta['anomalies'])} anomaly(s))")
            score += meta_score

        # ── Object structure ──────────────────────────────────────
        obj = self.results.get("objects", {})
        chain_score = min(len(obj.get("filter_chains", [])) * 3, 9)
        if chain_score:
            breakdown.append(f"Filter chains         : +{chain_score} pts  ({len(obj['filter_chains'])} multi-filter chain(s))")
            score += chain_score

        # ── Cap at 100 ────────────────────────────────────────────
        score = min(score, 100)

        # ── Determine severity tier ───────────────────────────────
        severity = "CLEAN"
        for threshold, label in self.SEVERITY_TIERS:
            if score >= threshold:
                severity = label
                break

        return {
            "score":       score,
            "severity":    severity,
            "breakdown":   breakdown,
            "indicators":  indicators,
            "mitigations": self._get_mitigations(severity, indicators),
        }

    def _get_mitigations(self, severity: str, indicators: list) -> list:
        """Return relevant mitigations based on detected findings."""
        base = [
            "Do NOT open this file on a production system.",
            "Quarantine the file immediately if found on an endpoint.",
            "Compute and submit the file hash to VirusTotal for reputation check.",
        ]
        if severity in ("CRITICAL", "HIGH"):
            base += [
                "Initiate incident response procedures if this file was opened.",
                "Check endpoint EDR/SIEM logs for child processes spawned by PDF readers.",
                "Block associated URLs/IPs at firewall and proxy level.",
                "Disable JavaScript in PDF reader: Edit > Preferences > JavaScript.",
                "Scan all systems that received this file via email or file share.",
            ]
        if severity == "MEDIUM":
            base += [
                "Submit to sandbox (Any.run / Hybrid Analysis) for behavioral analysis.",
                "Review network logs for connections to extracted URLs/IPs.",
            ]
        base += [
            "Update PDF reader software to latest patched version.",
            "Train users to report suspicious email attachments.",
            "Implement email gateway filtering for PDFs with embedded JavaScript.",
        ]
        return base
