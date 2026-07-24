"""Three-tier deduplication for findings ingested from scanner imports.

Two scanners can report the exact same underlying vulnerability in ways
that never look identical at the row level: Nessus and ZAP both flagging
the same CVE on the same host, the same misconfiguration replicated across
every node behind a load balancer, or a SAST rule firing on a class that
only differs by line number after a refactor. ``DeduplicationEngine``
resolves a new finding against everything already on file using three
tiers, tried from most to least certain, and reports how confident it is in
the match rather than silently collapsing anything below "certain".

TIER 1 - Exact match (confidence 0.95)
    Same CVE *and* the same location (same host+port, or the same code
    file+line, or the same URL+parameter). This is as close to "the same
    finding, reported twice" as two independently-normalized rows get -
    e.g. Nessus and ZAP both surfacing CVE-2021-12345 on the same host and
    port.

TIER 2 - Cross-host, same CVE (confidence 0.7)
    Same CVE, but a *different* host - and the same port/service when both
    findings specify one. This is the classic load-balancer case: the same
    vulnerable software version deployed to every node behind a VIP, so
    the CVE and the port/service line up but the host doesn't. Medium
    confidence because a shared CVE alone doesn't prove it's the same
    deployment - two unrelated hosts can happen to run the same vulnerable
    library - but the matching port/service makes that coincidence much
    less likely.

TIER 3 - Mirrored infrastructure, no CVE (confidence 0.65)
    Many findings never carry a CVE at all - weak TLS ciphers, missing
    security headers, other configuration issues that scanners flag by
    plugin/rule rather than by vulnerability ID. Tier 3 catches the same
    "replicated across load-balanced hosts" pattern for those: same CWE +
    same port/service + different host, *plus* the titles must share a
    meaningful keyword (e.g. both mention "cipher", or both mention "TLS").

    The title-overlap requirement exists because CWE alone is too coarse a
    signal: CWE-327 ("Broken or Risky Crypto Algorithm") covers both "weak
    TLS cipher" and "certificate signed with SHA-1", which are the same
    weakness *class* but different findings, not the same finding mirrored
    across hosts. Requiring an overlapping keyword - after stripping generic
    words like "weak" or "enabled" that show up in unrelated findings too -
    keeps the CWE match tied to a specific vulnerability rather than the
    whole category.

Tiers are tried in order (1, then 2, then 3) and the first match wins, so a
finding is always scored at the highest confidence tier it qualifies for.
"""

from __future__ import annotations

import re
from typing import List, Optional, Tuple

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.finding import Finding, LocationType


class DeduplicationEngine:
    """Matches a new finding against already-known findings, tier by tier."""

    TIER1_CONFIDENCE = 0.95
    TIER2_CONFIDENCE = 0.7
    TIER3_CONFIDENCE = 0.65

    # Words too generic to signal "same finding" on their own - common
    # English stopwords plus vulnerability-report adjectives that recur
    # across findings that are otherwise unrelated (e.g. "weak" shows up in
    # both "Weak TLS Cipher" and "Weak Hashing Algorithm", which are
    # different findings that happen to share CWE-327).
    _GENERIC_TITLE_WORDS = frozenset(
        {
            "a", "an", "the", "and", "or", "on", "in", "of", "to", "for",
            "with", "is", "are", "via", "using",
            "weak", "enabled", "detected", "found", "vulnerable",
            "insecure", "outdated", "missing",
        }
    )

    # --- Public API ---------------------------------------------------------

    def find_duplicates(
        self, new_finding: Finding, existing_findings: List[Finding]
    ) -> Optional[Tuple[Finding, float]]:
        """Match ``new_finding`` against ``existing_findings``.

        Tries Tier 1, then Tier 2, then Tier 3, returning the first hit as
        ``(canonical_finding, confidence)``. Returns ``None`` if none of the
        three tiers find a match. ``existing_findings`` should only contain
        non-duplicate findings, so every match resolves to one canonical row
        rather than chaining through another duplicate.
        """
        match = self._classify(new_finding, existing_findings)
        return None if match is None else (match[0], match[1])

    def apply_dedup(self, db: Session, finding: Finding) -> Finding:
        """Match ``finding`` against every non-duplicate finding on file and
        set its ``is_duplicate``/``canonical_id``/``dedup_confidence`` fields
        in place.

        Queries the DB directly rather than relying on the caller to pass in
        candidates, so this can be called right after a finding is built and
        before it's added to the session.
        """
        existing = (
            db.execute(
                select(Finding)
                .where(Finding.is_duplicate.is_(False))
                .order_by(Finding.created_at)
            )
            .scalars()
            .all()
        )
        # Guard against matching a finding against itself, in case it was
        # already flushed before apply_dedup runs.
        existing = [f for f in existing if f is not finding]

        match = self.find_duplicates(finding, existing)
        if match is not None:
            canonical, confidence = match
            finding.is_duplicate = True
            finding.canonical_id = canonical.id
            finding.dedup_confidence = confidence
        return finding

    # --- Tier dispatch --------------------------------------------------------

    def _classify(
        self, new_finding: Finding, existing_findings: List[Finding]
    ) -> Optional[Tuple[Finding, float, int]]:
        """Same as ``find_duplicates`` but also returns which tier matched,
        for callers (like the report generator) that want to break results
        down by tier.
        """
        for tier, matcher in (
            (1, self._match_tier1),
            (2, self._match_tier2),
            (3, self._match_tier3),
        ):
            result = matcher(new_finding, existing_findings)
            if result is not None:
                canonical, confidence = result
                return canonical, confidence, tier
        return None

    # --- Tier 1: exact CVE + exact location ------------------------------------

    def _match_tier1(
        self, new_finding: Finding, existing_findings: List[Finding]
    ) -> Optional[Tuple[Finding, float]]:
        cve = self._normalize(new_finding.cve_id)
        if not cve:
            return None
        for candidate in existing_findings:
            if self._normalize(candidate.cve_id) == cve and self._exact_location_match(
                new_finding, candidate
            ):
                return candidate, self.TIER1_CONFIDENCE
        return None

    # --- Tier 2: same CVE, different host, matching port/service --------------

    def _match_tier2(
        self, new_finding: Finding, existing_findings: List[Finding]
    ) -> Optional[Tuple[Finding, float]]:
        cve = self._normalize(new_finding.cve_id)
        if not cve:
            return None
        for candidate in existing_findings:
            if self._normalize(candidate.cve_id) != cve:
                continue
            if not self._different_host(new_finding, candidate):
                continue
            if not self._compatible_port_service(new_finding, candidate):
                continue
            return candidate, self.TIER2_CONFIDENCE
        return None

    # --- Tier 3: no CVE needed - same CWE + overlapping title keyword ----------

    def _match_tier3(
        self, new_finding: Finding, existing_findings: List[Finding]
    ) -> Optional[Tuple[Finding, float]]:
        for candidate in existing_findings:
            if not self._different_host(new_finding, candidate):
                continue
            if not self._compatible_port_service(new_finding, candidate):
                continue
            if not self._same_cwe(new_finding, candidate):
                continue
            if not self._title_keyword_overlap(new_finding, candidate):
                continue
            return candidate, self.TIER3_CONFIDENCE
        return None

    # --- Field-comparison helpers -----------------------------------------------

    @staticmethod
    def _normalize(value: Optional[str]) -> Optional[str]:
        return value.strip().upper() if value else None

    @classmethod
    def _exact_location_match(cls, a: Finding, b: Finding) -> bool:
        """True when two findings point at literally the same place."""
        if a.location_type != b.location_type:
            return False
        if a.location_type == LocationType.CODE:
            return bool(a.code_file) and a.code_file == b.code_file and a.code_line == b.code_line
        if a.location_type == LocationType.WEB_ENDPOINT:
            return bool(a.url) and a.url == b.url and a.parameter == b.parameter
        # HOST / SERVICE / CONFIG all key off host+port.
        return bool(a.host) and a.host == b.host and a.port == b.port

    @staticmethod
    def _different_host(a: Finding, b: Finding) -> bool:
        return bool(a.host) and bool(b.host) and a.host != b.host

    @staticmethod
    def _compatible_port_service(a: Finding, b: Finding) -> bool:
        """True when both findings share a port, and don't contradict on service.

        Port is required (it's the anchor that ties two different hosts
        together as "the same exposed thing"); service is only compared when
        both sides actually report one, since not every tool populates it.
        """
        if a.port is None or b.port is None or a.port != b.port:
            return False
        if a.service and b.service and a.service.lower() != b.service.lower():
            return False
        return True

    @classmethod
    def _same_cwe(cls, a: Finding, b: Finding) -> bool:
        return bool(a.cwe_id) and cls._normalize(a.cwe_id) == cls._normalize(b.cwe_id)

    @classmethod
    def _title_keywords(cls, title: Optional[str]) -> set:
        """Meaningful (non-generic, 3+ char) lowercase words in a title."""
        if not title:
            return set()
        words = re.findall(r"[a-z0-9]+", title.lower())
        return {w for w in words if len(w) >= 3 and w not in cls._GENERIC_TITLE_WORDS}

    @classmethod
    def _title_keyword_overlap(cls, a: Finding, b: Finding) -> bool:
        """True when the two titles share at least one meaningful keyword,
        e.g. both mention "cipher" or both mention "tls" - as opposed to
        only sharing generic words like "weak" or "enabled".
        """
        return bool(cls._title_keywords(a.title) & cls._title_keywords(b.title))


# Module-level default engine so callers can `from app.services.deduplication
# import apply_dedup` without instantiating the class themselves.
_default_engine = DeduplicationEngine()


def find_duplicates(
    new_finding: Finding, existing_findings: List[Finding]
) -> Optional[Tuple[Finding, float]]:
    return _default_engine.find_duplicates(new_finding, existing_findings)


def apply_dedup(db: Session, finding: Finding) -> Finding:
    return _default_engine.apply_dedup(db, finding)


# --- Reporting -----------------------------------------------------------------


def print_dedup_report(db: Session) -> None:
    """Dry-run: recompute dedup matches for every finding in creation order, as
    if each were freshly imported, without writing anything back to the DB.

    Useful for sanity-checking the engine against data that's already been
    seeded/imported (and may already have hand-set ``is_duplicate`` values)
    without risking overwriting them.
    """
    findings = db.execute(select(Finding).order_by(Finding.created_at)).scalars().all()

    engine = DeduplicationEngine()
    canonical_pool: List[Finding] = []
    tier_counts = {1: 0, 2: 0, 3: 0}
    pairs: List[Tuple[Finding, Finding, int, float]] = []

    for finding in findings:
        match = engine._classify(finding, canonical_pool)
        if match is not None:
            canonical, confidence, tier = match
            tier_counts[tier] += 1
            pairs.append((finding, canonical, tier, confidence))
        else:
            canonical_pool.append(finding)

    print(
        f"Found {len(pairs)} duplicate pairs across {len(findings)} findings "
        f"using Tier 1/2/3 (Tier 1: {tier_counts[1]}, Tier 2: {tier_counts[2]}, "
        f"Tier 3: {tier_counts[3]})"
    )
    for finding, canonical, tier, confidence in pairs:
        print(
            f"  Tier {tier} (confidence {confidence:.2f}): "
            f"'{finding.title}' [{finding.host or finding.code_file}] -> "
            f"canonical '{canonical.title}' [{canonical.host or canonical.code_file}]"
        )


if __name__ == "__main__":
    from app.database import get_session_factory

    session = get_session_factory()()
    try:
        print_dedup_report(session)
    finally:
        session.close()
