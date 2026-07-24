"""Verifies DeduplicationEngine's three tiers.

Tier tests below build Finding objects purely in memory (no DB needed) since
find_duplicates() is a pure function over a candidate list. apply_dedup()
tests need a live DB (they exercise the DB query + flush integration) and use
the db_session fixture, which rolls back on teardown.
"""

import uuid
from datetime import datetime, timedelta, timezone

from app.models.finding import Finding, LocationType, Scan, ScanStatus, Severity, ToolSource
from app.seed_data import FINDINGS
from app.services.deduplication import DeduplicationEngine, apply_dedup

NOW = datetime.now(timezone.utc)


def _finding(**overrides):
    defaults = dict(
        id=uuid.uuid4(),
        scan_id=uuid.uuid4(),
        tool_source=ToolSource.NESSUS,
        title="Test Finding",
        severity_normalized=Severity.HIGH,
        location_type=LocationType.HOST,
        host="10.20.4.99",
        port=443,
        service="https",
        created_at=NOW,
    )
    defaults.update(overrides)
    return Finding(**defaults)


# --- Tier 1: exact CVE + exact location -------------------------------------


def test_tier1_exact_cve_and_host_is_high_confidence():
    engine = DeduplicationEngine()
    canonical = _finding(cve_id="CVE-9999-00001", host="10.20.4.50", port=443)
    new = _finding(cve_id="CVE-9999-00001", host="10.20.4.50", port=443)

    match = engine.find_duplicates(new, [canonical])

    assert match is not None
    matched_finding, confidence = match
    assert matched_finding is canonical
    assert confidence == DeduplicationEngine.TIER1_CONFIDENCE
    assert confidence >= 0.9


def test_tier1_requires_same_port_not_just_same_host():
    engine = DeduplicationEngine()
    canonical = _finding(cve_id="CVE-9999-00001", host="10.20.4.50", port=443)
    new = _finding(cve_id="CVE-9999-00001", host="10.20.4.50", port=8443)

    # Different port on the same host isn't an exact location match, so this
    # should fall through to Tier 2 rather than Tier 1 - and Tier 2 requires a
    # *different* host, so it should not match at all.
    match = engine.find_duplicates(new, [canonical])
    assert match is None


# --- Tier 2: same CVE, different host, matching port/service ----------------


def test_tier2_same_cve_different_host_same_port_is_medium_confidence():
    engine = DeduplicationEngine()
    canonical = _finding(cve_id="CVE-9999-00002", host="10.20.4.10", port=443, service="https")
    new = _finding(cve_id="CVE-9999-00002", host="10.20.4.16", port=443, service="https")

    match = engine.find_duplicates(new, [canonical])

    assert match is not None
    matched_finding, confidence = match
    assert matched_finding is canonical
    assert confidence == DeduplicationEngine.TIER2_CONFIDENCE
    assert 0.5 <= confidence <= 0.7


def test_tier2_same_cve_different_port_does_not_match():
    engine = DeduplicationEngine()
    canonical = _finding(cve_id="CVE-9999-00002", host="10.20.4.10", port=443)
    new = _finding(cve_id="CVE-9999-00002", host="10.20.4.16", port=8080)

    assert engine.find_duplicates(new, [canonical]) is None


# --- Tier 3 (revised): same CWE + same port/service + different host, ------
# --- PLUS an overlapping title keyword --------------------------------------


def test_tier3_same_cwe_and_exact_title_matches_at_065():
    engine = DeduplicationEngine()
    canonical = _finding(
        cve_id=None,
        title="Missing Security Headers (X-Frame-Options, CSP)",
        cwe_id="CWE-693",
        host="10.20.4.10",
        port=443,
        service="https",
    )
    new = _finding(
        cve_id=None,
        title="Missing Security Headers (X-Frame-Options, CSP)",
        cwe_id="CWE-693",
        host="10.20.4.11",
        port=443,
        service="https",
    )

    match = engine.find_duplicates(new, [canonical])

    assert match is not None
    matched_finding, confidence = match
    assert matched_finding is canonical
    assert confidence == DeduplicationEngine.TIER3_CONFIDENCE
    assert confidence == 0.65


def test_tier3_same_cwe_and_overlapping_keyword_matches_at_065():
    """Titles don't need to match exactly - just share a meaningful word."""
    engine = DeduplicationEngine()
    canonical = _finding(
        cve_id=None,
        title="Weak TLS Cipher Suite Enabled (RC4)",
        cwe_id="CWE-327",
        host="10.20.4.10",
        port=443,
        service="https",
    )
    new = _finding(
        cve_id=None,
        title="Deprecated TLS Cipher Configuration Detected",
        cwe_id="CWE-327",
        host="10.20.4.20",
        port=443,
        service="https",
    )

    match = engine.find_duplicates(new, [canonical])

    assert match is not None
    matched_finding, confidence = match
    assert matched_finding is canonical
    assert confidence == DeduplicationEngine.TIER3_CONFIDENCE


def test_tier3_same_cwe_but_no_title_overlap_does_not_match():
    """The sha1-cert / tls-rc4 false positive this revision fixes: same CWE
    (CWE-327 covers both "weak cipher" and "weak cert hash"), same port,
    different host - but no shared keyword once generic words like "weak"
    are excluded, so these are correctly NOT treated as duplicates.
    """
    engine = DeduplicationEngine()
    tls_rc4 = _finding(
        cve_id=None,
        title="Weak TLS Cipher Suite Enabled (RC4) on Payment Gateway",
        cwe_id="CWE-327",
        host="10.20.4.10",
        port=443,
        service="https",
    )
    sha1_cert = _finding(
        cve_id=None,
        title="SSL Certificate Signed Using Weak Hashing Algorithm (SHA-1)",
        cwe_id="CWE-327",
        host="10.20.4.12",
        port=443,
        service="https",
    )

    assert engine.find_duplicates(sha1_cert, [tls_rc4]) is None


def test_tier3_requires_cwe_even_with_overlapping_title():
    engine = DeduplicationEngine()
    canonical = _finding(cve_id=None, title="Cipher Suite Issue", cwe_id=None, host="10.20.4.10", port=443)
    new = _finding(cve_id=None, title="Cipher Suite Issue", cwe_id="CWE-327", host="10.20.4.11", port=443)

    assert engine.find_duplicates(new, [canonical]) is None


def test_no_match_when_title_cwe_and_cve_all_differ():
    engine = DeduplicationEngine()
    canonical = _finding(cve_id=None, title="Finding A", cwe_id="CWE-1", host="10.20.4.10", port=443)
    new = _finding(cve_id=None, title="Finding B", cwe_id="CWE-2", host="10.20.4.11", port=443)

    assert engine.find_duplicates(new, [canonical]) is None


# --- Reproduces the seed data's hand-crafted duplicate pairs -----------------


def test_reproduces_seed_data_hand_crafted_duplicates():
    """Rebuilds app.seed_data.FINDINGS as in-memory Finding objects (no DB) in
    seed order and runs them through the engine one at a time, mimicking a
    fresh import. Confirms it independently arrives at the same two
    is_duplicate pairs the seed data hand-sets - at the tiers/confidences
    specified for this engine (0.7 for Tier 2, 0.65+ for Tier 3), which differ
    from the seed data's own hand-picked confidence values (0.93 / 0.88).
    """
    ids_by_key = {entry["key"]: uuid.uuid4() for entry in FINDINGS}
    built = []
    for i, entry in enumerate(FINDINGS):
        kwargs = {
            k: v
            for k, v in entry.items()
            if k not in ("key", "canonical_key", "is_duplicate", "canonical_id", "dedup_confidence")
        }
        finding = Finding(**kwargs)
        finding.id = ids_by_key[entry["key"]]
        finding.created_at = NOW + timedelta(seconds=i)
        built.append((entry["key"], finding))

    engine = DeduplicationEngine()
    canonical_pool = []
    results = {}
    for key, finding in built:
        match = engine.find_duplicates(finding, [f for _, f in canonical_pool])
        if match is not None:
            canonical, confidence = match
            canonical_key = next(k for k, f in canonical_pool if f is canonical)
            results[key] = (canonical_key, confidence)
        else:
            canonical_pool.append((key, finding))

    assert results["tls-rc4-dup"] == ("tls-rc4", DeduplicationEngine.TIER2_CONFIDENCE)
    assert results["missing-security-headers-dup"] == (
        "missing-security-headers",
        DeduplicationEngine.TIER3_CONFIDENCE,
    )

    # sha1-cert (CWE-327, host .12) and tls-rc4 (CWE-327, host .10) share a
    # CWE and a port/service but are genuinely different vulnerabilities
    # (weak cert hash vs. weak cipher suite) with no overlapping title
    # keyword once "weak" is excluded as generic. The revised Tier 3 no
    # longer flags this pair - confirming the fix for the false positive
    # found when Tier 3 fell back to CWE alone.
    assert "sha1-cert" not in results


# --- apply_dedup() end-to-end against a real DB session ----------------------


def _make_scan(db, name):
    scan = Scan(name=name, scope="test", status=ScanStatus.COMPLETED, tool_sources={"nessus": True})
    db.add(scan)
    db.flush()
    return scan


def test_apply_dedup_persists_tier1_match(db_session):
    scan = _make_scan(db_session, "dedup test - tier1")

    original = _finding(scan_id=scan.id, cve_id="CVE-9999-00003", host="10.20.9.5", port=443)
    apply_dedup(db_session, original)
    db_session.add(original)
    db_session.flush()
    assert original.is_duplicate is False  # first seen: nothing to match against

    duplicate = _finding(scan_id=scan.id, cve_id="CVE-9999-00003", host="10.20.9.5", port=443)
    apply_dedup(db_session, duplicate)
    db_session.add(duplicate)
    db_session.flush()

    assert duplicate.is_duplicate is True
    assert duplicate.canonical_id == original.id
    assert duplicate.dedup_confidence == DeduplicationEngine.TIER1_CONFIDENCE


def test_apply_dedup_persists_tier2_match(db_session):
    scan = _make_scan(db_session, "dedup test - tier2")

    original = _finding(scan_id=scan.id, cve_id="CVE-9999-00004", host="10.20.9.10", port=443)
    apply_dedup(db_session, original)
    db_session.add(original)
    db_session.flush()

    other_host = _finding(scan_id=scan.id, cve_id="CVE-9999-00004", host="10.20.9.11", port=443)
    apply_dedup(db_session, other_host)
    db_session.add(other_host)
    db_session.flush()

    assert other_host.is_duplicate is True
    assert other_host.canonical_id == original.id
    assert other_host.dedup_confidence == DeduplicationEngine.TIER2_CONFIDENCE
