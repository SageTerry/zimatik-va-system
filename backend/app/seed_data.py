"""Populate the database with realistic sample data for testing/demo purposes.

Creates two Scan records (one Nessus, one SonarQube) and ~20 Finding records
modeled on what a financial services security team would actually turn up:
payment API vulnerabilities, weak TLS/crypto configs, exposed secrets, and
the usual long tail of low-severity infrastructure noise.

Run with:

    python -m app.seed_data          # prompts before clearing existing data
    python -m app.seed_data --yes    # skips the confirmation prompt
"""

from __future__ import annotations

import argparse
import sys
import uuid
from datetime import datetime, timedelta, timezone

from app.database import get_session_factory
from app.models import (
    Finding,
    FalsePositiveRisk,
    LocationType,
    RemediationStatus,
    Scan,
    ScanStatus,
    Severity,
    ToolSource,
)

NOW = datetime.now(timezone.utc)

SCAN_NESSUS_ID = uuid.uuid4()
SCAN_SONARQUBE_ID = uuid.uuid4()

SCANS = [
    {
        "id": SCAN_NESSUS_ID,
        "name": "External Network Vulnerability Scan - Payments Infrastructure",
        "scope": "10.20.4.0/24 (payments-prod DMZ)",
        "status": ScanStatus.COMPLETED,
        "tool_sources": {"nessus": True},
        "started_at": NOW - timedelta(days=2),
        "completed_at": NOW - timedelta(days=2) + timedelta(hours=3),
    },
    {
        "id": SCAN_SONARQUBE_ID,
        "name": "SAST Scan - payments-api Repository",
        "scope": "git.internal/payments/payments-api @ main",
        "status": ScanStatus.COMPLETED,
        "tool_sources": {"sonarqube": True},
        "started_at": NOW - timedelta(days=1),
        "completed_at": NOW - timedelta(days=1) + timedelta(minutes=40),
    },
]

# Each entry gets a stable "key" so duplicate findings can point back at their
# canonical finding's id without a separate resolution pass.
FINDINGS = [
    # --- CRITICAL ---------------------------------------------------------
    {
        "key": "sqli-payment-api",
        "scan_id": SCAN_SONARQUBE_ID,
        "tool_source": ToolSource.SONARQUBE,
        "tool_finding_id": "AY-SQ-10231",
        "cwe_id": "CWE-89",
        "owasp_category": "A03:2021-Injection",
        "title": "SQL Injection in Payment API",
        "description": (
            "The processPayment endpoint concatenates the raw accountNumber request "
            "parameter directly into a native SQL query executed against the ledger "
            "database, allowing an attacker to inject arbitrary SQL and read or modify "
            "payment records."
        ),
        "cvss_v3": 9.8,
        "severity_normalized": Severity.CRITICAL,
        "location_type": LocationType.CODE,
        "code_file": "payments-api/src/main/java/com/zimatik/payments/controller/PaymentController.java",
        "code_line": 142,
        "proof_of_concept": (
            "Sending accountNumber=1' OR '1'='1 returns every customer ledger row "
            "instead of a single account."
        ),
        "detection_method": "Static taint analysis (source: HTTP parameter, sink: JDBC Statement.executeQuery)",
        "confidence": 0.95,
        "false_positive_risk": FalsePositiveRisk.LOW,
        "recommended_fix": "Replace string concatenation with parameterized PreparedStatement bindings for all query inputs.",
        "effort_level": "MEDIUM",
        "mitigation": "Deploy a WAF rule blocking SQL metacharacters on /api/payments/process until patched.",
        "remediation_status": RemediationStatus.OPEN,
        "tags": ["payments", "injection", "owasp-top-10"],
    },
    {
        "key": "hardcoded-aws-key",
        "scan_id": SCAN_SONARQUBE_ID,
        "tool_source": ToolSource.SONARQUBE,
        "tool_finding_id": "AY-SQ-10287",
        "cwe_id": "CWE-798",
        "owasp_category": "A07:2021-Identification and Authentication Failures",
        "title": "Hardcoded AWS API Key in Source Code",
        "description": (
            "An active AWS access key and secret are hardcoded in AwsConfig.java and "
            "committed to version control, granting anyone with repository access "
            "programmatic access to the production statement-archive S3 bucket."
        ),
        "cvss_v3": 9.1,
        "severity_normalized": Severity.CRITICAL,
        "location_type": LocationType.CODE,
        "code_file": "payments-api/src/main/java/com/zimatik/payments/config/AwsConfig.java",
        "code_line": 27,
        "proof_of_concept": "grep -R 'AKIA' payments-api/src reveals a live-looking access key ID and secret literal.",
        "detection_method": "Secrets pattern matching (AWS access key regex)",
        "confidence": 0.9,
        "false_positive_risk": FalsePositiveRisk.LOW,
        "recommended_fix": "Revoke the exposed key immediately, rotate credentials, and load AWS credentials from the instance role or a secrets manager.",
        "effort_level": "LOW",
        "mitigation": "Restrict the key's IAM policy to read-only on the archive bucket until rotation completes.",
        "remediation_status": RemediationStatus.IN_PROGRESS,
        "tags": ["secrets", "aws", "payments"],
    },
    {
        "key": "struts-rce",
        "scan_id": SCAN_NESSUS_ID,
        "tool_source": ToolSource.NESSUS,
        "tool_finding_id": "nessus-182556-10.20.4.15",
        "cve_id": "CVE-2023-50164",
        "cwe_id": "CWE-434",
        "title": "Remote Code Execution via Outdated Apache Struts",
        "description": (
            "The file-upload servlet on the customer-onboarding host is running Apache "
            "Struts 2.5.30, vulnerable to a file-upload logic flaw allowing path traversal "
            "and arbitrary file upload, leading to remote code execution."
        ),
        "cvss_v3": 9.8,
        "severity_normalized": Severity.CRITICAL,
        "location_type": LocationType.HOST,
        "host": "10.20.4.15",
        "service": "http",
        "port": 8080,
        "proof_of_concept": "Nessus plugin 182556 confirmed the vulnerable Struts version string in HTTP response headers.",
        "detection_method": "Version-banner check + Nessus remote plugin 182556",
        "confidence": 0.85,
        "false_positive_risk": FalsePositiveRisk.LOW,
        "recommended_fix": "Upgrade Apache Struts to 2.5.33 or later and redeploy the onboarding service.",
        "effort_level": "MEDIUM",
        "mitigation": "Restrict inbound access to port 8080 to the internal load balancer only until patched.",
        "remediation_status": RemediationStatus.OPEN,
        "tags": ["rce", "struts", "onboarding"],
    },
    # --- HIGH ---------------------------------------------------------------
    {
        "key": "xss-search",
        "scan_id": SCAN_SONARQUBE_ID,
        "tool_source": ToolSource.SONARQUBE,
        "tool_finding_id": "AY-SQ-10304",
        "cwe_id": "CWE-79",
        "owasp_category": "A03:2021-Injection",
        "title": "Cross-Site Scripting in Search Endpoint",
        "description": (
            "The transaction search results page reflects the query parameter back "
            "into the HTML response without encoding, allowing an XSS payload to "
            "execute in an authenticated user's session."
        ),
        "cvss_v3": 8.2,
        "severity_normalized": Severity.HIGH,
        "location_type": LocationType.CODE,
        "code_file": "payments-api/src/main/java/com/zimatik/payments/controller/SearchController.java",
        "code_line": 88,
        "proof_of_concept": "/search?query=<script>alert(document.cookie)</script> executes in the response.",
        "detection_method": "Static taint analysis (source: HTTP parameter, sink: unescaped JSP output)",
        "confidence": 0.88,
        "false_positive_risk": FalsePositiveRisk.LOW,
        "recommended_fix": "HTML-encode the query parameter before rendering, or migrate the view to an auto-escaping template engine.",
        "effort_level": "LOW",
        "mitigation": "Add a Content-Security-Policy header restricting inline script execution.",
        "remediation_status": RemediationStatus.OPEN,
        "tags": ["xss", "payments"],
    },
    {
        "key": "tls-rc4",
        "scan_id": SCAN_NESSUS_ID,
        "tool_source": ToolSource.NESSUS,
        "tool_finding_id": "nessus-65821-10.20.4.10",
        "cve_id": "CVE-2013-2566",
        "cwe_id": "CWE-327",
        "title": "Weak TLS Cipher Suite Enabled (RC4) on Payment Gateway",
        "description": (
            "The payment gateway load balancer accepts TLS connections using the RC4 "
            "stream cipher, which has known statistical biases that allow partial "
            "plaintext recovery from encrypted sessions."
        ),
        "cvss_v3": 7.4,
        "severity_normalized": Severity.HIGH,
        "location_type": LocationType.HOST,
        "host": "10.20.4.10",
        "service": "https",
        "port": 443,
        "detection_method": "Nessus plugin 65821 (SSL RC4 Cipher Suites Supported)",
        "confidence": 0.9,
        "false_positive_risk": FalsePositiveRisk.LOW,
        "recommended_fix": "Disable RC4 cipher suites in the load balancer TLS policy; restrict to TLS 1.2+ with AEAD ciphers.",
        "effort_level": "LOW",
        "mitigation": "None available short of disabling the cipher; prioritize the fix.",
        "remediation_status": RemediationStatus.OPEN,
        "tags": ["tls", "payments"],
    },
    {
        "key": "tls-rc4-dup",
        "scan_id": SCAN_NESSUS_ID,
        "tool_source": ToolSource.NESSUS,
        "tool_finding_id": "nessus-65821-10.20.4.16",
        "cve_id": "CVE-2013-2566",
        "cwe_id": "CWE-327",
        "title": "Weak TLS Cipher Suite Enabled (RC4) on Payment Gateway",
        "description": (
            "The secondary payment gateway node behind the same VIP also accepts TLS "
            "connections using the RC4 stream cipher."
        ),
        "cvss_v3": 7.4,
        "severity_normalized": Severity.HIGH,
        "location_type": LocationType.HOST,
        "host": "10.20.4.16",
        "service": "https",
        "port": 443,
        "detection_method": "Nessus plugin 65821 (SSL RC4 Cipher Suites Supported)",
        "confidence": 0.9,
        "false_positive_risk": FalsePositiveRisk.LOW,
        "recommended_fix": "Disable RC4 cipher suites in the load balancer TLS policy; restrict to TLS 1.2+ with AEAD ciphers.",
        "effort_level": "LOW",
        "remediation_status": RemediationStatus.OPEN,
        "tags": ["tls", "payments"],
        "is_duplicate": True,
        "canonical_key": "tls-rc4",
        "dedup_confidence": 0.93,
    },
    {
        "key": "insecure-deserialization",
        "scan_id": SCAN_SONARQUBE_ID,
        "tool_source": ToolSource.SONARQUBE,
        "tool_finding_id": "AY-SQ-10319",
        "cwe_id": "CWE-502",
        "title": "Insecure Deserialization in Session Handler",
        "description": (
            "SessionManager deserializes the session_state cookie using Java's native "
            "ObjectInputStream without type filtering, allowing a crafted cookie to "
            "trigger arbitrary object instantiation (gadget chain RCE)."
        ),
        "cvss_v3": 8.1,
        "severity_normalized": Severity.HIGH,
        "location_type": LocationType.CODE,
        "code_file": "payments-api/src/main/java/com/zimatik/payments/session/SessionManager.java",
        "code_line": 203,
        "detection_method": "Static analysis (dangerous sink: ObjectInputStream.readObject)",
        "confidence": 0.8,
        "false_positive_risk": FalsePositiveRisk.MEDIUM,
        "recommended_fix": "Replace native Java serialization with a signed, schema-validated JSON session token.",
        "effort_level": "HIGH",
        "mitigation": "Add an ObjectInputFilter allow-list restricting deserializable classes.",
        "remediation_status": RemediationStatus.OPEN,
        "tags": ["deserialization", "payments"],
    },
    {
        "key": "outdated-openssl",
        "scan_id": SCAN_NESSUS_ID,
        "tool_source": ToolSource.NESSUS,
        "tool_finding_id": "nessus-207041-10.20.4.11",
        "cve_id": "CVE-2024-6119",
        "cwe_id": "CWE-125",
        "title": "Outdated OpenSSL Version with Multiple Known Vulnerabilities",
        "description": (
            "The auth service host is running OpenSSL 3.2.1, affected by a "
            "denial-of-service flaw in X.509 name-constraint checking that can crash "
            "the TLS-terminating process on a crafted certificate."
        ),
        "cvss_v3": 7.5,
        "severity_normalized": Severity.HIGH,
        "location_type": LocationType.HOST,
        "host": "10.20.4.11",
        "service": "https",
        "port": 443,
        "detection_method": "Nessus plugin 207041 (OpenSSL version check)",
        "confidence": 0.85,
        "false_positive_risk": FalsePositiveRisk.LOW,
        "recommended_fix": "Upgrade OpenSSL to 3.2.3 or later across the auth service fleet.",
        "effort_level": "MEDIUM",
        "mitigation": "None; schedule an emergency patch window.",
        "remediation_status": RemediationStatus.OPEN,
        "tags": ["openssl", "auth"],
    },
    # --- MEDIUM ---------------------------------------------------------------
    {
        "key": "missing-csrf",
        "scan_id": SCAN_SONARQUBE_ID,
        "tool_source": ToolSource.SONARQUBE,
        "tool_finding_id": "AY-SQ-10342",
        "cwe_id": "CWE-352",
        "owasp_category": "A01:2021-Broken Access Control",
        "title": "Missing CSRF Token on Fund Transfer Form",
        "description": (
            "The internal fund-transfer form submits to /api/transfers/execute without "
            "a CSRF token, allowing an attacker to trigger transfers from an "
            "authenticated victim's browser via a forged cross-site request."
        ),
        "cvss_v3": 6.5,
        "severity_normalized": Severity.MEDIUM,
        "location_type": LocationType.CODE,
        "code_file": "payments-api/src/main/java/com/zimatik/payments/controller/TransferController.java",
        "code_line": 67,
        "detection_method": "Static analysis (state-changing POST without CSRF annotation)",
        "confidence": 0.75,
        "false_positive_risk": FalsePositiveRisk.MEDIUM,
        "recommended_fix": "Enable Spring Security's CSRF protection for all state-changing endpoints and add a token to the transfer form.",
        "effort_level": "LOW",
        "mitigation": "Enforce SameSite=Strict on the session cookie as an interim control.",
        "remediation_status": RemediationStatus.OPEN,
        "tags": ["csrf", "payments"],
    },
    {
        "key": "unencrypted-pii",
        "scan_id": SCAN_SONARQUBE_ID,
        "tool_source": ToolSource.SONARQUBE,
        "tool_finding_id": "AY-SQ-10358",
        "cwe_id": "CWE-311",
        "owasp_category": "A02:2021-Cryptographic Failures",
        "title": "Unencrypted Data Storage of Customer PII",
        "description": (
            "The ssn and date_of_birth columns on the customer_profile table are "
            "stored in plaintext rather than using the application's field-level "
            "encryption helper, exposing PII to anyone with database read access."
        ),
        "cvss_v3": 5.9,
        "severity_normalized": Severity.MEDIUM,
        "location_type": LocationType.CODE,
        "code_file": "payments-api/src/main/java/com/zimatik/payments/model/CustomerProfile.java",
        "code_line": 34,
        "detection_method": "Static analysis (sensitive field without @Encrypted annotation)",
        "confidence": 0.7,
        "false_positive_risk": FalsePositiveRisk.MEDIUM,
        "recommended_fix": "Apply the existing field-level encryption utility to ssn and date_of_birth, and backfill-encrypt existing rows.",
        "effort_level": "MEDIUM",
        "mitigation": "Restrict direct database read access to the customer_profile table to the DBA role.",
        "remediation_status": RemediationStatus.OPEN,
        "tags": ["pii", "encryption", "payments"],
    },
    {
        "key": "directory-listing",
        "scan_id": SCAN_NESSUS_ID,
        "tool_source": ToolSource.NESSUS,
        "tool_finding_id": "nessus-11032-10.20.4.30",
        "cwe_id": "CWE-548",
        "title": "Directory Listing Enabled on File Server",
        "description": (
            "The document-upload host serves directory listings for /statements/, "
            "exposing the filenames (and in some cases contents) of customer PDF "
            "statements to unauthenticated requests."
        ),
        "cvss_v3": 5.3,
        "severity_normalized": Severity.MEDIUM,
        "location_type": LocationType.HOST,
        "host": "10.20.4.30",
        "service": "http",
        "port": 80,
        "detection_method": "Nessus plugin 11032 (Web Server Directory Browsing)",
        "confidence": 0.9,
        "false_positive_risk": FalsePositiveRisk.LOW,
        "recommended_fix": "Disable directory indexing in the web server configuration for all static content paths.",
        "effort_level": "LOW",
        "mitigation": "Add a deny-all robots.txt and IP allow-list until fixed.",
        "remediation_status": RemediationStatus.OPEN,
        "tags": ["disclosure", "statements"],
    },
    {
        "key": "missing-security-headers",
        "scan_id": SCAN_NESSUS_ID,
        "tool_source": ToolSource.NESSUS,
        "tool_finding_id": "nessus-98620-10.20.4.10",
        "cwe_id": "CWE-693",
        "title": "Missing Security Headers (X-Frame-Options, CSP)",
        "description": (
            "Responses from the customer portal do not set X-Frame-Options or "
            "Content-Security-Policy headers, leaving the login page vulnerable to "
            "clickjacking."
        ),
        "cvss_v3": 4.8,
        "severity_normalized": Severity.MEDIUM,
        "location_type": LocationType.HOST,
        "host": "10.20.4.10",
        "service": "https",
        "port": 443,
        "detection_method": "Nessus plugin 98620 (HTTP Security Header Not Detected)",
        "confidence": 0.85,
        "false_positive_risk": FalsePositiveRisk.LOW,
        "recommended_fix": "Add X-Frame-Options: DENY and a restrictive Content-Security-Policy to the reverse proxy configuration.",
        "effort_level": "LOW",
        "remediation_status": RemediationStatus.OPEN,
        "tags": ["headers", "clickjacking"],
    },
    {
        "key": "missing-security-headers-dup",
        "scan_id": SCAN_NESSUS_ID,
        "tool_source": ToolSource.NESSUS,
        "tool_finding_id": "nessus-98620-10.20.4.11",
        "cwe_id": "CWE-693",
        "title": "Missing Security Headers (X-Frame-Options, CSP)",
        "description": (
            "The second portal node behind the same VIP also fails to set "
            "X-Frame-Options or Content-Security-Policy headers."
        ),
        "cvss_v3": 4.8,
        "severity_normalized": Severity.MEDIUM,
        "location_type": LocationType.HOST,
        "host": "10.20.4.11",
        "service": "https",
        "port": 443,
        "detection_method": "Nessus plugin 98620 (HTTP Security Header Not Detected)",
        "confidence": 0.85,
        "false_positive_risk": FalsePositiveRisk.LOW,
        "recommended_fix": "Add X-Frame-Options: DENY and a restrictive Content-Security-Policy to the reverse proxy configuration.",
        "effort_level": "LOW",
        "remediation_status": RemediationStatus.OPEN,
        "tags": ["headers", "clickjacking"],
        "is_duplicate": True,
        "canonical_key": "missing-security-headers",
        "dedup_confidence": 0.88,
    },
    {
        "key": "sha1-cert",
        "scan_id": SCAN_NESSUS_ID,
        "tool_source": ToolSource.NESSUS,
        "tool_finding_id": "nessus-35291-10.20.4.12",
        "cwe_id": "CWE-327",
        "title": "SSL Certificate Signed Using Weak Hashing Algorithm (SHA-1)",
        "description": (
            "The certificate presented by the legacy reporting host is signed with "
            "SHA-1, which is deprecated due to demonstrated collision attacks and is "
            "rejected by modern browsers."
        ),
        "cvss_v3": 5.3,
        "severity_normalized": Severity.MEDIUM,
        "location_type": LocationType.HOST,
        "host": "10.20.4.12",
        "service": "https",
        "port": 443,
        "detection_method": "Nessus plugin 35291 (SSL Certificate Signed Using Weak Hashing Algorithm)",
        "confidence": 0.9,
        "false_positive_risk": FalsePositiveRisk.LOW,
        "recommended_fix": "Reissue the certificate using SHA-256 or better from the internal CA.",
        "effort_level": "LOW",
        "remediation_status": RemediationStatus.RISK_ACCEPTED,
        "business_context": "Host is scheduled for decommission in Q4; risk accepted pending retirement.",
        "tags": ["tls", "certificate"],
    },
    # --- LOW ------------------------------------------------------------------
    {
        "key": "weak-password-policy",
        "scan_id": SCAN_SONARQUBE_ID,
        "tool_source": ToolSource.SONARQUBE,
        "tool_finding_id": "AY-SQ-10371",
        "cwe_id": "CWE-521",
        "title": "Weak Password Policy Allows Short Passwords",
        "description": (
            "PasswordValidator accepts passwords as short as 6 characters with no "
            "complexity requirement, below the organization's minimum baseline for "
            "customer-facing financial accounts."
        ),
        "cvss_v3": 3.7,
        "severity_normalized": Severity.LOW,
        "location_type": LocationType.CODE,
        "code_file": "payments-api/src/main/java/com/zimatik/payments/auth/PasswordValidator.java",
        "code_line": 19,
        "detection_method": "Static analysis (hardcoded minimum length constant)",
        "confidence": 0.6,
        "false_positive_risk": FalsePositiveRisk.MEDIUM,
        "recommended_fix": "Raise the minimum length to 12 characters and require a mix of character classes, or adopt a passphrase + breached-password check policy.",
        "effort_level": "LOW",
        "remediation_status": RemediationStatus.OPEN,
        "tags": ["auth", "password-policy"],
    },
    {
        "key": "icmp-timestamp",
        "scan_id": SCAN_NESSUS_ID,
        "tool_source": ToolSource.NESSUS,
        "tool_finding_id": "nessus-10114-10.20.4.15",
        "title": "ICMP Timestamp Request Response",
        "description": (
            "The host responds to ICMP timestamp requests, which can be used to "
            "estimate system clock skew and aid in certain time-based attacks or OS "
            "fingerprinting."
        ),
        "cvss_v3": 2.6,
        "severity_normalized": Severity.LOW,
        "location_type": LocationType.HOST,
        "host": "10.20.4.15",
        "service": "icmp",
        "detection_method": "Nessus plugin 10114 (ICMP Timestamp Request Remote Date Disclosure)",
        "confidence": 0.95,
        "false_positive_risk": FalsePositiveRisk.LOW,
        "recommended_fix": "Disable ICMP timestamp responses at the host firewall.",
        "effort_level": "LOW",
        "remediation_status": RemediationStatus.WONT_FIX,
        "business_context": "Accepted as low-risk noise; not prioritized against higher-severity findings.",
        "tags": ["icmp", "info-disclosure"],
    },
    {
        "key": "verbose-errors",
        "scan_id": SCAN_SONARQUBE_ID,
        "tool_source": ToolSource.SONARQUBE,
        "tool_finding_id": "AY-SQ-10389",
        "cwe_id": "CWE-209",
        "title": "Verbose Error Messages Reveal Stack Trace",
        "description": (
            "The global exception handler returns the full Java stack trace, "
            "including internal class names and file paths, in the HTTP response "
            "body when an unhandled exception occurs."
        ),
        "cvss_v3": 3.1,
        "severity_normalized": Severity.LOW,
        "location_type": LocationType.CODE,
        "code_file": "payments-api/src/main/java/com/zimatik/payments/middleware/ErrorHandler.java",
        "code_line": 45,
        "detection_method": "Static analysis (exception.printStackTrace to HTTP response)",
        "confidence": 0.7,
        "false_positive_risk": FalsePositiveRisk.MEDIUM,
        "recommended_fix": "Return a generic error message to clients and log the full stack trace server-side only.",
        "effort_level": "LOW",
        "remediation_status": RemediationStatus.OPEN,
        "tags": ["info-disclosure", "error-handling"],
    },
    {
        "key": "outdated-jquery",
        "scan_id": SCAN_SONARQUBE_ID,
        "tool_source": ToolSource.SONARQUBE,
        "tool_finding_id": "AY-SQ-10402",
        "cve_id": "CVE-2020-11023",
        "cwe_id": "CWE-79",
        "title": "Outdated jQuery Library with Known Vulnerabilities",
        "description": (
            "The customer portal bundles jQuery 1.12.4, affected by a cross-site "
            "scripting flaw when passing HTML containing <option> elements to "
            "jQuery's DOM manipulation methods."
        ),
        "cvss_v3": 3.5,
        "severity_normalized": Severity.LOW,
        "location_type": LocationType.CODE,
        "code_file": "payments-api/src/main/resources/static/js/lib/jquery-1.12.4.min.js",
        "code_line": 1,
        "detection_method": "Software composition analysis (known-vulnerable dependency version match)",
        "confidence": 0.8,
        "false_positive_risk": FalsePositiveRisk.LOW,
        "recommended_fix": "Upgrade the bundled jQuery to 3.5.0 or later.",
        "effort_level": "LOW",
        "remediation_status": RemediationStatus.OPEN,
        "tags": ["dependency", "frontend"],
    },
    # --- INFO -------------------------------------------------------------
    {
        "key": "tcp-timestamps",
        "scan_id": SCAN_NESSUS_ID,
        "tool_source": ToolSource.NESSUS,
        "tool_finding_id": "nessus-25220-10.20.4.15",
        "title": "TCP Timestamps Enabled",
        "description": (
            "The host has TCP timestamps enabled, which can be used to estimate "
            "system uptime and, in rare configurations, assist fingerprinting. "
            "Informational only."
        ),
        "cvss_v3": 0.0,
        "severity_normalized": Severity.INFO,
        "location_type": LocationType.HOST,
        "host": "10.20.4.15",
        "service": "tcp",
        "detection_method": "Nessus plugin 25220 (TCP/IP Timestamps Supported)",
        "confidence": 0.95,
        "false_positive_risk": FalsePositiveRisk.LOW,
        "recommended_fix": "No action required; informational finding.",
        "effort_level": "LOW",
        "remediation_status": RemediationStatus.WONT_FIX,
        "tags": ["informational"],
    },
    {
        "key": "self-signed-cert-staging",
        "scan_id": SCAN_NESSUS_ID,
        "tool_source": ToolSource.NESSUS,
        "tool_finding_id": "nessus-57582-10.20.4.40",
        "title": "Self-Signed Certificate Detected in Staging Environment",
        "description": (
            "The staging payments environment presents a self-signed TLS "
            "certificate. Acceptable for non-production use, but flagged to confirm "
            "the host is not reachable from outside the corporate network."
        ),
        "cvss_v3": 0.0,
        "severity_normalized": Severity.INFO,
        "location_type": LocationType.HOST,
        "host": "10.20.4.40",
        "service": "https",
        "port": 443,
        "detection_method": "Nessus plugin 57582 (SSL Self-Signed Certificate)",
        "confidence": 0.9,
        "false_positive_risk": FalsePositiveRisk.LOW,
        "recommended_fix": "No action required if confirmed internal-only; otherwise issue a certificate from the internal CA.",
        "effort_level": "LOW",
        "remediation_status": RemediationStatus.FALSE_POSITIVE,
        "business_context": "Confirmed staging-only host, not internet-reachable; marked false positive after triage.",
        "tags": ["informational", "staging"],
    },
]


def _build_scans() -> list[Scan]:
    return [Scan(**scan_kwargs) for scan_kwargs in SCANS]


def _build_findings() -> list[Finding]:
    ids_by_key = {entry["key"]: uuid.uuid4() for entry in FINDINGS}

    findings = []
    for entry in FINDINGS:
        kwargs = {k: v for k, v in entry.items() if k not in ("key", "canonical_key")}
        kwargs["id"] = ids_by_key[entry["key"]]
        if "canonical_key" in entry:
            kwargs["canonical_id"] = ids_by_key[entry["canonical_key"]]
        findings.append(Finding(**kwargs))
    return findings


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--yes",
        "-y",
        action="store_true",
        help="Skip the confirmation prompt before clearing existing data.",
    )
    args = parser.parse_args()

    session = get_session_factory()()
    try:
        existing_scans = session.query(Scan).count()
        existing_findings = session.query(Finding).count()

        if existing_scans or existing_findings:
            print(
                f"Found {existing_scans} existing scan(s) and {existing_findings} "
                "existing finding(s)."
            )
            if not args.yes:
                answer = input("Clear existing data before seeding? [y/N] ").strip().lower()
                if answer != "y":
                    print("Aborted: existing data left untouched.")
                    sys.exit(0)

            # Deleting scans cascades to findings via the ORM relationship.
            session.query(Scan).delete()
            session.commit()
            print("Cleared existing scans and findings.")

        scans = _build_scans()
        findings = _build_findings()

        session.add_all(scans)
        session.add_all(findings)
        session.commit()

        print(f"Created {len(scans)} scans and {len(findings)} findings.")
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


if __name__ == "__main__":
    main()
