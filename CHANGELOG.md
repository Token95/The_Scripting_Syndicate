# Changelog

All notable changes to the **Live Threat Intel** project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.4.0] - 2026-07-22
### Added
- **CISA KEV (Known Exploited Vulnerabilities) Enrichment:** Added `load_kev_catalog()` / `kev_lookup()` to cross-reference every CVE found against CISA's public feed of actively-exploited vulnerabilities. The whole catalog is downloaded once per run (not per-CVE) and cached to `kev_cache.json` for `KEV_CACHE_HOURS` to avoid needless re-downloads. Matches trigger a bright-red "ACTIVELY EXPLOITED" banner in the terminal, a `CISA KEV Matches` line in the end-of-run dashboard, and a warning-level `operator.log` entry with the federal remediation due date.
- **Enriched CSV/PDF Export:** CSV and PDF reports now include `CVSS Score`, `Severity`, `CISA KEV`, `KEV Due Date`, and `Remediation Guidance` columns instead of just the CVE ID, so both artifacts are actionable on their own without needing to cross-reference the terminal output.
- **Authoritative Remediation Text:** When a CVE is on the CISA KEV list, its `requiredAction` text is used as the remediation guidance instead of the generic "update to latest version" fallback.

### Changed
- **No Duplicate API Calls:** The per-service scan loop now caches each CVE's fetched CVSS score/description/KEV status (`svc['cve_data']`) so the CSV export reuses that data instead of re-querying NIST/CIRCL for the same CVE a second time.
- **Expanded Operator Log Coverage:** Added explicit `operator.log` entries for scan completion, the full execution summary, and each stage of the PDF hand-off (start, success, or `CRITICAL EXCEPTION` on failure), closing out the audit-trail requirement with a real, reviewable log of authorization, target selection, scan lifecycle, API failures, and report generation.

---

## [2.3.0] - 2026-07-15
### Added
- **Interactive Target Menu:** Replaced command-line arguments with a robust `while` loop menu. Operators can now choose between Localhost, Auto-detected Local Network, Custom Target, or a safe Exit option.
- **Rules of Engagement Gate:** Implemented a mandatory authorization prompt that executes *before* any network activity, ensuring strict ethical and operational compliance.
- **Self-Healing Dependency Loop:** The `check_dependencies` function now uses a verification loop to install the latest versions of all required packages (`pip install --upgrade`), preventing execution crashes due to outdated libraries.
- **Dynamic File Archiving:** All CSV and PDF output files now use human-readable, executive-friendly timestamps (`YYYY-MM-DD_HHMM`). Files are no longer overwritten, creating a comprehensive audit trail for every scan.
- **Cleaned Terminal Dashboard:** Upgraded the end-of-scan summary with a polished, professional output block that includes execution time, severity metrics, and the newly generated report filenames.
- **Standard Library Optimization:** Refactored imports to group all Python standard libraries at the top for PEP 8 compliance, while quarantining third-party dependencies behind the dependency checker.

---

## [2.2.0] - 2026-07-15
### Added
- **Zero-Touch Subnet Automation:** Integrated `socket` library to auto-discover local IPv4 addresses and calculate `/24` subnets.
- **Full Asset Inventory Logging:** CSV export logic now records all open ports; ports with no known CVEs are logged as "None - Clean."
- **Executive PDF Dashboard:** Added styled summary dashboard to PDF reports with dynamic color-coding based on CVSS severity.

---

## [2.1.0] - 2026-07-15
### Added
- **Automated PDF Report Generator:** Created `report.py` for professional executive-level reporting.
- **Script Chaining:** Automated the hand-off between `threat_intel.py` and `report.py`.
- **Operator Logging:** Persistent `operator.log` generation for troubleshooting and audit trails.
- **Pre-Scan Target Validation:** Regex-based input sanitization for IPs, hostnames, and CIDR notation.

### Fixed
- **Unresolved Target Handling:** Improved error feedback for unreachable hosts or filtering firewalls.