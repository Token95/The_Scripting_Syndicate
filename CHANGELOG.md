# Changelog

All notable changes to the **Live Threat Intel** project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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