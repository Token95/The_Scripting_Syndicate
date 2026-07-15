# Changelog

All notable changes to the **Live Threat Intel** project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] - Planned for Weeks 4 & 5
### To Do
- Finalize documentation and PowerPoint presentation.
- Conduct final end-to-end testing across Windows and Linux environments.

---

## [2.1.0] - 2026-07-15
### Added
- **Interactive Dependency Check:** Replaced the silent background installation script with an interactive prompt. The script now notifies the user of missing packages and requests explicit `[y/N]` permission before executing `pip install`[cite: 1].
- **Operator Logging:** Implemented persistent background logging. The script now automatically generates an `operator.log` file that records timestamps, tool initialization, API calls, and errors for auditing and troubleshooting[cite: 1].
- **Authorized Use Prompt (Rules of Engagement):** Added a mandatory authorization gate. Operators must now explicitly confirm they have permission to scan the target `[y/N]` before the script proceeds, ensuring ethical compliance[cite: 1].
- **Pre-Scan Target Validation:** Introduced a Regular Expression (Regex) validation check for the target input. This prevents the Nmap wrapper from hanging or executing against invalid formats (e.g., `999.999.999.999`)[cite: 1].
- **Automated CSV Export:** Added functionality to automatically generate a `scan_report.csv` file upon completion. This User Report includes Target, Port, Service, and CVE IDs for easier handoffs and analysis[cite: 1].
- **End-of-Run Summary Dashboard:** Integrated a runtime timer and a final summary block that outputs the total execution time, total open services, vulnerable services, and the highest CVSS severity found[cite: 1].

### Changed
- **Status Helpers:** Upgraded the `info()`, `good()`, and `bad()` terminal functions to simultaneously write their outputs to the `operator.log` file.
- **Dependencies:** Updated `requirements.txt` to explicitly track `pyfiglet` alongside `python-nmap` and `requests`.

### Fixed
- **Unresolved Target Handling:** Corrected the terminal output to accurately reflect when a scan fails due to the host being unreachable, invalid, or aggressively filtering traffic[cite: 1].