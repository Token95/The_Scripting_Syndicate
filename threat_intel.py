#!/usr/bin/env python3
# =======================================================================
#  THE SCRIPTING SYNDICATE  -  Live Threat Intel (nmap + CVE lookup)
# -----------------------------------------------------------------------
#  What this script does:
#    1. Interactively check Python dependencies [ENHANCED]
#    2. Requests Opertator Authorization (Rules of Engagement) [ENHANCED]
#    3. Validates targest format to prevent hangs [ENHANCED]
#    4. Runs nmap services/version scan aganst a target
#    5. Pulls CVE descriptions from CIRCL and CVSS scores from NIST.
#    6. Generate a terminal report, CSV file, and runtimes Log. [ENHANCED]
# =======================================================================

import os                 # run shell commands (like clear screen)
import sys                # handles exit codes, command-line arguments, and terminal checks
import socket             # [+] ENHANCEMENT: auto-detect local network IP
import subprocess         # shell to pip during the bootstrap
import time               # sleep() to pace NIST requests

# ... the rest of your imports ...
# =======================================================================
# [+] ENHANCEMENT 1: INTERACTIVE DEPENDENCY CHECK
# -----------------------------------------------------------------------
# Replaces the previous silent background installer. Silently executing
# system commands can trigger security flags and makes troubleshooting
# difficult for operators. This updated block attempts to import the
# required third-party libraries first. If an ImportError is caught, it
# pauses execution, notifies the operator exactly which package is missing,
# and explicitly asks for authorization (y/N) before modifying the system.
# =======================================================================

try:
    import nmap            # Wrapper used to control the Nmap binary from Python
    import requests        # Handles HTTP GET requests to the CIRCL and NIST APIs
    import pyfiglet        # Generates the ASCII art banner for the CLI interface
   

except ImportError as e:

    # 'e' contains the raw error message (e.g., "No module named 'requests'").
    # We convert it to a string and split it at the single quotes to isolate just the package name.

    missing_module = str(e).split("'")[1] if "'" in str(e) else str(e)
    
    # Display a highly visible warning block to the operator

    print("=" * 50)
    print(f"[-] WARNING: Missing required Python package: '{missing_module}'")
    print("=" * 50)
    
    # Prompt the operator for explicit authorization before installing anything

    choice = input(f"Would you like to install '{missing_module}' now? [y/N]: ").strip().lower()
    
    if choice == 'y':
        print(f"[*] Installing {missing_module}...")
        
        # The 'nmap' library is imported as 'nmap', but the actual pip package is 'python-nmap'.
        # This inline check ensures we tell pip to fetch the correct package name.

        pkg_name = "python-nmap" if missing_module == "nmap" else missing_module
        
        # Execute the pip install command visibly in the terminal.
        # - sys.executable ensures we use the pip associated with the current Python environment.
        # - --break-system-packages allows installation on modern, managed Linux environments like our Ubuntu testing VM.

        subprocess.run([sys.executable, "-m", "pip", "install", pkg_name, "--break-system-packages"])
        
        # Require a clean restart to ensure the newly installed module is properly loaded into memory

        print("[+] Installation complete. Please restart the script.")
        sys.exit(0)  # Exit code 0 indicates a clean, intentional termination
        
    else:

        # If the user denies authorization, we cannot proceed. Exit gracefully.

        print("[-] Cannot run without dependencies. Exiting.")
        sys.exit(1)  # Exit code 1 indicates termination due to an error/missing requirement
# -----------------------------------------------------------------------

# =======================================================================
# [+] ENHANCEMENT: DEPENDENCY CHECKER (LATEST VERSIONS & VERIFICATION LOOP)
# =======================================================================

def check_dependencies():
    """Loops to ensure all required packages are installed and up to date."""
    required_packages = {
        'nmap': 'python-nmap',
        'requests': 'requests',
        'pyfiglet': 'pyfiglet',
        'fpdf': 'fpdf'
    }
    
    while True:
        missing = []
        for module, pip_name in required_packages.items():
            try:
                __import__(module)
            except ImportError:
                missing.append(pip_name)
                
        if not missing:
            break # All dependencies are met, break the loop!
            
        print(f"\n[!] Missing required packages: {', '.join(missing)}")
        ans = input("Would you like to install the latest versions now? [y/N]: ").strip().lower()
        
        if ans in ['y', 'yes']:
            print("[*] Installing latest dependencies...")
            import subprocess

            # Added --upgrade to ensure we grab the absolute latest versions

            subprocess.run([sys.executable, "-m", "pip", "install", "--upgrade"] + missing)
            print("[*] Install complete. Looping back to verify...")
        else:
            print("[-] Cannot proceed without dependencies. Exiting.")
            sys.exit(1)

# ---- Third-party + remaining stdlib imports ------

import re              # regex, used to pull CVE IDs out of nmap output
import time            # sleep() to pace NIST requests
import textwrap        # wrap long CVE descriptions
import configparser    # read API URLs from settings.ini
import requests        # HTTP requests
import nmap            # nmap wrapper

# [+] ENHANCEMENT 2: Imported modules for Data Export and Auditing

import csv
import logging

# [+] ENHANCEMENT 3: Imported for reading/writing the local CISA KEV cache file

import json

# Configure the persistent Operator Log

logging.basicConfig(
    filename='operator.log', 
    level=logging.INFO, 
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# ---- Configuration: read API endpoints from settings.ini --------------

config = configparser.ConfigParser()       # create config reader
config.read('settings.ini')                # load ini file from cwd
NIST_URL = config['API_ENDPOINTS']['nist_url']    # NVD score endpoint (+ cveId=)
CIRCL_URL = config['API_ENDPOINTS']['circl_url']  # CIRCL description endpoint
NIST_API_KEY = config['API_ENDPOINTS'].get('nist_api_key','') # Safely load key if it exists
KEV_URL = config['API_ENDPOINTS'].get('kev_url','') # CISA KEV catalog (no key needed)

# ---- Tunables ---------------------------------------------------------

MAX_CVES_PER_SERVICE = 5   # list the top N CVEs per service (vulners lists worst-first)
NIST_DELAY = 1.5           # seconds to wait between NIST calls (respect rate limit)

# [+] ENHANCEMENT 3: CISA KEV local cache settings
# The KEV feed is one big JSON file (the whole catalog, not per-CVE lookups),
# so we pull it once per run and keep a copy on disk. If the copy on disk is
# still younger than KEV_CACHE_HOURS, we reuse it instead of re-downloading.

KEV_CACHE_FILE = "kev_cache.json"   # where the local copy of the catalog is stored
KEV_CACHE_HOURS = 24                # how long the local copy stays "fresh"

# ---- Colors: ANSI codes for terminal styling -------------------

USE_COLOR = sys.stdout.isatty()   # True for a terminal; False if piped to a file
RESET  = "\033[0m"     # reset all styling back to normal
BOLD   = "\033[1m"     # bold text
DIM    = "\033[2m"     # faded/dim text
RED    = "\033[31m"    # red    -> HIGH severity
GREEN  = "\033[32m"    # green  -> LOW severity / success markers
YELLOW = "\033[33m"    # yellow -> MEDIUM severity
CYAN   = "\033[36m"    # cyan   -> headings / info markers
BRED   = "\033[91m"    # bright red -> CRITICAL severity


def c(text, *styles):
    """Wrap text in one or more ANSI styles. Returns plain text if color is off."""
    if not USE_COLOR:                       # not a terminal -> don't add codes
        return text
    return "".join(styles) + text + RESET   # prepend styles, append reset


# ---- Status-line helpers (colored [*]/[+]/[-] prefixes) ----------

# [+] ENHANCEMENT 2: Upgraded status helpers to simultaneously print to the terminal 
# and record the exact same event in 'operator.log' for troubleshooting and auditing.

def info(msg): 
    print(f"{c('[*]', CYAN)} {msg}")      # [*] cyan   = informational
    logging.info(msg)                     # Silently write to log file

def good(msg): 
    print(f"{c('[+]', GREEN)} {msg}")     # [+] green  = good news
    logging.info(msg)                     # Silently write to log file

def bad(msg):  
    print(f"{c('[-]', RED)} {msg}")       # [-] red    = problem/error
    logging.error(msg)                    # Silently write error to log file



def severity(score):
    """Map a numeric CVSS base score to a (label, color) pair."""
    if score >= 9.0:                 # 9.0 - 10.0
        return "CRITICAL", BRED
    if score >= 7.0:                 # 7.0 - 8.9
        return "HIGH", RED
    if score >= 4.0:                 # 4.0 - 6.9
        return "MEDIUM", YELLOW
    if score > 0.0:                  # 0.1 - 3.9
        return "LOW", GREEN
    return "NONE", DIM               # 0.0 / unknown


def rule(width=52):
    """Print dim horizontal separator line."""
    print(c("-" * width, DIM))


# ---- Banner: team name (ASCII art) + roster --------------------------

BANNER_TEXT = "Scripting Syndicate"   # text rendered as ASCII art
BANNER_FONT = "small"                 # any installed pyfiglet font: small/standard/slant/big

TEAM = [                              # (name, role) pairs, printed under the art
    ("Devon Brown",           "Project Lead & Developer"),
    ("Shannika Dyer",         "Documentarian"),
    ("Adam Timmons",          "Tester"),
    ("Edy Silveira de Souza", "Presenter"),
]


def clear():
    """Clear the terminal (cls on Windows, clear everywhere else)."""
    os.system('cls' if os.name == 'nt' else 'clear')


def banner_lines():
    """BANNER_TEXT as ASCII art; fall back to plain text if pyfiglet is missing."""
    try:
        import pyfiglet                                                  # imported as fall back
        art = pyfiglet.figlet_format(BANNER_TEXT, font=BANNER_FONT, width=120)  # make art
        return art.rstrip("\n").split("\n")                             # trim + split into lines
    except Exception:                                                   # pyfiglet absent or bad font
        return [BANNER_TEXT]                                            # plain-text fallback


def show_banner():
    """Clear the screen and print the ASCII banner plus the team roster."""
    clear()                                                       # wipe the terminal
    lines = banner_lines()                                        # get art lines
    width = max((len(line) for line in lines), default=len(BANNER_TEXT))  # widest art line
    print()                                                       # blank spacer
    print(c("  " + "T H E".center(width), CYAN, BOLD))            # centered "T H E" over the art
    for line in lines:                                            # print each art line
        print(c("  " + line, CYAN, BOLD))
    print()                                                       # blank spacer
    for name, role in TEAM:                                       # print roster
        print(f"  {c(f'{name:<23}', BOLD)}{c(role, DIM)}")        # name (bold) padded, role (dim)
    print()                                                       # blank spacer


def get_cve_description(cve_id):
    """Hit CIRCL's Vulnerability-Lookup API and return a plain-English description."""
    if not cve_id or str(cve_id).lower() == "None":                                    # guard: no CVE to look up
        return "No vulnerability identified."
    info(f"Fetching description for {cve_id} from CIRCL...") # status line
    try:
        response = requests.get(f"{CIRCL_URL}{cve_id}", timeout=10)   # GET the CVE record
        if response.status_code == 200 and response.json():          # got a valid JSON body
            data = response.json()                                   # parse it

            # In the CVE 5.0 format the text lives at containers.cna.descriptions[].

            descriptions = data.get("containers", {}).get("cna", {}).get("descriptions", [])
            for d in descriptions:                                   # look through each entry
                if d.get("lang", "").lower().startswith("en"):       # find in English
                    return d.get("value", "Description not found.")  # return text
    except Exception as e:                                           # network/JSON error
        bad(f"CIRCL API Error: {e}")
    return "Failed to retrieve description."                         # default if nothing matched


def get_cvss_score(cve_id):
    """Hit the NIST NVD API and return the CVSS base score (tries v3.1 -> v3.0 -> v2)."""
    if not cve_id or str(cve_id).lower() == "None":                                    # guard: no CVE to look up
        return 0.0
    info(f"Fetching CVSS score for {cve_id} from NIST...")  # status line

    # ----- BROWSER DISGUISE + OPTIONAL API KEY ------------------------

    headers ={
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHMTL, like Gecko) Chrome/114.0.0.0 Safari/537.36'
    }
    if NIST_API_KEY:                                                # Guard: only attach if key was found
        headers['apiKey'] = NIST_API_KEY                            # Inject VIP key to bypass rate limits
    try:
        response = requests.get(f"{NIST_URL}{cve_id}", headers=headers, timeout=10)   # GET the CVE record
        if response.status_code == 200:                              # success
            vuln_data = response.json().get("vulnerabilities", [])   # list matches
            if vuln_data:                                            # at least one match
                metrics = vuln_data[0].get("cve", {}).get("metrics", {})   # scoring block
                for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):  # newest first
                    if key in metrics:                               # this version exists
                        return metrics[key][0]["cvssData"]["baseScore"]   # return its score
        elif response.status_code == 429:                            # rate limited
            bad("NIST rate limit hit (HTTP 429) - slow down or get an API key.")
    except Exception as e:                                           # network/JSON error
        bad(f"NIST API Error: {e}")
    return 0.0                                                       # default if no score found


# =======================================================================
# [+] ENHANCEMENT 3: CISA KEV (KNOWN EXPLOITED VULNERABILITIES) CATALOG
# -----------------------------------------------------------------------
# Unlike NIST/CIRCL, this is NOT a per-CVE lookup - it is one JSON download
# of the entire catalog, which we index locally by CVE ID. That means
# adding this enrichment costs exactly ONE extra network call per run,
# not one per CVE, and it never counts against the NIST rate limit.
# =======================================================================

def load_kev_catalog():
    """Download the CISA KEV catalog once, index it by CVE ID, and cache it
    on disk so repeated runs within KEV_CACHE_HOURS don't re-download it."""
    if not KEV_URL:                                        # guard: no URL configured
        return {}

    # ----- SERVE FROM A FRESH LOCAL CACHE IF WE HAVE ONE ---------------

    if os.path.exists(KEV_CACHE_FILE):                                  # a cached copy exists
        age_hours = (time.time() - os.path.getmtime(KEV_CACHE_FILE)) / 3600  # how old is it
        if age_hours < KEV_CACHE_HOURS:                                 # still fresh enough
            try:
                with open(KEV_CACHE_FILE, "r", encoding="utf-8") as f:
                    kev_map = json.load(f)                              # load cached dict
                good(f"CISA KEV catalog loaded from local cache ({age_hours:.1f}h old, {len(kev_map)} entries).")
                return kev_map
            except Exception:                                           # corrupt cache file
                pass                                                    # fall through and re-fetch live

    # ----- OTHERWISE, FETCH THE LIVE CATALOG ----------------------------

    info("Fetching CISA Known Exploited Vulnerabilities (KEV) catalog...")
    try:
        response = requests.get(KEV_URL, timeout=15)            # GET the full catalog
        if response.status_code == 200:                         # success
            data = response.json()                              # parse the JSON body

            # Re-key the "vulnerabilities" list by cveID so lookups are O(1)
            # instead of scanning the whole list for every CVE we found.

            kev_map = {v["cveID"]: v for v in data.get("vulnerabilities", []) if "cveID" in v}

            try:
                with open(KEV_CACHE_FILE, "w", encoding="utf-8") as f:
                    json.dump(kev_map, f)                       # save for next run
            except Exception as e:                              # disk write failed - not fatal
                bad(f"Could not write KEV cache to disk: {e}")

            good(f"CISA KEV catalog loaded: {len(kev_map)} known-exploited CVEs indexed.")
            return kev_map
        else:
            bad(f"CISA KEV fetch failed (HTTP {response.status_code}).")
    except Exception as e:                                       # network/JSON error
        bad(f"CISA KEV API Error: {e}")

    # ----- LIVE FETCH FAILED: FALL BACK TO A STALE CACHE IF WE HAVE ONE -

    if os.path.exists(KEV_CACHE_FILE):
        try:
            with open(KEV_CACHE_FILE, "r", encoding="utf-8") as f:
                kev_map = json.load(f)
            bad("Using stale local KEV cache because the live fetch failed.")
            return kev_map
        except Exception:
            pass

    bad("CISA KEV catalog unavailable this run - continuing without it.")
    return {}                                                    # never block the scan on this


def kev_lookup(cve_id, kev_data):
    """Return the CISA KEV entry for a CVE ID, or None if it isn't in the catalog.
    This is a plain local dict lookup - no network call - so it's free to call
    for every CVE, even ones we didn't spend a NIST call scoring."""
    if not cve_id or not kev_data:                              # guard: nothing to check
        return None
    return kev_data.get(cve_id)


def scan_target(target):
    """Run 'nmap -sV --script vulners' against target and collect CVEs per open service."""
    info(f"Scanning {target} (nmap -sV --script vulners)... this can take a minute.")
    nm = nmap.PortScanner()                                  # create the scanner object
    nm.scan(hosts=target, arguments='-sV --script vulners')  # -sV = version detect, vulners = CVE map

    services = []                                            # results here
    for host in nm.all_hosts():                              # each host that responded
        for proto in nm[host].all_protocols():              # each protocol (tcp/udp)
            for port in sorted(nm[host][proto].keys()):     # each port, low -> high
                svc = nm[host][proto][port]                 # this port's service info
                if svc.get('state') != 'open':              # skip anything not open
                    continue

                # The vulners script output is only present when -sV found a version.

                vulners_out = svc.get('script', {}).get('vulners', '')

                # Pull CVE IDs from text, keeping vulners' worst-first order,
                # dropping duplicates (each CVE appears twice: as an ID and in a URL).

                seen, cves = set(), []
                for cve in re.findall(r'CVE-\d{4}-\d+', vulners_out):  # regex-match CVE IDs
                    if cve not in seen:                               # first time seen
                        seen.add(cve)                                 # remember it
                        cves.append(cve)                              # keep in order

                services.append({                           # store record per service
                    'host': host,
                    'port': port,
                    'proto': proto,
                    'name': svc.get('name', ''),            # service name (e.g. ssh)
                    'product': svc.get('product', ''),      # product (e.g. OpenSSH)
                    'version': svc.get('version', ''),      # version string
                    'cves': cves,                           # list of CVE IDs found
                })
    return services                                         # return all services


# ---- Main: runs when the file is executed directly ---------------

if __name__ == "__main__":


# =======================================================================
    # [+] ENHANCEMENT: ZERO-TOUCH AUTO-DISCOVER & SUBNET SWEEP
    # -----------------------------------------------------------------------
    # Automatically detects the machine's local IP and calculates the /24 
    # subnet. Bypasses user input entirely unless a target is explicitly 
    # passed via the command line.
    # =======================================================================


    # Start execution timer for the End-of-Run Summary

    start_time = time.time()
    
    show_banner()                                               # clear + print banner
    
    print(c("=" * 52, CYAN, BOLD))                              # title bar top
    print(c("  LIVE THREAT INTEL  |  nmap + CVE lookup", CYAN, BOLD)) # tool title
    print(c("=" * 52, CYAN, BOLD))                              # title bar bottom

    # =======================================================================
    # [+] ENHANCEMENT: AUTHORIZATION & INTERACTIVE MENU
    # =======================================================================
    
    # 1. Mandatory Authorization Gate FIRST

    print("\n" + c("[!] RULES OF ENGAGEMENT", YELLOW))
    roe = input("Do you have explicit authorization to scan this environment? [y/N]: ").strip().lower()
    if roe not in ['y', 'yes']:
        bad("Authorization denied. Exiting script.")
        logging.warning("User denied authorization. Exiting.")
        sys.exit(1)
        
    logging.info("Operator authorized scan. Tool initialized.")

    # 2. Get local network info for the menu

    def get_local_ip():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except Exception:
            return "127.0.0.1"

    local_ip = get_local_ip()

    # Safely calculate the /24 subnet based on the discovered IP

    subnet = "127.0.0.1" if local_ip == "127.0.0.1" else f"{local_ip.rsplit('.', 1)[0]}.0/24"

    # 3. Interactive Menu Loop

    target = None
    if len(sys.argv) > 1: 

        # If the operator passed an IP via command line, skip the menu

        target = sys.argv[1]
    else:
        while True:
            print("\n" + c("=== TARGET SELECTION MENU ===", CYAN))
            print("  1. Scan Localhost (127.0.0.1)")
            print(f"  2. Scan Local Network ({subnet})")
            print("  3. Enter Custom Target (IP / Subnet / Hostname)")
            print("  4. End Scan / Exit")
            
            choice = input(f"\nSelect an option [1-4]: ").strip()
            
            if choice == '1':
                target = "127.0.0.1"
                break
            elif choice == '2':
                target = subnet
                break
            elif choice == '3':
                target = input("Enter Custom Target: ").strip()

                # Regex validation before accepting the custom input

                ip_pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:/[0-9]{1,2})?$|^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
                if not ip_pattern.match(target):
                    bad("Error: Invalid IP, Subnet, or hostname format. Please try again.")
                    continue # Loops them back to the menu
                break
            elif choice == '4':
                good("Exiting The Scripting Syndicate tool. Goodbye!")
                sys.exit(0)
            else:
                bad("Invalid selection. Please enter a number between 1 and 4.")

    logging.info(f"Target validated successfully: {target}")

    # 4. Load the CISA KEV catalog (one download for the whole run, not per-CVE)

    kev_data = load_kev_catalog()
    logging.info(f"CISA KEV catalog ready with {len(kev_data)} entries.")

    # 5. Execute the Scan

    services = scan_target(target)

    # 6. Handle empty scan results

    if not services:
        bad("No open ports found (host may be down, invalid, or filtering).")
        logging.warning(f"Scan finished, but no open ports found on {target}.")
        sys.exit(0)

    top_score = 0.0        # track highest severity seen (for the summary)
    vuln_services = 0      # count how many services had at least one CVE
    kev_hits = 0            # count how many found CVEs are on the CISA KEV list

    # ---- Per-service report loop --------------------------------------

    for svc in services:

        # Build a banner: else the service name, else "unknown".

        banner = f"{svc['product']} {svc['version']}".strip() or svc['name'] or "unknown"
        endpoint = f"{svc['host']}:{svc['port']}/{svc['proto']}"     # e.g. 127.0.0.1:22/tcp

        print()                                                     # spacer
        rule()                                                      # separator line
        print(f"  {c(endpoint, BOLD)}   {c(banner, CYAN)}")         # header: address + service
        rule()                                                      # separator line

        if not svc['cves']:                                         # nothing found for service
            good("No known CVEs matched for this service.")
            continue                                                # move to next service

        vuln_services += 1                                          # this service has CVEs

        # Show only the top few CVEs (worst-first) to limit API calls.

        svc['cve_data'] = {}                                        # cache per-CVE results here so
                                                                      # the CSV/PDF export below can
                                                                      # reuse them instead of re-calling
                                                                      # the NIST/CIRCL APIs a second time

        for cve in svc['cves'][:MAX_CVES_PER_SERVICE]:
            score = get_cvss_score(cve)                             # NIST: severity number
            desc = get_cve_description(cve)                         # CIRCL: description text
            top_score = max(top_score, score)                      # update running max

            label, color = severity(score)                         # bucket + color for score
            badge = c(f"{label:<8} {score:>4}/10", color, BOLD)    # e.g. "HIGH   8.1/10"
            print(f"\n  {c(cve, BOLD)}   {badge}")                 # CVE id + severity badge
            for line in textwrap.wrap(desc, width=70):             # wrap description
                print(f"    {line}")                               # indented, one line at a time

            # ----- CISA KEV CHECK: free local dict lookup, no extra API call -----

            kev_entry = kev_lookup(cve, kev_data)                  # None if not on the KEV list
            if kev_entry:
                kev_hits += 1                                       # tally for the summary line
                due = kev_entry.get("dueDate", "Unknown")           # federal remediation deadline
                action = kev_entry.get("requiredAction", "Apply vendor patch immediately.")
                warning = f"CISA KEV: ACTIVELY EXPLOITED IN THE WILD - remediate by {due}"
                print(f"    {c(warning, BRED, BOLD)}")             # bright-red banner, hard to miss
                for line in textwrap.wrap(f"Required Action: {action}", width=70):
                    print(f"    {line}")
                logging.warning(f"{cve} is on the CISA KEV catalog (due {due}): {action}")

            # Save everything we just fetched so the CSV/PDF export doesn't
            # need to hit NIST/CIRCL again for the same CVE.

            svc['cve_data'][cve] = {
                'score': score,
                'label': label,
                'desc': desc,
                'kev': bool(kev_entry),
                'kev_due': kev_entry.get('dueDate', '') if kev_entry else '',
                'kev_action': kev_entry.get('requiredAction', '') if kev_entry else '',
            }

            time.sleep(NIST_DELAY)                                 # pace requests (rate limit)

    # =======================================================================
    # [+] ENHANCEMENT: ENRICHED CSV EXPORT (Actionable Data + Remediation)
    # -----------------------------------------------------------------------
    # This reuses the score/description/KEV data already fetched in the
    # per-service loop above (svc['cve_data']) instead of calling NIST or
    # CIRCL a second time for the same CVE - the report gets richer without
    # costing any additional API calls.
    # =======================================================================
    try:
        import csv
        from datetime import datetime

        # Generate a unique timestamp for the filenames (YYYY-MM-DD_HHMM)

        timestamp_str = datetime.now().strftime("%Y-%m-%d_%H%M")
        csv_filename = f"scan_report_{timestamp_str}.csv"
        pdf_filename = f"Executive_Report_{timestamp_str}.pdf"

        logging.info(f"Initiating CSV report generation: {csv_filename}")

        with open(csv_filename, mode="w", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)

            # Expanded headers for actionable analyst intelligence

            writer.writerow([
                "Target", "Port", "Service", "CVE ID",
                "CVSS Score", "Severity", "CISA KEV", "KEV Due Date",
                "Remediation Guidance"
            ])

            # Loop back through our results to populate the rows

            for s in services:
                cves = s.get('cves', [])
                cached = s.get('cve_data', {})   # scores/descriptions/KEV data fetched earlier

                if not cves:
                    writer.writerow([
                        s['host'], s['port'], s['name'], "None - Clean",
                        "0.0", "NONE", "No", "",
                        "No action required. Port is clean."
                    ])
                    continue

                for cve in cves:
                    data = cached.get(cve)   # only the top MAX_CVES_PER_SERVICE were scored live

                    if data:
                        # Already fetched above - reuse it, no new network call.

                        score, label = data['score'], data['label']
                        is_kev, kev_due, kev_action = data['kev'], data['kev_due'], data['kev_action']
                    else:
                        # This CVE was past the top-N cutoff and never scored, to keep
                        # NIST call volume capped. The KEV check is still free (a local
                        # dict lookup against the catalog we already downloaded once),
                        # so we still run it - we just don't call NIST/CIRCL again here.

                        score, label = "N/A", "UNSCORED"
                        kev_entry = kev_lookup(cve, kev_data)
                        is_kev = bool(kev_entry)
                        kev_due = kev_entry.get('dueDate', '') if kev_entry else ''
                        kev_action = kev_entry.get('requiredAction', '') if kev_entry else ''

                    # CISA's required action is authoritative when a CVE is on the KEV
                    # list; otherwise fall back to generic vendor-patch guidance.

                    if is_kev:
                        remediation = f"[CISA KEV - DUE {kev_due}] {kev_action}"
                    else:
                        remediation = f"Update {s['name']} package to latest vendor-patched version or apply patch for {cve}."

                    writer.writerow([
                        s['host'], s['port'], s['name'], cve,
                        score, label, "Yes" if is_kev else "No", kev_due,
                        remediation
                    ])

        good(f"\nUser Report generated successfully: {csv_filename}")
        logging.info(f"CSV report generated successfully: {csv_filename}")
    except Exception as e:
        bad(f"\nFailed to create CSV report: {e}")
        logging.error(f"CRITICAL EXCEPTION: CSV Generation failed: {e}")

    # =======================================================================
    # [+] TERMINAL DASHBOARD: END-OF-RUN SUMMARY
    # =======================================================================

    runtime = round(time.time() - start_time, 2)
    total_cves = sum(len(s.get('cves', [])) for s in services)
    label, color = severity(top_score)

    # KEV line is red the moment even one match exists - that's the whole point
    # of pulling this feed: it should be impossible for an analyst to miss.

    kev_color = BRED if kev_hits > 0 else GREEN

    print("\n" + c("=" * 52, CYAN, BOLD))
    print(c("                SCAN COMPLETE", BOLD))
    print(c("=" * 52, CYAN, BOLD))
    print(f" Target:                 {target}")
    print(f" Total Open Services:    {len(services)}")
    print(f" Vulnerable Services:    {vuln_services}")
    print(f" Total CVEs Found:       {total_cves}")
    print(f" CISA KEV Matches:       {c(str(kev_hits), kev_color, BOLD)}")
    print(f" Highest Severity:       {c(f'{label} ({top_score}/10)', color, BOLD)}")
    print(f" Execution Time:         {runtime} seconds")
    print(f" Report Saved:           {csv_filename}")
    print(c("=" * 52, CYAN, BOLD))

    # Log the final completion metrics for the audit trail

    logging.info(f"Scan completed successfully on target: {target}")
    logging.info(
        f"Execution summary -> Runtime: {runtime}s | Total Services: {len(services)} | "
        f"Vulnerable Services: {vuln_services} | Total CVEs: {total_cves} | "
        f"CISA KEV Matches: {kev_hits} | Peak Severity: {label} ({top_score}/10)"
    )

    # =======================================================================
    # [+] ENHANCEMENT: TRIGGER AUTOMATED PDF REPORT
    # =======================================================================

    print("\n" + c("[*] Launching PDF Report Generator...", CYAN))
    logging.info("Initiating hand-off to report.py for PDF generation.")
    try:
        import subprocess

        # Pass the dashboard summary data AND the dynamic filenames directly into the PDF script

        subprocess.run([
            sys.executable, "report.py",
            target, str(len(services)), str(vuln_services),
            str(total_cves), str(top_score), label, str(runtime),
            csv_filename, pdf_filename
        ])
        logging.info(f"PDF report generated successfully: {pdf_filename}")
    except Exception as e:
        bad(f"Failed to automatically generate PDF report: {e}")
        logging.error(f"CRITICAL EXCEPTION: Failed to execute report.py: {e}")