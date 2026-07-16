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

# ---- Tunables ---------------------------------------------------------
MAX_CVES_PER_SERVICE = 5   # list the top N CVEs per service (vulners lists worst-first)
NIST_DELAY = 1.5           # seconds to wait between NIST calls (respect rate limit)

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
    def get_local_ip():
        """Connects a dummy socket to pull the true local IP on the active interface."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80)) # Doesn't send data, just routes the interface
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except Exception:
            return "127.0.0.1" # Fallback if entirely offline

    # Get target: from the command line if given, else completely automate it.
    if len(sys.argv) > 1:                       
        target = sys.argv[1]
    else:                                       
        local_ip = get_local_ip()
        
        # If we are offline, just scan localhost. Otherwise, calculate the /24 VLAN.
        if local_ip == "127.0.0.1":
            target = local_ip
            print(f"\n[*] Offline mode. Auto-targeting localhost: {c(target, GREEN)}")
        else:
            # Split the IP (e.g., 192.168.1.45), drop the last number, and add .0/24
            ip_parts = local_ip.split('.')
            target = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
            print(f"\n[*] No target specified. Auto-sweeping local subnet: {c(target, GREEN)}")

    # Updated Regex: Perfectly accepts Subnets (CIDR notation like /24)
    ip_pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:/[0-9]{1,2})?$|^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
    if not ip_pattern.match(target):
        bad(f"Error: '{target}' is not a valid IP, Subnet, or hostname format.")
        logging.error(f"Invalid target format entered: {target}")
        sys.exit(1)

    logging.info(f"Target validated successfully: {target}")

    services = scan_target(target)              # run the nmap scan

    # [+] ENHANCEMENT: Start execution timer for the End-of-Run Summary
    start_time = time.time()
    
    show_banner()                                                   # clear + print banner
    
    # [+] ENHANCEMENT: Mandatory Rules of Engagement (RoE) prompt
    print(c("=" * 52, CYAN, BOLD))
    print(c("                 AUTHORIZED USE ONLY", BRED, BOLD))
    print(c(" Only scan systems you own or have explicit permission to assess.", DIM))
    print(c("=" * 52, CYAN, BOLD))
    
    auth = input("Do you confirm you are authorized to scan this target? [y/N]: ").strip().lower()
    if auth != 'y':
        bad("Access Denied. You must be authorized to run this tool. Exiting.")
        logging.warning("User aborted execution: Unauthorized scan attempt.")
        sys.exit(0)
        
    logging.info("Operator authorized scan. Tool initialized.")
    print()                                                         # blank spacer

    print(c("=" * 52, CYAN, BOLD))                                  # title bar top
    print(c("  LIVE THREAT INTEL  |  nmap + CVE lookup", CYAN, BOLD))# tool title
    print(c("=" * 52, CYAN, BOLD))                                  # title bar bottom

    # Get target: from the command line if given, else prompt for it.
    if len(sys.argv) > 1:                       # target passed as an argument
        target = sys.argv[1]
    else:                                       # nothing passed -> ask interactively
        target = input("\nTarget IP / hostname: ").strip()

    if not target:                              # empty input -> nothing to do
        bad("No target given. Exiting.")
        logging.error("No target provided.")
        sys.exit(1)                             # exit code 1 = error

    # [+] ENHANCEMENT: Pre-scan validation to prevent Nmap from hanging on bad IPs

    # Regex checks for a valid IPv4 format or a basic domain name.

    ip_pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$|^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
    if not ip_pattern.match(target):
        bad(f"Error: '{target}' is not a valid IP address or hostname format.")
        logging.error(f"Invalid target format entered: {target}")
        sys.exit(1)

    logging.info(f"Target validated successfully: {target}")

    services = scan_target(target)              # run the nmap scan

    if not services:                            # scan came back empty
        # [+] ENHANCEMENT: Updated error message to reflect testing edge-cases
        bad("No open ports found (host may be down, invalid, or filtering).")
        logging.warning(f"Scan finished, but no open ports found on {target}.")
        sys.exit(0)                             # exit code 0 = clean exit

    top_score = 0.0        # track highest severity seen (for the summary)
    vuln_services = 0      # count how many services had at least one CVE


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
        for cve in svc['cves'][:MAX_CVES_PER_SERVICE]:
            score = get_cvss_score(cve)                             # NIST: severity number
            desc = get_cve_description(cve)                         # CIRCL: description text
            top_score = max(top_score, score)                      # update running max

            label, color = severity(score)                         # bucket + color for score
            badge = c(f"{label:<8} {score:>4}/10", color, BOLD)    # e.g. "HIGH   8.1/10"
            print(f"\n  {c(cve, BOLD)}   {badge}")                 # CVE id + severity badge
            for line in textwrap.wrap(desc, width=70):             # wrap description
                print(f"    {line}")                               # indented, one line at a time

            time.sleep(NIST_DELAY)                                 # pace requests (rate limit)
# =======================================================================
    # [+] ENHANCEMENT: AUTOMATED CSV EXPORT (FULL INVENTORY)
    # -----------------------------------------------------------------------
    # Automatically generates a CSV containing every open port discovered.
    # Ports with no known CVEs are logged as "None - Clean" for team analysis.
    # =======================================================================
    csv_filename = "scan_report.csv"
    try:
        with open(csv_filename, mode="w", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)
            # Write the column headers
            writer.writerow(["Target", "Port", "Service", "CVE ID"])
            
            # Loop back through our results to populate the rows
            for s in services:
                cves = s.get('cves', [])
                
                # If the list of CVEs is empty, log the open port as clean
                if not cves:
                    writer.writerow([s['host'], s['port'], s['name'], "None - Clean"])
                
                # If there are vulnerabilities, log a row for each one
                else:
                    for cve in cves:
                        writer.writerow([s['host'], s['port'], s['name'], cve])
                        
        good(f"\nUser Report generated successfully: {csv_filename}")
        logging.info(f"{csv_filename} generated successfully.")
    except Exception as e:
        # Handle file I/O or CSV writing errors gracefully
        logging.exception("Failed to generate CSV report")
        try:
            # Fallback: notify user on stderr if 'good' isn't appropriate
            print(f"Failed to generate {csv_filename}: {e}")
        except Exception:
            pass
    # -----------------------------------------------------------------------
    # Calculates execution time and provides a clean snapshot of the scan 
    # results, making the terminal output feel much more polished.
    # =======================================================================
    runtime = round(time.time() - start_time, 2)
    total_cves = sum(len(s.get('cves', [])) for s in services)
    label, color = severity(top_score)                             

    print("\n" + c("=" * 52, CYAN, BOLD))
    print(c("                 SCAN COMPLETE", BOLD))
    print(c("=" * 52, CYAN, BOLD))
    print(f" Target:                 {target}")
    print(f" Total Open Services:    {len(services)}")
    print(f" Vulnerable Services:    {vuln_services}")
    print(f" Total CVEs Found:       {total_cves}")
    print(f" Highest Severity:       {c(f'{label} ({top_score}/10)', color, BOLD)}")
    print(f" Execution Time:         {runtime} seconds")
    print(f" Report Saved:           {csv_filename}")
    print(c("=" * 52, CYAN, BOLD))

    # Log the final metrics
    logging.info(f"Execution completed in {runtime}s. Vulnerable services: {vuln_services}. Total CVEs: {total_cves}.")

    # =======================================================================
    # [+] ENHANCEMENT: TRIGGER AUTOMATED PDF REPORT
    # -----------------------------------------------------------------------
    # Automatically runs report.py so the operator gets both the CSV and the 
    # finalized PDF without needing to run a second command.
    # =======================================================================
    print("\n" + c("[*] Launching PDF Report Generator...", CYAN))
    try:
        import subprocess
        # Pass the dashboard summary data directly into the PDF script
        subprocess.run([
            sys.executable, "report.py", 
            target, str(len(services)), str(vuln_services), 
            str(total_cves), str(top_score), label, str(runtime)
        ])
    except Exception as e:
        bad(f"Failed to automatically generate PDF report: {e}")
        logging.error(f"Failed to execute report.py: {e}")