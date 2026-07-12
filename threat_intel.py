#!/usr/bin/env python3
# =======================================================================
#  THE SCRIPTING SYNDICATE  -  Live Threat Intel (nmap + CVE lookup)
# -----------------------------------------------------------------------
#  What this script does:
#    1. Silently makes sure Python dependencies are installed.
#    2. Prints team banner.
#    3. Runs nmap service/version scan against a target, with the
#       "vulners" script to map service versions -> known CVEs.
#    4. Every CVE it finds, pulls description from
#       CIRCL and a CVSS severity score from NIST.
#    5. Prints color-coded report and short summary.
# =======================================================================

# ---- Standard-library imports for the dependency bootstrap ------
import os                 # run shell commands (clear screen)
import sys                # interpreter path, argv, stdout, exit codes
import subprocess         # shell to pip during the bootstrap
import importlib.util     # check if module is installed without importing it

# ---- Dependency bootstrap: silently install anything missing ----------
# Runs BEFORE third-party imports below, so imports can't fail.
# Key = the name you 'import', Value = the name pip installs (they differ
# for python-nmap, which is imported as just 'nmap').
REQUIRED = {
    "requests": "requests",       # HTTP client for the API calls
    "nmap": "python-nmap",        # Python wrapper around the nmap binary
    "pyfiglet": "pyfiglet",       # turns text into ASCII-art for the banner
}


def _ensure_deps():
    """Install any required package that isn't already importable, silently."""
    for module, package in REQUIRED.items():          # walk each dependency
        if importlib.util.find_spec(module) is None:  # None = not installed
            subprocess.run(                           # call: pip install <pkg>
                [sys.executable, "-m", "pip", "install", package,
                 "--break-system-packages",           # allow install on managed Python
                 "--quiet"],                           # suppress pip's own chatter
                stdout=subprocess.DEVNULL,             # hide normal output
                stderr=subprocess.DEVNULL,             # hide errors too (stay silent)
            )


_ensure_deps()   # run the check/install, before we import them
# -----------------------------------------------------------------------

# ---- Third-party + remaining stdlib imports ------
import re              # regex, used to pull CVE IDs out of nmap output
import time            # sleep() to pace NIST requests
import textwrap        # wrap long CVE descriptions
import configparser    # read API URLs from settings.ini
import requests        # HTTP requests
import nmap            # nmap wrapper

# ---- Configuration: read API endpoints from settings.ini --------------
config = configparser.ConfigParser()       # create config reader
config.read('settings.ini')                # load ini file from cwd
NIST_URL = config['API_ENDPOINTS']['nist_url']    # NVD score endpoint (+ cveId=)
CIRCL_URL = config['API_ENDPOINTS']['circl_url']  # CIRCL description endpoint

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
def info(msg): print(f"{c('[*]', CYAN)} {msg}")   # [*] cyan   = informational
def good(msg): print(f"{c('[+]', GREEN)} {msg}")  # [+] green  = good news
def bad(msg):  print(f"{c('[-]', RED)} {msg}")    # [-] red    = problem/error


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
    if cve_id == "None":                                    # guard: no CVE to look up
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
    if cve_id == "None":                                    # guard: no CVE to look up
        return 0.0
    info(f"Fetching CVSS score for {cve_id} from NIST...")  # status line
    try:
        response = requests.get(f"{NIST_URL}{cve_id}", timeout=10)   # GET the CVE record
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
    show_banner()                                                   # clear + print banner
    print(c("=" * 52, CYAN, BOLD))                                  # title bar top
    print(c("  LIVE THREAT INTEL  |  nmap + CVE lookup", CYAN, BOLD))# tool title
    print(c("=" * 52, CYAN, BOLD))                                  # title bar bottom

    # Get target: from the command line if given, else prompt for it.
    if len(sys.argv) > 1:                       # target passed as an argument
        target = sys.argv[1]
    else:                                       # nothing passed -> ask interactively
        target = input("Target IP / hostname: ").strip()

    if not target:                              # empty input -> nothing to do
        bad("No target given. Exiting.")
        sys.exit(1)                             # exit code 1 = error

    services = scan_target(target)              # run the nmap scan

    if not services:                            # scan came back empty
        bad("No open ports found (host may be down or filtering).")
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

    # ---- Summary ------------------------------------------------------
    print()                                                        # spacer
    print(c("=" * 52, CYAN, BOLD))                                 # summary bar top
    label, color = severity(top_score)                             # bucket worst score
    print(f"  Scanned {c(str(len(services)), BOLD)} open service(s); "  # how many services
          f"{c(str(vuln_services), BOLD)} with known CVEs.")           # how many vulnerable
    print(f"  Highest severity found: {c(f'{label} ({top_score}/10)', color, BOLD)}")  # worst finding
    print(c("=" * 52, CYAN, BOLD))                                 # summary bar bottom
