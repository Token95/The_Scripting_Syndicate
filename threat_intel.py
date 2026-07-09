#!/usr/bin/env python3
import requests
import configparser

# Loading the configuration for the ini file
config = configparser.ConfigParser()
config.read('settings.ini')
CIRCL_URL = config['API_ENDPOINTS']['circl_url']
NIST_URL = config['API_ENDPOINTS']['nist_url']

# Define the script to run against and open source api for vulnerablites    
def get_cve_description(cve_id):
    """Hits the open-source CIRL API to get the human-readable description."""
    if cve_id == "None":
        return "No vulnerability identified."
    
    print(f"[*] Fetching description for {cve_id} from CIRCL...")
    try:
        response = requests.get(f"{CIRCL_URL}{cve_id}", timeout=10)
        if response.status_code == 200 and response.json():
            return response.json().get('summary', 'Description not found.')
    except Exception as e:
        print(f"[-] CIRCL_API Error: {e}")
    return "Failed to retrieve decription"

# Define the script to take an CVE and run that through an open source API to get the CVSS score and get it severaity score
def get_cvss_score(cve_id):
    """Hits the NIST NVD API to get the exact CVSS Base Score."""
    if cve_id == "None":
        return 0.0
    print(f"[*] Fetching CVSS score for {cve_id} from NIST...")
    try: 
        response = requests.get(f"{NIST_URL}{cve_id}", timeout=10)
        if response.status_code == 200:
            data =response.json()
            vuln_data = data.get("vulnerabilities", [])
            if vuln_data :
                metrics = vuln_data[0].get("cve", {}).get("metrics", {})
                # We are starting with the  CVSS v3.1 first
                if "cvssMeticV31" in metrics:
                    return metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
    except Exception as e:
        print(f"[-] NIST API Errior: {0}")
    return 0.0
      
# test run for metting tomorrow 
if __name__ == "__main__":
    print("\n" +"="*50)
    print("  LIVE THREAT INTEK API TEST")
    print("="*50)

# Try it on the VM thursday
test_cve ="CVE-2021-41773"

desc = get_cve_description(test_cve)
score = get_cvss_score(test_cve)

print("\n--- TEST RESULTS ---")
print(f"Target CVE:   {test_cve}")
print(f"Dasce Score:  {score} / 10")
print(f"Description:  {desc}\n")
