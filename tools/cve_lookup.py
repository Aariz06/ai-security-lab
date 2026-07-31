import sys
import requests
import os
import time

API_KEY = os.environ.get("NVD_API_KEY")
API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
TIMEOUT = 20

def main():
    if len(sys.argv) < 2:
        print("Usage: python cve_lookup.py CVE-2021-44228 [CVE-...]")
        sys.exit(1)

    for cve_id in sys.argv[1:]:
        try:
            cve = fetch(cve_id)
            if cve is None:
                print(f"{cve_id}: not found")
            else:
                report(cve)
        except requests.HTTPError as e:
            print(f"{cve_id}: HTTP error — {e}")
        except requests.RequestException as e:
            print(f"{cve_id}: network error — {e}")

# Fetches the CVE record
def fetch(cve_id, retries=3):
    headers = {"apiKey": API_KEY} if API_KEY else {}
    for attempt in range(retries):
        r = requests.get(
            API,
            params={"cveId": cve_id},
            headers=headers,
            timeout=TIMEOUT,
        )
        if r.status_code in (429, 503):      # busy / throttled — wait, retry
            time.sleep(6 * (attempt + 1))     # 6s, then 12s, then 18s
            continue
        r.raise_for_status()                 # any other bad status: raise
        items = r.json().get("vulnerabilities", [])
        return items[0]["cve"] if items else None
    r.raise_for_status()                     # out of retries — surface it
    return None

# Chooses the newest CVSS version
def best_cvss(metrics):
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            data = metrics[key][0]["cvssData"]
            return (
                data.get("baseScore"),
                data.get("baseSeverity", "UNKNOWN"),
                data.get("vectorString", ""),
                key.replace("cvssMetric", "CVSS "),
            )
    return None, "UNKNOWN", "", "none"

# Prints the CVE information
def report(cve):
    cve_id = cve["id"]
    desc = next(
        (d["value"] for d in cve["descriptions"] if d["lang"] == "en"),
        "No description",
    )
    score, severity, vector, version = best_cvss(cve.get("metrics", {}))

    print("=" * 62)
    print(f"{cve_id}   [{cve.get('vulnStatus', 'unknown')}]")
    print("=" * 62)
    print(f"Severity : {severity}  (score {score}, {version})")
    print(f"Vector   : {vector}")
    print(f"Published: {cve.get('published', '')[:10]}")
    print(f"\nDescription:\n{desc}\n")

    refs = cve.get("references", [])[:5]
    if refs:
        print("References:")
        for ref in refs:
            print(f"  - {ref['url']}")

    if score is not None and score >= 9.0:
        print("\n** CRITICAL — treat as emergency patching **")
    elif score is not None and score >= 7.0:
        print("\n** HIGH — patch inside normal SLA **")

if __name__ == "__main__":
    main()