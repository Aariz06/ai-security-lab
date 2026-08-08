# seclab

A small security toolkit I wrote while learning Python for security work.

## Install
```bash
python -m venv venv
source venv/bin/activate      # Windows: .\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Usage

### Analyse an SSH auth log
```bash
python seclab.py logs sample_auth.log --threshold 5
```
Reports failed logins per source IP, flags likely brute force, and alerts on any
IP that has both failures and a success, which suggests a *successful*
brute force.

### Look up CVEs
```bash
python seclab.py cve CVE-2021-44228 CVE-2014-0160
```
Queries NVD API 2.0. Prefers CVSS v3.1, falls back to v3.0 then v2.

## Notes
- NVD rate limit without an API key is 5 requests / 30s
- Sample log data is synthetic; no real host data is committed