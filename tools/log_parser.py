# Parses SSH auth logs and report failed login attempts per source IP

import re
import sys
from collections import defaultdict

FAILED = re.compile(r"Failed password for (?:invalid user )?(?P<user>.\S+) from (?P<ip>\d+.\d+.\d+.\d+)")
ACCEPTED = re.compile(r"Accepted \S+ for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)")
BRUTE_FORCE_THRESHOLD = 3

def main():
    if len(sys.argv) != 2:
        print("Usage: python log_parser.py <path-to-auth.log>")
        sys.exit(1)
    try:
        report(*parse(sys.argv[1]))
    except FileNotFoundError:
        print(f"File not found: {sys.argv[1]}")
        sys.exit(1)
    

# Reads the log and counts all the failed logins, accepted logins, and the total number of lines parsed
def parse(path):
    failed = defaultdict(list)
    accepted = defaultdict(list)
    total = 0

    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            total += 1
            m = FAILED.search(line)
            if m:
                failed[m.group("ip")].append(m.group("user"))
                continue
            m = ACCEPTED.search(line)
            if m:
                accepted[m.group("ip")].append(m.group("user"))

    return failed, accepted, total

# Reports the results of parsing the log
def report(failed, accepted, total):
    print(f"Lines read: {total}")
    print(f"Unique IPs with failures: {len(failed)}\n")

    print("FAILED LOGINS BY SOURCE IP")
    print("-" * 58)
    for ip, users in sorted(failed.items(), key=lambda kv: len(kv[1]), reverse=True):
        flag = "  <-- possible brute force" if len(users) >= BRUTE_FORCE_THRESHOLD else ""
        print(f"{ip:<18} {len(users):>4} attempts{flag}")
        print(f"{'':18} users tried: {', '.join(sorted(set(users)))}")

    if accepted:
        print("\nSUCCESSFUL LOGINS")
        print("-" * 58)
        for ip, users in accepted.items():
            print(f"{ip:<18} {', '.join(sorted(set(users)))}")


    # Detects if there is a potential sucessful brute force attack
    both = set(failed) & set(accepted)
    if both:
        print("\n** ALERT: IPs with failures AND a success — possible successful brute force **")
        for ip in both:
            print(f"   {ip}")

if __name__ == "__main__":
    main()