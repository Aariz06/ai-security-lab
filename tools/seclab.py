import argparse
import sys
import log_parser
import cve_lookup


def main():
    args = build_parser().parse_args()
    try:
        args.func(args)
    except KeyboardInterrupt:
        sys.exit(130)

# Calls log_parser fucntions
def cmd_logs(args):
    failed, accepted, total = log_parser.parse(args.path)
    log_parser.BRUTE_FORCE_THRESHOLD = args.threshold
    log_parser.report(failed, accepted, total)

# Calls cve_loockup functions
def cmd_cve(args):
    for cve_id in args.cve_ids:
        cve = cve_lookup.fetch(cve_id)
        if cve is None:
            print(f"{cve_id}: not found")
        else:
            cve_lookup.report(cve)

# 
def build_parser():
    p = argparse.ArgumentParser(
        prog="seclab",
        description="Security toolkit: log analysis and CVE lookup.",
        epilog="Example: python seclab.py logs sample_auth.log --threshold 5",
    )
    subs = p.add_subparsers(dest="command", required=True)

    logs = subs.add_parser("logs", help="Analyse an SSH auth log")
    logs.add_argument("path", help="Path to the auth log")
    logs.add_argument("--threshold", type=int, default=3,
                      help="Failures before flagging brute force (default: 3)")
    logs.set_defaults(func=cmd_logs)

    cve = subs.add_parser("cve", help="Look up CVEs in the NVD")
    cve.add_argument("cve_ids", nargs="+", help="One or more CVE IDs")
    cve.set_defaults(func=cmd_cve)

    return p


if __name__ == "__main__":
    main()
