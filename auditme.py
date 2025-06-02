import argparse
from modules.base_audit import run_audits

def main():
    parser = argparse.ArgumentParser(description="AuditMe: Basic Security Auditing Tool")
    parser.add_argument(
        '--module',
        type=str,
        default='base',
        help='Name of the audit module to run (default: base)'
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    args = parser.parse_args()

    print(f"[+] Runnit audit module: {args.module}")
    results = run_audits(module_name=args.module, verbose=args.verbose)
    print("\n== Audit Results ===")
    for check, result in results.items():
        status = "PASS" if result['passed'] else "FAIL"
        print(f"{check}: {status}")
        if args.verbose:
            print(f" Details: {result['details']}")

if __name__ == "__main__":
    main()