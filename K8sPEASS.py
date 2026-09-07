#!/usr/bin/env python3
"""Kubernetes Privilege Escalation Awesome Script Suite."""

from __future__ import annotations

import argparse
import os
import sys

from colorama import Fore

from src.k8s import K8sPEASS


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run K8sPEASS to enumerate the current Kubernetes identity and its "
            "permissions without changing resources or using exec-like actions."
        )
    )
    parser.add_argument("--kubeconfig", help="Kubeconfig path; uses kubectl defaults otherwise")
    parser.add_argument("--context", help="Kubeconfig context; uses current-context otherwise")
    parser.add_argument("--server", help="Kubernetes API server URL")
    parser.add_argument(
        "--token",
        default=os.getenv("K8S_TOKEN"),
        help="Bearer token; prefer the K8S_TOKEN environment variable",
    )
    parser.add_argument("--certificate-authority", help="CA certificate path")
    parser.add_argument("--client-certificate", help="Client certificate path")
    parser.add_argument("--client-key", help="Client private-key path")
    parser.add_argument(
        "--as",
        dest="impersonate_user",
        help="Explicitly enumerate another identity (requires impersonate permission)",
    )
    parser.add_argument(
        "--as-group",
        action="append",
        dest="impersonate_groups",
        default=[],
        help="Group for --as; repeatable",
    )
    parser.add_argument(
        "--insecure-skip-tls-verify",
        action="store_true",
        help="Skip server certificate verification (unsafe)",
    )
    parser.add_argument(
        "--namespace",
        action="append",
        dest="namespaces",
        default=[],
        help="Additional namespace name to review; repeatable",
    )
    parser.add_argument("--threads", type=int, default=5, help="Concurrent review requests")
    parser.add_argument("--timeout", type=int, default=15, help="Per-request timeout in seconds")
    parser.add_argument(
        "--retries",
        type=int,
        default=2,
        help="Retries for throttling and temporary API/network failures (0-5)",
    )
    brute = parser.add_mutually_exclusive_group()
    brute.add_argument(
        "--brute-force-permissions",
        action="store_true",
        help="Run exhaustive SSAR checks without asking (slow and audit noisy)",
    )
    brute.add_argument(
        "--skip-bruteforce",
        action="store_true",
        help="Never ask about or run exhaustive permission checks",
    )
    parser.add_argument(
        "--no-ask",
        action="store_true",
        help="Do not prompt; safely skip slow work unless explicitly enabled",
    )
    parser.add_argument(
        "--show-all",
        action="store_true",
        help="Print low-risk and all repeated findings",
    )
    parser.add_argument("--out-json-path", help="Write the complete JSON report here")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if bool(args.client_certificate) != bool(args.client_key):
        parser.error("--client-certificate and --client-key must be supplied together")
    if args.token and args.client_certificate:
        parser.error("choose either bearer-token or client-certificate authentication")
    if args.impersonate_groups and not args.impersonate_user:
        parser.error("--as-group requires --as")
    scanner = None
    try:
        scanner = K8sPEASS(
            kubeconfig=args.kubeconfig,
            context=args.context,
            server=args.server,
            token=args.token,
            certificate_authority=args.certificate_authority,
            client_certificate=args.client_certificate,
            client_key=args.client_key,
            impersonate_user=args.impersonate_user,
            impersonate_groups=args.impersonate_groups,
            insecure_skip_tls_verify=args.insecure_skip_tls_verify,
            namespaces=args.namespaces,
            threads=args.threads,
            timeout=args.timeout,
            retries=args.retries,
            brute_force_permissions=args.brute_force_permissions,
            skip_bruteforce=args.skip_bruteforce,
            no_ask=args.no_ask,
            show_all=args.show_all,
            out_path=args.out_json_path,
        )
        scanner.run_analysis()
    except KeyboardInterrupt:
        print(f"{Fore.YELLOW}Interrupted. No Kubernetes resources were changed.")
        return 130
    except Exception as exc:
        print(f"{Fore.RED}K8sPEASS failed safely: {exc}")
        return 1
    finally:
        if scanner is not None:
            scanner.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
