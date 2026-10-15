"""
aegis/cli.py
============
Unified CLI entrypoint — python -m aegis <command>
"""

import argparse
import sys

# Windows console defaults to CP1252; force UTF-8 so box-drawing chars render.
if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def _cmd_cyclic(args: argparse.Namespace) -> None:
    from aegis.core.cyclic import find_offset, generate, cyclic_metainfo

    if args.find is not None:
        crash = int(args.find, 16) if args.find.startswith("0x") else int(args.find, 16)
        offset = find_offset(crash, arch=args.arch)
        if offset is None:
            print(f"[!] Pattern not found for 0x{crash:X}  (arch={args.arch})")
        else:
            print(f"[+] Offset: {offset}  (0x{offset:X})")
    else:
        pat  = generate(args.length)
        info = cyclic_metainfo(args.length)
        print(pat.decode())
        print(
            f"\n[*] {info['length']} bytes | "
            f"{info['unique_windows']} unique 4-byte windows | "
            f"{info['coverage_pct']}% De Bruijn coverage",
            file=sys.stderr,
        )


def _cmd_checksec(args: argparse.Namespace) -> None:
    from aegis.core.checksec import inspect, format_report

    try:
        result = inspect(args.binary)
    except FileNotFoundError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        sys.exit(1)
    except ValueError as exc:
        print(f"[!] Parse error: {exc}", file=sys.stderr)
        sys.exit(1)

    no_color = getattr(args, "no_color", False)
    print(format_report(result, color=not no_color))


def _cmd_scan(args: argparse.Namespace) -> None:
    from aegis.core.source_scanner import scan, format_scan_report

    try:
        results = scan(
            args.path,
            recursive=not args.no_recursive,
            min_severity=args.severity,
        )
    except FileNotFoundError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        sys.exit(1)
    except ValueError as exc:
        print(f"[!] Parse error: {exc}", file=sys.stderr)
        sys.exit(1)

    no_color = getattr(args, "no_color", False)
    no_snippet = getattr(args, "no_snippet", False)
    print(format_scan_report(results, color=not no_color, show_snippet=not no_snippet))


def _cmd_gui(args: argparse.Namespace) -> None:
    from aegis.gui import launch_studio

    try:
        launch_studio(debug=getattr(args, "debug", False))
    except Exception as exc:
        print(f"[!] Failed to launch Aegis Studio: {exc}", file=sys.stderr)
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="aegis",
        description="Aegis 2.0 — Binary Security Analysis Framework & Studio",
    )
    sub = parser.add_subparsers(dest="command")

    # ── gui ──────────────────────────────────────────────────────────────────
    gui_p = sub.add_parser("gui", help="Launch native Windows 11 Liquid Glass GUI (Aegis Studio)")
    gui_p.add_argument("--debug", action="store_true", help="Enable WebView2 developer tools")
    gui_p.set_defaults(func=_cmd_gui)

    # ── cyclic ──────────────────────────────────────────────────────────────
    cyc = sub.add_parser("cyclic", help="Generate / query De Bruijn patterns")
    cyc.add_argument("length", type=int, nargs="?", default=100,
                     help="Pattern length in bytes (default: 100)")
    cyc.add_argument("--find", metavar="HEX",
                     help="Resolve crash value to byte offset (e.g. 0x61616264)")
    cyc.add_argument("--arch", type=int, choices=[32, 64], default=32,
                     help="Target architecture (default: 32)")
    cyc.set_defaults(func=_cmd_cyclic)

    # ── checksec ─────────────────────────────────────────────────────────────
    sec = sub.add_parser("checksec", help="Inspect binary mitigations (PE / ELF)")
    sec.add_argument("binary", help="Path to PE or ELF binary")
    sec.add_argument("--no-color", action="store_true",
                     help="Disable ANSI colour output")
    sec.set_defaults(func=_cmd_checksec)

    # ── scan ─────────────────────────────────────────────────────────────────
    scn = sub.add_parser("scan", help="Static source vulnerability scan (C / C++)")
    scn.add_argument("path", help="C/C++ source file or directory")
    scn.add_argument("--severity", choices=["critical", "high", "medium", "low", "info"],
                     default="info", help="Minimum severity threshold (default: info)")
    scn.add_argument("--no-recursive", action="store_true",
                     help="Do not scan subdirectories recursively")
    scn.add_argument("--no-color", action="store_true",
                     help="Disable ANSI colour output")
    scn.add_argument("--no-snippet", action="store_true",
                     help="Omit code snippet previews")
    scn.set_defaults(func=_cmd_scan)

    if len(sys.argv) == 1:
        # Default without subcommands: launch Aegis Studio GUI
        _cmd_gui(argparse.Namespace(debug=False))
        return

    args = parser.parse_args()
    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
