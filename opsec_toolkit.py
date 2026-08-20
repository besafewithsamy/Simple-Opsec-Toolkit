#!/usr/bin/env python3
"""
OPSEC Toolkit
Made by Sami Salhi

A lightweight toolkit for everyday operational security tasks:
metadata cleaning, secure-ish file shredding, DNS resolver diagnostics,
username footprint checks, and a local TCP port scanner.

Usage:
    python opsec_toolkit.py                    # interactive menu (original behavior)
    python opsec_toolkit.py clean FILE          # clean metadata from a file
    python opsec_toolkit.py shred FILE [-p N] [-y]
    python opsec_toolkit.py dns
    python opsec_toolkit.py footprint USERNAME [-w N]
    python opsec_toolkit.py scan [--host HOST] [--range START-END] [-w N] [-t SECONDS]
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import os
import platform
import random
import re
import socket
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

__version__ = "2.0.0"



def hr(char: str = "-", n: int = 60) -> None:
    print(char * n)


def clear_screen() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def prompt(msg: str) -> str:
    return input(msg).strip()


def confirm(msg: str, default: bool = False) -> bool:
    hint = "Y/n" if default else "y/N"
    ans = input(f"{msg} [{hint}]: ").strip().lower()
    if not ans:
        return default
    return ans in ("y", "yes")


def is_file(path: str) -> bool:
    return Path(path).is_file()


def safe_out_path(in_path: Path, prefix: str = "clean_") -> Path:
    """Return a non-colliding output path so we never silently overwrite
    a previous run's cleaned file."""
    out = in_path.with_name(prefix + in_path.name)
    counter = 1
    while out.exists():
        out = in_path.with_name(f"{prefix}{in_path.stem}_{counter}{in_path.suffix}")
        counter += 1
    return out


def try_import(name: str):
    try:
        return __import__(name)
    except Exception:
        return None


PIL = try_import("PIL")
piexif = try_import("piexif")
pypdf = try_import("pypdf")
docx_mod = try_import("docx")
requests = try_import("requests")

IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".webp", ".tif", ".tiff"}
LOSSY_IMAGE_EXTS = {".jpg", ".jpeg"}
PDF_EXTS = {".pdf"}
DOCX_EXTS = {".docx"}


@dataclass
class OpResult:
    ok: bool
    message: str
    output: Optional[Path] = None

#  metadata cleaner
 


def clean_image_metadata(path: Path) -> OpResult:
    if not PIL:
        return OpResult(False, "Pillow is not installed. Install: pip install pillow")

    try:
        from PIL import Image

        ext = path.suffix.lower()
        out_path = safe_out_path(path)
        img = Image.open(path)

        if img.mode in ("P", "RGBA") and ext in LOSSY_IMAGE_EXTS:
            img = img.convert("RGB")

        data = list(img.getdata())
        clean = Image.new(img.mode, img.size)
        clean.putdata(data)

        save_kwargs = {}
        if ext in LOSSY_IMAGE_EXTS:
            save_kwargs["quality"] = 95
            save_kwargs["optimize"] = True
        elif ext == ".png":
            save_kwargs["optimize"] = True

        clean.save(out_path, **save_kwargs)

        if piexif and ext in LOSSY_IMAGE_EXTS:
            try:
                piexif.remove(str(out_path))
            except Exception:
                pass

        return OpResult(True, "Image metadata cleaned.", out_path)
    except Exception as e:
        return OpResult(False, f"Cleaning image failed: {e}")


def clean_pdf_metadata(path: Path) -> OpResult:
    if not pypdf:
        return OpResult(False, "pypdf is not installed. Install: pip install pypdf")

    try:
        from pypdf import PdfReader, PdfWriter

        reader = PdfReader(str(path))
        writer = PdfWriter()
        for page in reader.pages:
            writer.add_page(page)

        writer.add_metadata({})

      
        try:
            root = writer._root_object
            if "/Metadata" in root:
                del root["/Metadata"]
        except Exception:
            pass

        out_path = safe_out_path(path)
        with open(out_path, "wb") as f:
            writer.write(f)

        return OpResult(True, "PDF metadata cleaned (incl. XMP, if present).", out_path)
    except Exception as e:
        return OpResult(False, f"Cleaning PDF failed: {e}")


def clean_docx_metadata(path: Path) -> OpResult:
    if not docx_mod:
        return OpResult(False, "python-docx is not installed. Install: pip install python-docx")

    try:
        import docx

        doc = docx.Document(str(path))
        props = doc.core_properties

        for field in (
            "author", "last_modified_by", "title", "subject", "keywords",
            "comments", "category", "content_status", "identifier",
            "language", "version",
        ):
            try:
                setattr(props, field, "")
            except Exception:
                pass

        out_path = safe_out_path(path)
        doc.save(str(out_path))

        return OpResult(
            True,
            "DOCX core properties cleaned. Note: this does not strip "
            "revision/rsid tracking data embedded in the XML - for that, "
            "re-save via 'Save As' in Word/LibreOffice first.",
            out_path,
        )
    except Exception as e:
        return OpResult(False, f"Cleaning DOCX failed: {e}")


def clean_metadata(path: Path) -> OpResult:
    ext = path.suffix.lower()
    if ext in IMAGE_EXTS:
        return clean_image_metadata(path)
    if ext in PDF_EXTS:
        return clean_pdf_metadata(path)
    if ext in DOCX_EXTS:
        return clean_docx_metadata(path)
    return OpResult(False, f"Unsupported file extension: {ext} (supported: image, pdf, docx)")


def metadata_cleaner_menu() -> None:
    hr()
    p = prompt("Enter path to the file (image/pdf/docx): ")
    if not is_file(p):
        print("File not found, please check the path.")
        return

    result = clean_metadata(Path(p))
    print(result.message)
    if result.ok and result.output:
        print(f"Output: {result.output}")



# 2) shredder



def shred_file(path: Path, passes: int = 3) -> OpResult:
    try:
        size = path.stat().st_size
        if size == 0:
            path.unlink()
            return OpResult(True, "File was empty; deleted.")

        try:
            os.chmod(path, 0o600)
        except Exception:
            pass

        with open(path, "r+b", buffering=0) as f:
            for _ in range(passes):
                f.seek(0)
                f.write(os.urandom(size))
                f.flush()
                os.fsync(f.fileno())

        rnd_name = path.with_name(
            "." + "".join(random.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(12))
        )
        try:
            path.rename(rnd_name)
            rnd_name.unlink()
        except Exception:
            path.unlink()

        return OpResult(True, f"Shredded with {passes} pass(es) and deleted.")
    except Exception as e:
        return OpResult(False, f"Shred failed: {e}")


def shredder_menu() -> None:
    hr()
    p = prompt("Enter path to file to shred: ")
    if not is_file(p):
        print("File not found.")
        return

    passes_str = prompt("Overwrite passes (default 3): ")
    passes = 3
    if passes_str:
        try:
            passes = max(1, int(passes_str))
        except Exception:
            print("Invalid number. Using default 3.")

    print("INFO: on SSDs and copy-on-write filesystems (e.g. Btrfs, ZFS, APFS),")
    print("overwrite-based shredding is not guaranteed to actually destroy the data.")
    if not confirm(f"Shred and permanently delete '{p}'?"):
        return

    result = shred_file(Path(p), passes=passes)
    print(result.message if result.ok else f"ERROR: {result.message}")



# 3) DNS diagnostics


def get_system_resolvers() -> List[str]:
    resolvers: List[str] = []
    sysname = platform.system().lower()

    if sysname in ("linux", "darwin"):
        resolv = Path("/etc/resolv.conf")
        if resolv.exists():
            for line in resolv.read_text(errors="ignore").splitlines():
                line = line.strip()
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) >= 2:
                        resolvers.append(parts[1])

    elif sysname == "windows":
      
        try:
            out = subprocess.check_output(["ipconfig", "/all"], text=True, errors="ignore")
            ip_re = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
            in_dns_block = False
            for line in out.splitlines():
                if "DNS Servers" in line:
                    in_dns_block = True
                elif line.strip() and not line.startswith((" ", "\t")):
                    in_dns_block = False

                if in_dns_block:
                    m = ip_re.search(line)
                    if m:
                        resolvers.append(m.group(1))
        except Exception:
            pass

    return list(dict.fromkeys(resolvers))


def resolve_test(domains: Sequence[str]) -> List[Tuple[str, Optional[str], Optional[str]]]:
    results = []
    for d in domains:
        try:
            ip = socket.gethostbyname(d)
            results.append((d, ip, None))
        except Exception as e:
            results.append((d, None, str(e)))
    return results


def dns_diagnostics_menu() -> None:
    hr()
    print("DNS diagnostics (this is not a DNS leak test - no packet capture)")

    resolvers = get_system_resolvers()
    if resolvers:
        print("System-configured DNS resolvers:")
        for r in resolvers:
            print(f"  - {r}")
    else:
        print("Could not reliably parse system resolvers.")

    print()
    domains = ["example.com", "cloudflare.com", "google.com"]
    print("Testing resolution via system resolver path:")
    for d, ip, err in resolve_test(domains):
        print(f"  {d}: ERROR {err}" if err else f"  {d}: {ip}")

    print("\nIf you're using a VPN, compare the resolver IPs above with your expected VPN DNS servers.")
    print("This cannot confirm 'no DNS leak' on its own.")



# 4) username footprint checker (now concurrent)


SITE_TEMPLATES = [
    ("GitHub", "https://github.com/{}"),
    ("GitLab", "https://gitlab.com/{}"),
    ("Reddit", "https://www.reddit.com/user/{}"),
    ("Twitter/X", "https://x.com/{}"),
    ("Instagram", "https://www.instagram.com/{}/"),
    ("Medium", "https://medium.com/@{}"),
    ("Dev.to", "https://dev.to/{}"),
]


@dataclass
class FootprintResult:
    site: str
    url: str
    exists: Optional[bool]  # True or False or None (unknown)
    note: str


def _check_site(session, username: str, site: str, tmpl: str, timeout: int = 7) -> FootprintResult:
    url = tmpl.format(username)
    try:
        if session is not None:
            r = session.get(
                url, timeout=timeout, allow_redirects=True,
                headers={"User-Agent": "opsec-toolkit/2.0"},
            )
            code, final_url = r.status_code, r.url
        else:
            import urllib.request

            req = urllib.request.Request(url, headers={"User-Agent": "opsec-toolkit/2.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                code, final_url = getattr(resp, "status", 200), url

        if code == 200:
            return FootprintResult(site, url, True, f"200 OK ({final_url})")
        if code == 404:
            return FootprintResult(site, url, False, "404 Not Found")
        if code in (401, 403, 429):
            return FootprintResult(site, url, None, f"{code} Blocked/Rate-limited")
        return FootprintResult(site, url, None, f"{code} Unknown")
    except Exception as e:
        return FootprintResult(site, url, None, f"Error/Blocked: {e}")


def footprint_check(username: str, max_workers: int = 5) -> List[FootprintResult]:
    """Check a username against SITE_TEMPLATES concurrently.

    max_workers is kept modest by default (5) - this is a small, fixed list
    of sites, so there's no real speed reason to hammer them all at once,
    and a lower concurrency is politer to the sites being checked.
    """
    session = requests.Session() if requests else None
    results: List[FootprintResult] = []
    with cf.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = [ex.submit(_check_site, session, username, site, tmpl) for site, tmpl in SITE_TEMPLATES]
        for fut in cf.as_completed(futures):
            results.append(fut.result())

    order = {site: i for i, (site, _) in enumerate(SITE_TEMPLATES)}
    results.sort(key=lambda r: order[r.site])
    return results


def footprint_menu() -> None:
    hr()
    username = prompt("Enter username to check: ")
    if not username:
        print("No username provided.")
        return

    print(f"Checking footprint for: {username}")
    hr()

    for r in footprint_check(username):
        status = "FOUND" if r.exists is True else "NOT FOUND" if r.exists is False else "UNKNOWN"
        print(f"{r.site:12} {status:10} {r.url}  |  {r.note}")

    print("\nNote: UNKNOWN often means the site blocked automated checks. This is not conclusive.")



# 5) local port scanner (now concurrent)


COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 587, 631, 8080, 8443, 3306, 5432, 6379, 27017]


def scan_port(host: str, port: int, timeout: float = 0.4) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((host, port)) == 0
    except Exception:
        return False


def scan_ports(host: str, ports: Sequence[int], timeout: float = 0.4, max_workers: int = 100) -> List[int]:
    open_ports: List[int] = []
    workers = max(1, min(max_workers, len(ports)))
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(scan_port, host, p, timeout): p for p in ports}
        for fut in cf.as_completed(futures):
            p = futures[fut]
            try:
                if fut.result():
                    open_ports.append(p)
            except Exception:
                pass
    return sorted(open_ports)


def local_scan_menu() -> None:
    hr()
    host = prompt("Host to scan (default 127.0.0.1): ") or "127.0.0.1"
    mode = prompt("Scan mode: 1) common ports  2) custom range  (default 1): ") or "1"

    ports: List[int] = COMMON_PORTS
    if mode.strip() == "2":
        start = prompt("Start port (e.g., 1): ")
        end = prompt("End port (e.g., 1024): ")
        try:
            a, b = int(start), int(end)
            if a < 1 or b > 65535 or a > b:
                raise ValueError
            ports = list(range(a, b + 1))
        except Exception:
            print("Invalid range. Using common ports.")
            ports = COMMON_PORTS

    timeout_s = prompt("Timeout per port in seconds (default 0.4): ") or "0.4"
    try:
        timeout = float(timeout_s)
        if timeout <= 0:
            raise ValueError
    except Exception:
        timeout = 0.4

    print(f"\nScanning {host} on {len(ports)} port(s)...")
    open_ports = scan_ports(host, ports, timeout=timeout)

    hr()
    if open_ports:
        print("Open ports:")
        print(", ".join(map(str, open_ports)))
    else:
        print("No open ports found (or filtered).")



MENU = {
    "1": ("Metadata cleaner (image/pdf/docx)", metadata_cleaner_menu),
    "2": ("Shred file (overwrite + delete)", shredder_menu),
    "3": ("DNS diagnostics (not a definitive leak test)", dns_diagnostics_menu),
    "4": ("Username checker across platforms", footprint_menu),
    "5": ("Simple local port scan", local_scan_menu),
    "0": ("Exit", None),
}


def show_deps() -> None:
    print("Dependency status:")
    print(f"  pillow:      {'OK' if PIL else 'missing'}")
    print(f"  piexif:      {'OK' if piexif else 'missing'}")
    print(f"  pypdf:       {'OK' if pypdf else 'missing'}")
    print(f"  python-docx: {'OK' if docx_mod else 'missing'}")
    print(f"  requests:    {'OK' if requests else 'missing'}")
    print("Install missing ones with: pip install -r requirements.txt")


def run_menu() -> None:
    clear_screen()
    print(f"OPSEC Toolkit v{__version__}")
    print("Made by Sami Salhi")
    show_deps()

    while True:
        hr()
        for k in sorted(MENU.keys(), key=lambda x: int(x) if x.isdigit() else 999):
            print(f"{k}. {MENU[k][0]}")
        hr()

        choice = prompt("Please choose an option: ")
        if choice == "0":
            print("Bye <3.")
            break

        if choice in MENU:
            fn = MENU[choice][1]
            if fn:
                fn()
                input("\nPress Enter to return to menu...")
                clear_screen()
        else:
            print("Invalid choice.")


def parse_port_range(spec: str) -> List[int]:
    m = re.fullmatch(r"(\d+)-(\d+)", spec.strip())
    if not m:
        raise argparse.ArgumentTypeError("range must look like START-END, e.g. 1-1024")
    a, b = int(m.group(1)), int(m.group(2))
    if a < 1 or b > 65535 or a > b:
        raise argparse.ArgumentTypeError("range must satisfy 1 <= START <= END <= 65535")
    return list(range(a, b + 1))


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="opsec_toolkit.py",
        description="OPSEC Toolkit - metadata cleaning, shredding, DNS diagnostics, "
                     "username footprint checks, local port scanning.",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command")

    clean_p = sub.add_parser("clean", help="Strip metadata from an image/pdf/docx file")
    clean_p.add_argument("file", help="Path to the file")

    shred_p = sub.add_parser("shred", help="Overwrite and delete a file")
    shred_p.add_argument("file", help="Path to the file")
    shred_p.add_argument("-p", "--passes", type=int, default=3, help="Overwrite passes (default 3)")
    shred_p.add_argument("-y", "--yes", action="store_true", help="Skip confirmation prompt")

    sub.add_parser("dns", help="Show DNS resolver diagnostics")

    fp_p = sub.add_parser("footprint", help="Check a username across common platforms")
    fp_p.add_argument("username")
    fp_p.add_argument("-w", "--workers", type=int, default=5, help="Concurrent requests (default 5)")

    scan_p = sub.add_parser("scan", help="Scan TCP ports on a host")
    scan_p.add_argument("--host", default="127.0.0.1")
    scan_p.add_argument("--range", type=parse_port_range, dest="ports",
                         help="Port range as START-END, e.g. 1-1024 (default: common ports)")
    scan_p.add_argument("-w", "--workers", type=int, default=100, help="Concurrent connections (default 100)")
    scan_p.add_argument("-t", "--timeout", type=float, default=0.4, help="Per-port timeout in seconds")

    return p


def run_cli(args: argparse.Namespace) -> int:
    if args.command == "clean":
        if not is_file(args.file):
            print("File not found.")
            return 1
        result = clean_metadata(Path(args.file))
        print(result.message)
        if result.ok and result.output:
            print(f"Output: {result.output}")
        return 0 if result.ok else 1

    if args.command == "shred":
        if not is_file(args.file):
            print("File not found.")
            return 1
        if not args.yes and not confirm(f"Shred and permanently delete '{args.file}'?"):
            print("Aborted.")
            return 1
        result = shred_file(Path(args.file), passes=max(1, args.passes))
        print(result.message if result.ok else f"ERROR: {result.message}")
        return 0 if result.ok else 1

    if args.command == "dns":
        dns_diagnostics_menu()
        return 0

    if args.command == "footprint":
        print(f"Checking footprint for: {args.username}")
        hr()
        for r in footprint_check(args.username, max_workers=max(1, args.workers)):
            status = "FOUND" if r.exists is True else "NOT FOUND" if r.exists is False else "UNKNOWN"
            print(f"{r.site:12} {status:10} {r.url}  |  {r.note}")
        return 0

    if args.command == "scan":
        ports = args.ports or COMMON_PORTS
        print(f"Scanning {args.host} on {len(ports)} port(s)...")
        open_ports = scan_ports(args.host, ports, timeout=args.timeout, max_workers=args.workers)
        if open_ports:
            print("Open ports:", ", ".join(map(str, open_ports)))
        else:
            print("No open ports found (or filtered).")
        return 0

    return 1


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()

    if args.command is None:
        run_menu()
        return

    sys.exit(run_cli(args))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted.")
