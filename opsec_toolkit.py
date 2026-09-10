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

__version__ = "2.1.0"



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
        from PIL import Image, ImageOps

        ext = path.suffix.lower()
        out_path = safe_out_path(path)
        with Image.open(path) as img:
            # Bake the EXIF orientation into the pixels, then drop the tag,
            # so "clean" doesn't silently rotate the photo.
            try:
                img = ImageOps.exif_transpose(img)
            except Exception:
                pass

            # JPEG can only hold RGB/L/CMYK - convert anything else first.
            if ext in LOSSY_IMAGE_EXTS and img.mode not in ("RGB", "L", "CMYK"):
                img = img.convert("RGB")

            # Rebuild from a fresh in-memory copy: strips info/icc profile
            # without materializing every pixel into a Python list (the old
            # list(getdata()) approach could eat ~1GB on a 12MP photo).
            clean = img.copy()
            clean.info = {}

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

        # Best-effort XMP removal. _root_object is private API - guard so a
        # future pypdf release can't break cleaning entirely.
        try:
            root = getattr(writer, "_root_object", None)
            if root is not None and "/Metadata" in root:
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



SHRED_MAX_PASSES = 15  # anything above this is wasted time (and warns)


def shred_file(path: Path, passes: int = 3) -> OpResult:
    try:
        # Never follow a symlink: overwriting would destroy the *target*
        # while the delete would only remove the link. Refuse instead.
        if path.is_symlink():
            return OpResult(False, "Refusing to shred a symlink (it points at another file).")

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
            # Wipe standards typically end with a truncate so the length
            # itself isn't a leftover hint.
            f.truncate(0)
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
    if passes > SHRED_MAX_PASSES:
        print(f"NOTE: {passes} passes is overkill - wear leveling means extra passes add no "
              f"security. Clamping to {SHRED_MAX_PASSES}.")
        passes = SHRED_MAX_PASSES

    print("INFO: on SSDs and copy-on-write filesystems (e.g. Btrfs, ZFS, APFS),")
    print("overwrite-based shredding is not guaranteed to actually destroy the data.")
    if not confirm(f"Shred and permanently delete '{p}'?"):
        return

    result = shred_file(Path(p), passes=passes)
    print(result.message if result.ok else f"ERROR: {result.message}")



# 3) DNS diagnostics


# Known public resolvers, for labeling output (not a leak test - just
# answers "whose DNS am I actually using?" at a glance).
RESOLVER_LABELS = {
    "1.1.1.1": "Cloudflare", "1.0.0.1": "Cloudflare",
    "8.8.8.8": "Google", "8.8.4.4": "Google",
    "9.9.9.9": "Quad9", "149.112.112.112": "Quad9",
    "94.140.14.14": "AdGuard", "94.140.15.15": "AdGuard",
    "208.67.222.222": "OpenDNS", "208.67.220.220": "OpenDNS",
    "185.228.168.9": "CleanBrowsing", "185.228.169.9": "CleanBrowsing",
    "76.76.19.19": "Control D", "76.223.122.150": "Control D",
    "0.0.0.0": "blocked/sinkholed",
}


def label_resolver(ip: str) -> str:
    return RESOLVER_LABELS.get(ip, "")


def _parse_resolv_conf(text: str) -> List[str]:
    resolvers: List[str] = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("nameserver"):
            parts = line.split()
            if len(parts) >= 2:
                resolvers.append(parts[1])
    return resolvers


def _windows_resolvers_powershell() -> List[str]:
    """Locale-independent DNS lookup via PowerShell; returns [] on failure."""
    try:
        out = subprocess.check_output(
            ["powershell", "-NoProfile", "-Command",
             "Get-DnsClientServerAddress -AddressFamily IPv4 | "
             "Select-Object -ExpandProperty ServerAddresses"],
            text=True, errors="ignore", timeout=10,
        )
        ip_re = re.compile(r"^\b(\d{1,3}(?:\.\d{1,3}){3})\b\s*$")
        return [m.group(1) for line in out.splitlines() if (m := ip_re.match(line.strip()))]
    except Exception:
        return []


def get_system_resolvers() -> List[str]:
    resolvers: List[str] = []
    sysname = platform.system().lower()

    if sysname in ("linux", "darwin"):
        resolv = Path("/etc/resolv.conf")
        if resolv.exists():
            resolvers += _parse_resolv_conf(resolv.read_text(errors="ignore"))

        # systemd-resolved stub: resolv.conf only lists 127.0.0.53, which
        # tells you nothing about the real upstream. Pull those too.
        stub_only = resolvers and all(r.startswith("127.") for r in resolvers)
        if stub_only:
            upstream = Path("/run/systemd/resolve/resolv.conf")
            if upstream.exists():
                extra = _parse_resolv_conf(upstream.read_text(errors="ignore"))
                if extra:
                    resolvers += extra

    elif sysname == "windows":
        # PowerShell first: locale-independent. Fall back to parsing
        # localized ipconfig output.
        resolvers = _windows_resolvers_powershell()
        if not resolvers:
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
            label = label_resolver(r)
            print(f"  - {r}" + (f"  ({label})" if label else ""))
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
    # (site, url template, reliable_without_login)
    # reliable=False: the site serves 200/login-wall pages for nonexistent
    # users, so a "FOUND" from it is not trustworthy anonymously.
    ("GitHub", "https://github.com/{}", True),
    ("GitLab", "https://gitlab.com/{}", True),
    ("Reddit", "https://www.reddit.com/user/{}", True),
    ("Twitter/X", "https://x.com/{}", False),
    ("Instagram", "https://www.instagram.com/{}/", False),
    ("Medium", "https://medium.com/@{}", True),
    ("Dev.to", "https://dev.to/{}", True),
]

# Plain browser UA: a tool-named UA gets blocked far more often, which
# turns results into UNKNOWN noise.
HTTP_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)


@dataclass
class FootprintResult:
    site: str
    url: str
    exists: Optional[bool]  # True or False or None (unknown)
    note: str
    reliable: bool = True  # False = 200 does NOT imply the user exists


def _check_site(username: str, site: str, tmpl: str, reliable: bool, timeout: float = 7.0) -> FootprintResult:
    url = tmpl.format(username)
    try:
        if requests:
            # One session per request: requests.Session is NOT thread-safe,
            # and with only ~7 requests the per-request cost is negligible.
            with requests.Session() as session:
                r = session.get(
                    url, timeout=timeout, allow_redirects=True,
                    headers={"User-Agent": HTTP_UA},
                )
            code, final_url = r.status_code, r.url
        else:
            import urllib.request

            req = urllib.request.Request(url, headers={"User-Agent": HTTP_UA})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                code, final_url = getattr(resp, "status", 200), url

        if code == 200:
            note = f"200 OK ({final_url})"
            if not reliable:
                note += " [unreliable anonymously: site may 200 for any name]"
            return FootprintResult(site, url, True, note, reliable)
        if code == 404:
            return FootprintResult(site, url, False, "404 Not Found", reliable)
        if code in (401, 403, 429):
            return FootprintResult(site, url, None, f"{code} Blocked/Rate-limited", reliable)
        return FootprintResult(site, url, None, f"{code} Unknown", reliable)
    except Exception as e:
        return FootprintResult(site, url, None, f"Error/Blocked: {e}", reliable)


def footprint_check(username: str, max_workers: int = 5, timeout: float = 7.0) -> List[FootprintResult]:
    """Check a username against SITE_TEMPLATES concurrently.

    max_workers is kept modest by default (5) - this is a small, fixed list
    of sites, so there's no real speed reason to hammer them all at once,
    and a lower concurrency is politer to the sites being checked.
    """
    results: List[FootprintResult] = []
    with cf.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = [
            ex.submit(_check_site, username, site, tmpl, reliable, timeout)
            for site, tmpl, reliable in SITE_TEMPLATES
        ]
        for fut in cf.as_completed(futures):
            results.append(fut.result())

    order = {site: i for i, (site, _, _) in enumerate(SITE_TEMPLATES)}
    results.sort(key=lambda r: order[r.site])
    return results


def _print_footprint(results: List[FootprintResult]) -> None:
    for r in results:
        status = "FOUND" if r.exists is True else "NOT FOUND" if r.exists is False else "UNKNOWN"
        print(f"{r.site:12} {status:10} {r.url}  |  {r.note}")

    print("\nNote: UNKNOWN often means the site blocked automated checks. This is not conclusive.")
    if any(r.exists is True and not r.reliable for r in results):
        print("Warning: some FOUND results come from sites that answer 200 to anyone "
              "(login walls). Treat those as unconfirmed.")


def footprint_menu() -> None:
    hr()
    username = prompt("Enter username to check: ")
    if not username:
        print("No username provided.")
        return

    print(f"Checking footprint for: {username}")
    hr()
    _print_footprint(footprint_check(username))



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


def port_service_name(port: int) -> str:
    """Best-effort IANA service name for a port ('' if unknown)."""
    try:
        return socket.getservbyport(port)
    except (OSError, OverflowError):
        return ""


def format_open_ports(open_ports: Sequence[int]) -> str:
    parts = []
    for p in open_ports:
        svc = port_service_name(p)
        parts.append(f"{p} ({svc})" if svc else str(p))
    return ", ".join(parts)


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
        print(format_open_ports(open_ports))
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


def parse_port_list(spec: str) -> List[int]:
    """Parse '22,80,443' (commas, optional spaces) into a sorted port list."""
    ports: List[int] = []
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if not chunk.isdigit():
            raise argparse.ArgumentTypeError(f"invalid port: {chunk!r}")
        p = int(chunk)
        if not (1 <= p <= 65535):
            raise argparse.ArgumentTypeError(f"port out of range 1-65535: {p}")
        ports.append(p)
    if not ports:
        raise argparse.ArgumentTypeError("empty port list")
    return sorted(set(ports))


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
    fp_p.add_argument("-t", "--timeout", type=float, default=7.0, help="Per-site timeout in seconds (default 7)")

    scan_p = sub.add_parser("scan", help="Scan TCP ports on a host")
    scan_p.add_argument("--host", default="127.0.0.1")
    scan_p.add_argument("--range", type=parse_port_range, dest="ports_range",
                          help="Port range as START-END, e.g. 1-1024 (default: common ports)")
    scan_p.add_argument("--ports", type=parse_port_list, dest="ports_list",
                          help="Explicit port list, e.g. 22,80,443 (overrides --range)")
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
        passes = max(1, args.passes)
        if passes > SHRED_MAX_PASSES:
            print(f"NOTE: {passes} passes is overkill on modern storage; clamping to {SHRED_MAX_PASSES}.")
            passes = SHRED_MAX_PASSES
        result = shred_file(Path(args.file), passes=passes)
        print(result.message if result.ok else f"ERROR: {result.message}")
        return 0 if result.ok else 1

    if args.command == "dns":
        dns_diagnostics_menu()
        return 0

    if args.command == "footprint":
        print(f"Checking footprint for: {args.username}")
        hr()
        _print_footprint(
            footprint_check(
                args.username,
                max_workers=max(1, args.workers),
                timeout=max(1.0, args.timeout),
            )
        )
        return 0

    if args.command == "scan":
        if args.ports_list:
            ports = args.ports_list
        elif args.ports_range:
            ports = args.ports_range
        else:
            ports = COMMON_PORTS
        print(f"Scanning {args.host} on {len(ports)} port(s)...")
        open_ports = scan_ports(args.host, ports, timeout=args.timeout, max_workers=args.workers)
        if open_ports:
            print("Open ports:", format_open_ports(open_ports))
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
