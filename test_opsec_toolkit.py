"""
Unit tests for opsec_toolkit.py

Run with: pytest test_opsec_toolkit.py -v

"""
import socket
import threading
from pathlib import Path

import pytest

import opsec_toolkit as tk


 
# safe_out_path
 

def test_safe_out_path_basic(tmp_path):
    src = tmp_path / "photo.jpg"
    src.write_bytes(b"x")
    out = tk.safe_out_path(src)
    assert out.name == "clean_photo.jpg"


def test_safe_out_path_avoids_collision(tmp_path):
    src = tmp_path / "photo.jpg"
    src.write_bytes(b"x")
    (tmp_path / "clean_photo.jpg").write_bytes(b"already here")

    out = tk.safe_out_path(src)
    assert out.name != "clean_photo.jpg"
    assert not out.exists()


 
# shred_file
 

def test_shred_file_removes_file(tmp_path):
    f = tmp_path / "secret.txt"
    f.write_bytes(b"sensitive data" * 100)

    result = tk.shred_file(f, passes=1)

    assert result.ok
    assert not f.exists()


def test_shred_empty_file(tmp_path):
    f = tmp_path / "empty.txt"
    f.write_bytes(b"")

    result = tk.shred_file(f, passes=3)

    assert result.ok
    assert not f.exists()


 
# port range parsing
 

def test_parse_port_range_valid():
    assert tk.parse_port_range("1-5") == [1, 2, 3, 4, 5]


@pytest.mark.parametrize("bad", ["0-10", "100-50", "70000-70001", "abc", "5"])
def test_parse_port_range_invalid(bad):
    with pytest.raises(Exception):
        tk.parse_port_range(bad)



# port scanning (against a real local socket, no network needed)


@pytest.fixture
def local_listener():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    stop = threading.Event()

    def accept_loop():
        srv.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
                conn.close()
            except (socket.timeout, OSError):
                continue

    t = threading.Thread(target=accept_loop, daemon=True)
    t.start()
    yield port
    stop.set()
  
    t.join(timeout=1)
    srv.close()


def test_scan_port_detects_open_port(local_listener):
    assert tk.scan_port("127.0.0.1", local_listener, timeout=1.0) is True


def test_scan_port_detects_closed_port():

    assert tk.scan_port("127.0.0.1", 1, timeout=0.3) is False


def test_scan_ports_concurrent_finds_open_port(local_listener):
    candidate_ports = [local_listener, 1, 2]
    open_ports = tk.scan_ports("127.0.0.1", candidate_ports, timeout=1.0, max_workers=10)
    assert open_ports == [local_listener]



# DNS resolver dedup behavior


def test_get_system_resolvers_dedupes(monkeypatch, tmp_path):
    fake_resolv = tmp_path / "resolv.conf"
    fake_resolv.write_text("nameserver 1.1.1.1\nnameserver 1.1.1.1\nnameserver 8.8.8.8\n")

    monkeypatch.setattr(tk.platform, "system", lambda: "Linux")
    monkeypatch.setattr(tk, "Path", lambda p="/etc/resolv.conf": fake_resolv if p == "/etc/resolv.conf" else Path(p))

    resolvers = tk.get_system_resolvers()
    assert resolvers == ["1.1.1.1", "8.8.8.8"]


# systemd-resolved: stub 127.0.0.53 should trigger upstream lookup


def test_systemd_stub_pulls_upstream(monkeypatch, tmp_path):
    stub = tmp_path / "stub_resolv.conf"
    stub.write_text("nameserver 127.0.0.53\n")
    upstream = tmp_path / "upstream_resolv.conf"
    upstream.write_text("nameserver 1.1.1.1\nnameserver 8.8.8.8\n")

    paths = {
        "/etc/resolv.conf": stub,
        "/run/systemd/resolve/resolv.conf": upstream,
    }
    monkeypatch.setattr(tk.platform, "system", lambda: "Linux")
    monkeypatch.setattr(tk, "Path", lambda p: paths.get(p, Path(p)))

    resolvers = tk.get_system_resolvers()
    assert "127.0.0.53" in resolvers
    assert "1.1.1.1" in resolvers and "8.8.8.8" in resolvers


def test_non_stub_skips_upstream_lookup(monkeypatch, tmp_path):
    normal = tmp_path / "resolv.conf"
    normal.write_text("nameserver 1.1.1.1\n")
    upstream = tmp_path / "upstream_resolv.conf"
    upstream.write_text("nameserver 9.9.9.9\n")

    paths = {
        "/etc/resolv.conf": normal,
        "/run/systemd/resolve/resolv.conf": upstream,
    }
    monkeypatch.setattr(tk.platform, "system", lambda: "Linux")
    monkeypatch.setattr(tk, "Path", lambda p: paths.get(p, Path(p)))

    assert tk.get_system_resolvers() == ["1.1.1.1"]


# resolver labeling


def test_label_resolver_known():
    assert tk.label_resolver("1.1.1.1") == "Cloudflare"
    assert tk.label_resolver("8.8.8.8") == "Google"
    assert tk.label_resolver("9.9.9.9") == "Quad9"


def test_label_resolver_unknown_is_blank():
    assert tk.label_resolver("203.0.113.7") == ""


# port list parsing (new --ports option)


def test_parse_port_list_valid():
    assert tk.parse_port_list("22,80,443") == [22, 80, 443]


def test_parse_port_list_sorts_and_dedupes():
    assert tk.parse_port_list("443, 22,22,80") == [22, 80, 443]


@pytest.mark.parametrize("bad", ["0", "70000", "abc", "22,notaport", "", "  "])
def test_parse_port_list_invalid(bad):
    with pytest.raises(Exception):
        tk.parse_port_list(bad)


# port service naming + formatting


def test_format_open_ports_adds_known_services():
    # 80 -> http on essentially every system's IANA table
    assert "http" in tk.format_open_ports([80])


def test_format_open_ports_bare_port_when_unknown():
    # port 1 has no well-known service name on most systems
    assert "1" in tk.format_open_ports([1])


# shred: symlink guard


def test_shred_refuses_symlink(tmp_path):
    target = tmp_path / "real.txt"
    target.write_bytes(b"do not touch")
    link = tmp_path / "link.txt"
    link.symlink_to(target)

    result = tk.shred_file(link, passes=1)

    assert not result.ok
    assert "symlink" in result.message.lower()
    assert target.exists()  # original untouched
    assert target.read_bytes() == b"do not touch"


# metadata cleaning: real EXIF removal (jpg), pdf, docx


def test_clean_image_removes_exif(tmp_path):
    pytest.importorskip("PIL")
    piexif = pytest.importorskip("piexif")
    from PIL import Image

    src = tmp_path / "photo.jpg"
    img = Image.new("RGB", (16, 16), color=(120, 140, 160))
    exif = piexif.dump({
        "0th": {piexif.ImageIFD.Make: b"TestCam", piexif.ImageIFD.Software: b"spyware"},
        "Exif": {piexif.ExifIFD.DateTimeOriginal: b"2024:01:01 00:00:00"},
    })
    img.save(str(src), exif=exif)

    result = tk.clean_image_metadata(src)

    assert result.ok and result.output is not None
    with Image.open(result.output) as cleaned:
        assert not cleaned.getexif()  # EXIF fully gone


def test_clean_pdf_smoke(tmp_path):
    pypdf = pytest.importorskip("pypdf")
    src = tmp_path / "doc.pdf"
    w = pypdf.PdfWriter()
    w.add_blank_page(width=200, height=200)
    w.add_metadata({"/Author": "Sami", "/Title": "secret"})
    with open(src, "wb") as f:
        w.write(f)

    result = tk.clean_pdf_metadata(src)

    assert result.ok and result.output is not None
    r = pypdf.PdfReader(str(result.output))
    assert not (r.metadata and r.metadata.get("/Author"))


def test_clean_docx_smoke(tmp_path):
    docx = pytest.importorskip("docx")
    src = tmp_path / "doc.docx"
    d = docx.Document()
    d.add_paragraph("hello world")
    d.core_properties.author = "Sami"
    d.save(str(src))

    result = tk.clean_docx_metadata(src)

    assert result.ok and result.output is not None
    cleaned = docx.Document(str(result.output))
    assert cleaned.core_properties.author == ""


# image cleaner keeps unusual modes from crashing (LA -> RGB for jpg)


def test_clean_image_converts_la_mode_for_jpg(tmp_path):
    pytest.importorskip("PIL")
    from PIL import Image

    # LA content can only be encoded as PNG, but users hand toolkits all
    # kinds of mismatches - a .jpg file containing PNG bytes is realistic.
    # The cleaner must survive the mode (LA) and produce a valid RGB JPEG.
    src = tmp_path / "la.jpg"
    buf = tmp_path / "inner.png"
    Image.new("LA", (8, 8)).save(str(buf))
    src.write_bytes(buf.read_bytes())

    result = tk.clean_image_metadata(src)

    assert result.ok
    with Image.open(result.output) as out_img:
        assert out_img.mode == "RGB"


# site template integrity: unreliable sites flagged


def test_site_templates_have_reliability_flag():
    assert all(len(t) == 3 for t in tk.SITE_TEMPLATES)
    unreliable = {name for name, _, rel in tk.SITE_TEMPLATES if not rel}
    assert {"Twitter/X", "Instagram"} <= unreliable
