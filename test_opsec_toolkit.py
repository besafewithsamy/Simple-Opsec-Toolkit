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
