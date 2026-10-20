#!/usr/bin/env python3
"""Exercise three release executables against a dedicated empty MySQL database.

Requires Python 3 and openssl. No routes, firewall rules or existing services
are changed. The supplied database is migrated; use a disposable test database.
"""
import argparse
import base64
import contextlib
import http.cookiejar
import json
import os
from pathlib import Path
import secrets
import socket
import statistics
import subprocess
import threading
import time
import urllib.error
import urllib.request


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_until(check, timeout=15):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            result = check()
            if result:
                return result
        except (OSError, ValueError, KeyError) as error:
            last = error
        time.sleep(0.1)
    raise TimeoutError(f"condition did not become true; last error: {last}")


def recv_exact(sock, size):
    out = bytearray()
    while len(out) < size:
        data = sock.recv(size - len(out))
        if not data:
            raise EOFError(f"truncated payload {len(out)}/{size}")
        out.extend(data)
    return bytes(out)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", required=True)
    parser.add_argument("--mysql-dsn", default=os.getenv("DRAFRP_SMOKE_MYSQL_DSN"))
    parser.add_argument("--work-dir", required=True)
    args = parser.parse_args()
    if not args.mysql_dsn:
        parser.error("supply --mysql-dsn or DRAFRP_SMOKE_MYSQL_DSN")
    work = Path(args.work_dir).resolve()
    work.mkdir(parents=True, exist_ok=False, mode=0o700)
    binaries = Path(args.bin_dir).resolve()
    processes, files = [], []
    timings = []
    stopped = threading.Event()
    tcp = socket.socket()
    tcp.bind(("127.0.0.1", 0))
    tcp.listen(16)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("127.0.0.1", 0))
    targets = {"tcp": tcp.getsockname()[1], "udp": udp.getsockname()[1]}

    def echo_stream(conn):
        with conn:
            conn.settimeout(20)
            try:
                while data := conn.recv(65536):
                    conn.sendall(data)
            except OSError:
                pass

    def accept_tcp():
        while not stopped.is_set():
            try:
                conn, _ = tcp.accept()
            except OSError:
                return
            threading.Thread(target=echo_stream, args=(conn,), daemon=True).start()

    def echo_udp():
        while not stopped.is_set():
            try:
                data, peer = udp.recvfrom(65535)
                udp.sendto(data, peer)
            except OSError:
                return

    threading.Thread(target=accept_tcp, daemon=True).start()
    threading.Thread(target=echo_udp, daemon=True).start()

    def config(name, value):
        path = work / f"{name}.json"
        path.write_text(json.dumps(value, indent=2), encoding="utf-8")
        path.chmod(0o600)
        return str(path)

    def start(role, value):
        path = config(role, value)
        log = (work / f"{role}.log").open("wb")
        files.append(log)
        suffix = ".exe" if os.name == "nt" else ""
        process = subprocess.Popen([str(binaries / f"drafrp-{role}{suffix}"), "--config", path], stdout=log, stderr=log)
        processes.append(process)
        return process

    try:
        cert, key = work / "carrier.crt", work / "carrier.key"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ed25519", "-nodes", "-keyout", str(key), "-out", str(cert), "-days", "1", "-subj", "/CN=edge.test", "-addext", "subjectAltName=DNS:edge.test", "-addext", "basicConstraints=critical,CA:FALSE"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        key.chmod(0o600)
        cloud_port, carrier_port, public_port = free_port(), free_port(), free_port()
        url = f"http://127.0.0.1:{cloud_port}"
        username, password = "smoke-" + secrets.token_hex(5), secrets.token_urlsafe(24)
        start("cloud", {"listen": f"127.0.0.1:{cloud_port}", "mysql_dsn": args.mysql_dsn, "storage_key": base64.b64encode(secrets.token_bytes(32)).decode(), "admin_username": username, "admin_password": password, "snapshot_ttl": "10s", "captcha_disabled": True})
        wait_until(lambda: urllib.request.urlopen(url + "/readyz", timeout=1).status == 204)
        jar = http.cookiejar.CookieJar()
        browser = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
        csrf = ""

        def api(method, path, value=None):
            raw = None if value is None else json.dumps(value).encode()
            request = urllib.request.Request(url + path, raw, {"Content-Type": "application/json", "X-CSRF-Token": csrf}, method=method)
            try:
                with browser.open(request, timeout=6) as response:
                    return json.load(response)
            except urllib.error.HTTPError as error:
                raise RuntimeError(f"{method} {path}: {error.code} {error.read().decode()}") from error

        login = api("POST", "/auth/login", {"username": username, "password": password})
        csrf = login["csrf_token"]
        with browser.open(url + "/console/", timeout=2) as response:
            html = response.read().decode()
            assert response.status == 200 and "/console/assets/" in html, "release console was not embedded"
        token = secrets.token_urlsafe(32)
        edge_resource = api("POST", "/api/v1/edges", {"name": "binary-smoke", "token": token, "public_host": "127.0.0.1", "listen_host": "127.0.0.1", "endpoints": [{"transport": "quic", "address": f"127.0.0.1:{carrier_port}", "server_name": "edge.test"}, {"transport": "tls", "address": f"127.0.0.1:{carrier_port}", "server_name": "edge.test"}], "ca_cert": cert.read_text(), "http_port": 0, "https_port": 0, "port_min": public_port, "port_max": public_port, "max_carriers": 4, "capacity_bps": -1})
        start("edge", {"cloud_url": url, "edge_id": edge_resource["id"], "token": token, "cert_file": str(cert), "key_file": str(key), "listen_host": "127.0.0.1", "sync_interval": "1s"})
        state = work / "device"
        start("client", {"cloud_url": url, "state_dir": str(state), "name": "binary-smoke-device", "sync_interval": "1s", "transport": "auto", "network_mode": "socket", "allowed_target_cidrs": ["127.0.0.1/32"]})
        pending = wait_until(lambda: json.loads((state / "device.json").read_text()).get("pending"))
        api("GET", "/api/v1/bind/" + pending["user_code"])
        binding = api("POST", "/api/v1/bind/confirm", {"user_code": pending["user_code"]})
        device_id = binding["device_id"]
        rules = []
        for protocol, target_port in targets.items():
            rules.append(api("POST", "/api/v1/rules", {"name": "binary-" + protocol, "protocol": protocol, "device_id": device_id, "edge_id": edge_resource["id"], "public_port": public_port, "target": f"127.0.0.1:{target_port}", "source_mode": "socket", "transport": "auto", "enabled": True}))

        def exchange(data):
            begin = time.monotonic()
            with socket.create_connection(("127.0.0.1", public_port), timeout=3) as conn:
                conn.settimeout(5)
                conn.sendall(data)
                assert recv_exact(conn, len(data)) == data
                conn.shutdown(socket.SHUT_WR)
                assert conn.recv(1) == b"", "TCP half-close not propagated"
            return time.monotonic() - begin

        wait_until(lambda: exchange(b"probe") >= 0)
        for _ in range(12):
            timings.append(exchange(secrets.token_bytes(4096)) * 1000)
        large = secrets.token_bytes(512 * 1024)
        with socket.create_connection(("127.0.0.1", public_port), timeout=3) as conn:
            conn.settimeout(8)
            upload_error = []

            def upload():
                try:
                    conn.sendall(large)
                    conn.shutdown(socket.SHUT_WR)
                except OSError as error:
                    upload_error.append(error)

            writer = threading.Thread(target=upload)
            writer.start()
            assert recv_exact(conn, len(large)) == large
            assert conn.recv(1) == b""
            writer.join(2)
            assert not writer.is_alive() and not upload_error
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as conn:
            conn.settimeout(5)
            for data in (b"first", secrets.token_bytes(48000), b""):
                conn.sendto(data, ("127.0.0.1", public_port))
                assert conn.recv(65535) == data
        wait_until(lambda: all(api("GET", "/api/v1/rules/" + rule["id"])["status"] == "ready" for rule in rules))
        with socket.create_connection(("127.0.0.1", public_port), timeout=3) as conn:
            conn.settimeout(5)
            conn.sendall(b"before-revoke")
            assert recv_exact(conn, 13) == b"before-revoke"
            api("DELETE", "/api/v1/devices/" + device_id)
            try:
                assert conn.recv(1) == b"", "revoked flow remained open"
            except ConnectionResetError:
                pass
        assert all(process.poll() is None for process in processes), "service exited during smoke test"
        result = {"status": "passed", "binary_roles": ["cloud", "edge", "client"], "tcp_large_bytes": len(large), "udp_max_tested_bytes": 48000, "zero_length_udp": True, "active_flow_revocation": True, "release_console_embedded": True, "connect_echo_close_ms_median": statistics.median(timings), "connect_echo_close_ms_p95": sorted(timings)[-1], "samples": len(timings), "note": "loopback smoke timing; not a WAN/frp performance comparison"}
        (work / "result.json").write_text(json.dumps(result, indent=2))
        print(json.dumps(result, indent=2))
    finally:
        stopped.set()
        tcp.close()
        udp.close()
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
        for process in reversed(processes):
            try:
                process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        for log in files:
            log.close()


if __name__ == "__main__":
    main()
