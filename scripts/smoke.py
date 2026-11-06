#!/usr/bin/env python3
"""Exercise release binaries against a disposable MySQL database.

Requires Python 3 and OpenSSL. No routes, firewall rules, or existing services
are changed. The supplied database is migrated; use a dedicated empty database.
On Linux, --performance adds loopback TCP/UDP load and process CPU/RSS metrics;
it is not a WAN, TUN, or cross-project benchmark.
"""
import argparse
import base64
import concurrent.futures
import http.cookiejar
import json
import math
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

TRANSFER_TIMEOUT_SECONDS = 120


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


def percentile_ms(samples, percentile):
    ordered = sorted(samples)
    if not ordered:
        return None
    rank = max(1, min(len(ordered), math.ceil(percentile * len(ordered) / 100)))
    return round(ordered[rank - 1], 3)


def latency_summary_ms(samples):
    return {
        "samples": len(samples),
        "p50": percentile_ms(samples, 50),
        "p95": percentile_ms(samples, 95),
        "p99": percentile_ms(samples, 99),
        "max": round(max(samples), 3) if samples else None,
    }


def read_process_stat(process, page_size):
    try:
        stat = Path(f"/proc/{process.pid}/stat").read_text(encoding="ascii")
    except OSError:
        return None
    fields = stat[stat.rfind(")") + 2:].split()
    if len(fields) < 22:
        return None
    cpu_ticks = int(fields[11]) + int(fields[12])
    rss_bytes = max(0, int(fields[21])) * page_size
    return cpu_ticks, rss_bytes


def tcp_echo_transfer(port, payload):
    started = time.perf_counter()
    with socket.create_connection(("127.0.0.1", port), timeout=3) as conn:
        conn.settimeout(TRANSFER_TIMEOUT_SECONDS)
        upload_errors = []

        def upload():
            try:
                conn.sendall(payload)
                conn.shutdown(socket.SHUT_WR)
            except OSError as error:
                upload_errors.append(error)

        sender = threading.Thread(target=upload, daemon=True)
        sender.start()
        echoed = recv_exact(conn, len(payload))
        sender.join(timeout=TRANSFER_TIMEOUT_SECONDS)
        if sender.is_alive():
            raise TimeoutError("TCP upload thread did not finish")
        if upload_errors:
            raise upload_errors[0]
        if echoed != payload or conn.recv(1):
            raise AssertionError("TCP echo or half-close mismatch")
    return time.perf_counter() - started


def udp_windowed_echo(port, payload_size, packet_count, window):
    address = ("127.0.0.1", port)
    samples = []
    receive_buffer = min(8 << 20, max(1 << 20, payload_size * window * 2))
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as conn:
        conn.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, receive_buffer)
        receive_buffer_bytes = conn.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
        conn.settimeout(0.25)
        started = time.perf_counter()
        for base in range(0, packet_count, window):
            pending = {}
            for sequence in range(base, min(base + window, packet_count)):
                payload = sequence.to_bytes(4, "big") + bytes([sequence & 0xFF]) * (payload_size - 4)
                sent_at = time.perf_counter()
                conn.sendto(payload, address)
                pending[sequence] = (payload, sent_at)
            while pending:
                try:
                    echoed, _ = conn.recvfrom(payload_size + 1)
                except socket.timeout:
                    break
                if len(echoed) < 4:
                    continue
                sequence = int.from_bytes(echoed[:4], "big")
                expected = pending.get(sequence)
                if expected is None:
                    continue
                if echoed != expected[0]:
                    raise AssertionError("UDP echo payload mismatch")
                del pending[sequence]
                samples.append((time.perf_counter() - expected[1]) * 1000)
        elapsed = time.perf_counter() - started
    received = len(samples)
    return {
        "payload_bytes": payload_size,
        "offered_packets": packet_count,
        "window": window,
        "received_packets": received,
        "lost_packets": packet_count - received,
        "loss_pct": round((packet_count - received) * 100 / packet_count, 3),
        "elapsed_s": round(elapsed, 3),
        "goodput_mib_s": round(received * payload_size / elapsed / (1024 * 1024), 3),
        "packets_per_s": round(received / elapsed, 2),
        "socket_receive_buffer_bytes": receive_buffer_bytes,
        "rtt_ms": latency_summary_ms(samples),
    }


def run_performance(port, process_roles, transport):
    if not Path("/proc").is_dir():
        raise RuntimeError("performance mode requires a Linux VM with /proc")
    page_size = os.sysconf("SC_PAGE_SIZE")
    ticks_per_second = os.sysconf("SC_CLK_TCK")
    process_metrics = {}

    def sample_processes():
        for role, process in process_roles.items():
            sample = read_process_stat(process, page_size)
            if sample is None:
                continue
            cpu_ticks, rss_bytes = sample
            metric = process_metrics.setdefault(role, {
                "start_ticks": cpu_ticks,
                "end_ticks": cpu_ticks,
                "rss_start_bytes": rss_bytes,
                "rss_peak_bytes": rss_bytes,
            })
            metric["end_ticks"] = cpu_ticks
            metric["rss_peak_bytes"] = max(metric["rss_peak_bytes"], rss_bytes)

    sample_processes()
    if len(process_metrics) != len(process_roles):
        raise RuntimeError("could not read all DraFRP process resource counters")
    stop_monitor = threading.Event()

    def monitor_processes():
        while not stop_monitor.wait(0.2):
            sample_processes()

    monitor = threading.Thread(target=monitor_processes, daemon=True)
    monitor.start()
    started = time.perf_counter()
    try:
        tcp_payload = b"p" * (4 << 20)
        tcp_latency = []
        with socket.create_connection(("127.0.0.1", port), timeout=3) as conn:
            conn.settimeout(5)
            request = b"r" * 64
            for _ in range(200):
                request_started = time.perf_counter()
                conn.sendall(request)
                if recv_exact(conn, len(request)) != request:
                    raise AssertionError("TCP latency echo mismatch")
                tcp_latency.append((time.perf_counter() - request_started) * 1000)

        tcp_goodput = []
        for flow_count in (1, 4, 16):
            transfer_started = time.perf_counter()
            with concurrent.futures.ThreadPoolExecutor(max_workers=flow_count) as executor:
                flow_seconds = list(executor.map(lambda _: tcp_echo_transfer(port, tcp_payload), range(flow_count)))
            elapsed = time.perf_counter() - transfer_started
            total_bytes = flow_count * len(tcp_payload)
            tcp_goodput.append({
                "concurrent_flows": flow_count,
                "payload_bytes_per_flow": len(tcp_payload),
                "elapsed_s": round(elapsed, 3),
                "aggregate_goodput_mib_s": round(total_bytes / elapsed / (1024 * 1024), 3),
                "flow_duration_ms": latency_summary_ms([duration * 1000 for duration in flow_seconds]),
            })

        udp = []
        for payload_size, packet_count in ((128, 500), (1400, 500), (48000, 100)):
            for window in (1, 16, 64):
                udp.append(udp_windowed_echo(port, payload_size, packet_count, window))
    finally:
        stop_monitor.set()
        monitor.join()
        sample_processes()
    elapsed = time.perf_counter() - started
    services = {}
    for role, metric in process_metrics.items():
        cpu_seconds = max(0, metric["end_ticks"] - metric["start_ticks"]) / ticks_per_second
        services[role] = {
            "cpu_seconds": round(cpu_seconds, 3),
            "cpu_percent_one_core_avg": round(cpu_seconds * 100 / elapsed, 2),
            "rss_start_bytes": metric["rss_start_bytes"],
            "rss_peak_sampled_bytes": metric["rss_peak_bytes"],
        }
    return {
        "carrier_mode": transport,
        "scope": "127.0.0.1 loopback, ordinary socket forwarding",
        "tcp_persistent_rtt_ms": latency_summary_ms(tcp_latency),
        "tcp_echo_goodput": tcp_goodput,
        "udp_windowed_echo": udp,
        "service_process_resources": {
            "sample_interval_ms": 200,
            "measurement_s": round(elapsed, 3),
            "processes": services,
        },
        "limitations": "VM loopback only; Python echo target and unrelated VM processes are not included in per-service CPU/RSS.",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", required=True)
    parser.add_argument("--mysql-dsn", default=os.getenv("DRAFRP_SMOKE_MYSQL_DSN"))
    parser.add_argument("--work-dir", required=True)
    parser.add_argument("--transport", choices=("auto", "quic_only", "tls_only"), default="auto")
    parser.add_argument("--performance", action="store_true", help="run loopback TCP/UDP throughput, latency, and service resource measurements on Linux")
    args = parser.parse_args()
    if args.performance and not Path("/proc").is_dir():
        parser.error("--performance requires a Linux VM with /proc")
    if not args.mysql_dsn:
        parser.error("supply --mysql-dsn or DRAFRP_SMOKE_MYSQL_DSN")
    work = Path(args.work_dir).resolve()
    work.mkdir(parents=True, exist_ok=False, mode=0o700)
    binaries = Path(args.bin_dir).resolve()
    processes, files = [], []
    process_roles = {}
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
            conn.settimeout(TRANSFER_TIMEOUT_SECONDS)
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
        process_roles[role] = process
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
        start("client", {"cloud_url": url, "state_dir": str(state), "name": "binary-smoke-device", "sync_interval": "1s", "transport": args.transport, "network_mode": "socket", "allowed_target_cidrs": ["127.0.0.1/32"]})
        pending = wait_until(lambda: json.loads((state / "device.json").read_text()).get("pending"))
        api("GET", "/api/v1/bind/" + pending["user_code"])
        binding = api("POST", "/api/v1/bind/confirm", {"user_code": pending["user_code"]})
        device_id = binding["device_id"]
        rules = []
        for protocol, target_port in targets.items():
            rules.append(api("POST", "/api/v1/rules", {"name": "binary-" + protocol, "protocol": protocol, "device_id": device_id, "edge_id": edge_resource["id"], "public_port": public_port, "target": f"127.0.0.1:{target_port}", "source_mode": "socket", "transport": args.transport, "enabled": True}))

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
        performance = run_performance(public_port, process_roles, args.transport) if args.performance else None
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
        if performance is not None:
            result["performance"] = performance
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
