#!/usr/bin/env python3
"""Verify Linux client TUN source identity through all three executables.

Run inside the disposable Linux VM. The Agent and origin fixture run in the
supplied dedicated NET_ADMIN Docker namespace. The edge must run as non-root,
with all capabilities dropped and no TUN device. Cloud and visitor run in the
VM. Host routes/firewall are never changed. Only the client namespace needs
/dev/net/tun, IPv4 forwarding, disabled rp_filter, route_localnet/accept_local,
iproute2 and iptables. --target-helper is built with
`go test -c ./internal/native`; the supplied database must be disposable.
"""
import argparse
import base64
import http.cookiejar
import json
from pathlib import Path
import secrets
import socket
import subprocess
import urllib.error
import urllib.request

from smoke import free_port, recv_exact, wait_until


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", required=True)
    parser.add_argument("--work-dir", required=True)
    parser.add_argument("--agent-container", required=True)
    parser.add_argument("--edge-container", required=True)
    parser.add_argument("--target-container", help="Optional separate LAN target namespace with an explicit visitor return route through the agent")
    parser.add_argument("--target-ip", default="127.0.0.1")
    parser.add_argument("--bridge-host", default="172.17.0.1")
    parser.add_argument("--visitor-host", required=True, help="A VM address outside the Docker bridge subnet, to avoid Docker masquerading local bridge-source traffic")
    parser.add_argument("--carrier-host", help="Optional IPv6 or IPv4 carrier address in the edge namespace; business visitors remain IPv4")
    parser.add_argument("--target-helper", required=True)
    parser.add_argument("--mysql-dsn-file", required=True)
    parser.add_argument("--bootstrap-config", help="Reuse admin credentials and storage key from a previous private cloud config when rerunning against the same disposable database")
    args = parser.parse_args()
    work = Path(args.work_dir).resolve()
    work.mkdir(mode=0o700, parents=True, exist_ok=False)
    binaries = Path(args.bin_dir).resolve()
    prefix = "/tmp/drafrp-tun-e2e-" + secrets.token_hex(6)
    container = args.agent_container
    origin_container = args.target_container or container
    target_ip = args.target_ip
    cloud_host = args.bridge_host
    host = subprocess.run(["docker", "inspect", "-f", "{{.NetworkSettings.Networks.bridge.IPAddress}}", args.edge_container], check=True, capture_output=True, text=True).stdout.strip()
    socket.inet_aton(host)
    carrier_host = args.carrier_host or host
    carrier_address = lambda port: f"[{carrier_host}]:{port}" if ":" in carrier_host else f"{carrier_host}:{port}"
    visitor_host = args.visitor_host
    processes, logs, container_paths = [], [], []

    def docker(*argv, check=True):
        return subprocess.run(["docker", *argv], check=check, capture_output=True, text=True)

    def remote(*argv, check=True, where=None):
        return docker("exec", where or container, *argv, check=check)

    def config(name, value):
        path = work / (name + ".json")
        path.write_text(json.dumps(value, indent=2))
        path.chmod(0o600)
        return str(path)

    def start(role, value):
        path = config(role, value)
        output = (work / (role + ".log")).open("wb")
        logs.append(output)
        process = subprocess.Popen([str(binaries / ("drafrp-" + role)), "--config", path], stdout=output, stderr=output)
        processes.append(process)
        return process

    def start_container(name, argv, env=(), where=None):
        output = (work / (name + ".log")).open("wb")
        logs.append(output)
        options = [piece for value in env for piece in ("-e", value)]
        destination = where or container
        process = subprocess.Popen(["docker", "exec", *options, destination, *argv], stdout=output, stderr=output)
        processes.append(process)
        container_paths.append((destination, argv[0]))
        return process

    def remote_json(path, where=None):
        result = remote("cat", path, check=False, where=where)
        if result.returncode:
            return None
        return json.loads(result.stdout)

    def edge_copy(source, name, mode="600"):
        # Write as the edge UID: docker cp can preserve the host UID, which a
        # process with ALL capabilities dropped cannot chown or chmod.
        with Path(source).open("rb") as data:
            subprocess.run(["docker", "exec", "-i", args.edge_container, "sh", "-c",
                'umask 077; cat > "$1" && chmod "$2" "$1"', "copy", prefix + "/" + name, mode],
                stdin=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)

    edge_info = json.loads(docker("inspect", args.edge_container).stdout)[0]
    assert edge_info["Config"]["User"] not in ("", "0", "root", "0:0")
    assert "ALL" in edge_info["HostConfig"]["CapDrop"]
    assert not edge_info["HostConfig"]["CapAdd"]
    assert not any(d["PathInContainer"] == "/dev/net/tun" for d in edge_info["HostConfig"]["Devices"])
    assert remote("test", "-e", "/dev/net/tun", check=False, where=args.edge_container).returncode != 0

    def edge_network_snapshot():
        snapshot = {name: remote(*command, where=args.edge_container).stdout for name, command in (
            ("links", ("ip", "-o", "link", "show")),
            ("routes", ("ip", "-4", "route", "show", "table", "all")),
            ("rules", ("ip", "-4", "rule", "show")))}
        # Separate read-only observer: the edge process itself has no NET_ADMIN.
        rules = docker("run", "--rm", "--network", "container:" + args.edge_container,
            "--cap-add", "NET_ADMIN", "--entrypoint", "iptables-save", edge_info["Config"]["Image"]).stdout
        snapshot["firewall"] = "\n".join(line for line in rules.splitlines() if not line.startswith("#"))
        return snapshot

    edge_network_before = edge_network_snapshot()

    try:
        # Docker can masquerade a VM socket bound to its bridge gateway even
        # when the destination is local. Check the same route before asserting
        # that visitor.getsockname() is the address observed by the edge.
        for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
            with socket.socket(socket.AF_INET, kind) as observer, socket.socket(socket.AF_INET, kind) as visitor:
                observer.settimeout(2)
                visitor.settimeout(2)
                observer.bind((cloud_host, 0))
                visitor.bind((visitor_host, 0))
                if kind == socket.SOCK_STREAM:
                    observer.listen(1)
                    visitor.connect(observer.getsockname())
                    accepted, observed = observer.accept()
                    accepted.close()
                else:
                    visitor.sendto(b"native-source-preflight", observer.getsockname())
                    _, observed = observer.recvfrom(128)
                assert observed == visitor.getsockname(), f"visitor route applies NAT: socket={visitor.getsockname()} observed={observed}; choose --visitor-host outside the Docker bridge subnet"
        remote("mkdir", "-m", "700", prefix)
        remote("mkdir", "-m", "700", prefix, where=args.edge_container)
        docker("cp", str(binaries / "drafrp-client"), container + ":" + prefix + "/client")
        if origin_container != container:
            remote("mkdir", "-m", "700", prefix, where=origin_container)
        docker("cp", str(Path(args.target_helper).resolve()), origin_container + ":" + prefix + "/target")
        remote("chmod", "700", prefix + "/client")
        remote("chmod", "700", prefix + "/target", where=origin_container)
        networks = json.loads(docker("inspect", container).stdout)[0]["NetworkSettings"]["Networks"]
        container_ip = networks["bridge"]["IPAddress"]
        socket.inet_aton(container_ip)
        target_env = ["DRAFRP_NATIVE_TARGET=1", "DRAFRP_NATIVE_BIND=" + target_ip]
        if not args.target_container:
            target_env += ["DRAFRP_NATIVE_BAD_SOURCE=" + container_ip]
        start_container("target", [prefix + "/target", "-test.run=^TestNativeRemoteTarget$"], target_env, where=origin_container)
        wait_until(lambda: "target-ready" in (work / "target.log").read_text())
        cert, key = work / "carrier.crt", work / "carrier.key"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ed25519", "-nodes", "-keyout", str(key), "-out", str(cert), "-days", "1", "-subj", "/CN=edge.test", "-addext", "subjectAltName=DNS:edge.test"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        key.chmod(0o600)
        for source, name in ((binaries / "drafrp-edge", "edge"), (cert, "carrier.crt"), (key, "carrier.key")):
            edge_copy(source, name, "700" if name == "edge" else "600")
        cloud_port, carrier_port = free_port(), free_port()
        public_ports = []
        while len(public_ports) < 3:
            port = free_port()
            if port not in (cloud_port, carrier_port, *public_ports):
                public_ports.append(port)
        url = f"http://{cloud_host}:{cloud_port}"
        bootstrap = {"storage_key": base64.b64encode(secrets.token_bytes(32)).decode(), "admin_username": "native-" + secrets.token_hex(5), "admin_password": secrets.token_urlsafe(24)}
        if args.bootstrap_config:
            previous = json.loads(Path(args.bootstrap_config).read_text())
            bootstrap = {name: previous[name] for name in bootstrap}
        username, password = bootstrap["admin_username"], bootstrap["admin_password"]
        # This fixture tests native forwarding, not the browser captcha flow.
        start("cloud", {"listen": f"{cloud_host}:{cloud_port}", "mysql_dsn": Path(args.mysql_dsn_file).read_text().strip(), **bootstrap, "snapshot_ttl": "1m", "captcha_disabled": True})
        wait_until(lambda: urllib.request.urlopen(url + "/readyz", timeout=1).status == 204)
        jar = http.cookiejar.CookieJar()
        browser = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar), urllib.request.ProxyHandler({}))
        csrf = ""

        def api(method, path, value=None):
            raw = None if value is None else json.dumps(value).encode()
            request = urllib.request.Request(url + path, raw, {"Content-Type": "application/json", "X-CSRF-Token": csrf}, method=method)
            try:
                with browser.open(request, timeout=6) as response:
                    return json.load(response)
            except urllib.error.HTTPError as error:
                raise RuntimeError(f"{method} {path}: {error.code} {error.read().decode()}") from error

        csrf = api("POST", "/auth/login", {"username": username, "password": password})["csrf_token"]
        token = secrets.token_urlsafe(32)
        edge = api("POST", "/api/v1/edges", {"name": "native-smoke", "token": token, "public_host": host, "listen_host": host, "endpoints": [{"transport": mode, "address": carrier_address(carrier_port), "server_name": "edge.test"} for mode in ("quic", "tls")], "ca_cert": cert.read_text(), "http_port": 0, "https_port": 0, "port_min": min(public_ports), "port_max": max(public_ports), "max_carriers": 4, "capacity_bps": -1})
        edge_cfg = config("edge", {"cloud_url": url, "edge_id": edge["id"], "token": token, "cert_file": prefix + "/carrier.crt", "key_file": prefix + "/carrier.key", "listen_host": host, "carrier_listen_hosts": list(dict.fromkeys([host, carrier_host])), "sync_interval": "1s"})
        edge_copy(edge_cfg, "edge.json")
        edge_process = start_container("edge", [prefix + "/edge", "--config", prefix + "/edge.json"], where=args.edge_container)
        client_cfg = config("client", {"cloud_url": url, "state_dir": prefix + "/device", "name": "tun-smoke-device", "sync_interval": "1s", "transport": "auto", "max_carriers_per_edge": 4, "network_mode": "tun", "native_return_cidrs": [target_ip + "/32"] if args.target_container else [], "allowed_target_cidrs": [target_ip + "/32"], "allowed_target_ports": [38081, 38082, 38083]})
        docker("cp", client_cfg, container + ":" + prefix + "/client.json")
        agent_process = start_container("client", [prefix + "/client", "--config", prefix + "/client.json"])
        pending = wait_until(lambda: (remote_json(prefix + "/device/device.json") or {}).get("pending"))
        inspection = api("GET", "/api/v1/bind/" + pending["user_code"])
        fingerprint = inspection["public_key_fingerprint"]
        wait_until(lambda: "Public key fingerprint: " + fingerprint in (work / "client.log").read_text())
        device = api("POST", "/api/v1/bind/confirm", {"user_code": pending["user_code"]})["device_id"]
        capabilities = {"native_tcp_ipv4_ip_port", "native_udp_ipv4_ip_port", "tun_client_tcp_ipv4_ip_port", "tun_client_udp_ipv4_ip_port"}

        def verified_device():
            for item in api("GET", "/api/v1/devices")["items"]:
                if item["id"] == device and capabilities.issubset(item["capabilities"]):
                    return item
            return None

        observed_device = wait_until(verified_device)
        assert observed_device["runtime"]["platform"] == "linux"
        assert observed_device["runtime"]["network_mode"] == "tun"
        rules = []
        for index, mode in enumerate(("quic_only", "tls_only")):
            for protocol, target_port in (("tcp", 38081), ("udp", 38082)):
                rules.append(api("POST", "/api/v1/rules", {"name": "tun-" + mode + "-" + protocol, "protocol": protocol, "device_id": device, "edge_id": edge["id"], "public_port": public_ports[index], "target": f"{target_ip}:{target_port}", "source_mode": "native", "transport": mode, "enabled": True}))
        def rules_have_status(allowed):
            states = [{key: value for key, value in api("GET", "/api/v1/rules/" + rule["id"]).items() if key in ("id", "protocol", "transport", "version", "applied_version", "status", "last_error")} for rule in rules]
            (work / "rule-status.json").write_text(json.dumps(states, indent=2))
            return all(state["status"] in allowed for state in states)

        # A rule becomes ready only after successful business forwarding.
        wait_until(lambda: rules_have_status({"listening", "ready"}), timeout=20)
        checked = []

        def visitor_tcp(port):
            conn = socket.socket()
            conn.settimeout(5)
            conn.bind((visitor_host, 0))
            conn.connect((host, port))
            observed = bytearray()
            while not observed.endswith(b"|"):
                observed.extend(recv_exact(conn, 1))
            expected = f"{conn.getsockname()[0]}:{conn.getsockname()[1]}"
            assert observed[:-1].decode() == expected, (observed, expected)
            return conn, expected

        for index, mode in enumerate(("quic_only", "tls_only")):
            conn, peer = visitor_tcp(public_ports[index])
            with conn:
                payload = secrets.token_bytes(128 * 1024)
                conn.sendall(payload)
                assert recv_exact(conn, len(payload)) == payload
                conn.shutdown(socket.SHUT_WR)
                assert conn.recv(1) == b"", "native TCP half-close failed"
            checked.append({"protocol": "tcp", "transport": mode, "actual_visitor": peer, "target_observed_same_ip_port": True, "bytes": len(payload)})
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                udp.settimeout(5)
                udp.bind((visitor_host, 0))
                peer = f"{udp.getsockname()[0]}:{udp.getsockname()[1]}".encode()
                for payload in (b"first", secrets.token_bytes(60000), b""):
                    (work / "progress.json").write_text(json.dumps({"transport": mode, "protocol": "udp", "payload_bytes": len(payload)}))
                    udp.sendto(payload, (host, public_ports[index]))
                    response, response_peer = udp.recvfrom(65535)
                    assert response_peer == (host, public_ports[index]), f"UDP response bypassed public listener: {response_peer}"
                    assert response == peer + b"|" + payload, "native UDP source tuple or payload changed"
            checked.append({"protocol": "udp", "transport": mode, "actual_visitor": peer.decode(), "target_observed_same_ip_port": True, "max_bytes": 60000, "zero_length": True})
            (work / "verified-cases.json").write_text(json.dumps(checked, indent=2))
        wait_until(lambda: rules_have_status({"ready"}), timeout=15)
        def carrier_observations():
            runtime = verified_device()["runtime"]
            carriers = runtime.get("carriers", [])
            selected = {item["transport"] for item in carriers if item.get("remote_address") == carrier_address(carrier_port)}
            return carriers if selected == {"quic", "tls"} else None
        observed_carriers = wait_until(carrier_observations)
        # A retired ordinary UDP listener must allow the same visitor tuple
        # after re-enabling, with no old flow or source reservation left behind.
        udp_rule = rules[3]

        def udp_listening():
            return bool(remote("ss", "-H", "-u", "-l", "-n", "sport = :" + str(public_ports[1]), where=args.edge_container).stdout.strip())

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as visitor:
            visitor.bind((visitor_host, 0))
            visitor.settimeout(5)
            expected = f"{visitor_host}:{visitor.getsockname()[1]}|".encode()
            visitor.sendto(b"before-reenable", (host, public_ports[1]))
            assert visitor.recvfrom(256) == (expected + b"before-reenable", (host, public_ports[1]))
            changed = api("GET", "/api/v1/rules/" + udp_rule["id"])
            changed["enabled"] = False
            changed = api("PUT", "/api/v1/rules/" + udp_rule["id"], changed)
            wait_until(lambda: not udp_listening())
            changed["enabled"] = True
            api("PUT", "/api/v1/rules/" + udp_rule["id"], changed)
            wait_until(udp_listening)
            wait_until(lambda: api("GET", "/api/v1/rules/" + udp_rule["id"])["status"] == "listening")
            visitor.sendto(b"after-reenable", (host, public_ports[1]))
            assert visitor.recvfrom(256) == (expected + b"after-reenable", (host, public_ports[1]))
        # Tightening an ACL must cancel a TCP flow that has already handshaken.
        active_acl, _ = visitor_tcp(public_ports[0])
        with active_acl:
            changed = api("GET", "/api/v1/rules/" + rules[0]["id"])
            changed["acl"] = {"default_action": "deny", "entries": [], "version": 1}
            changed = api("PUT", "/api/v1/rules/" + changed["id"], changed)
            try:
                assert active_acl.recv(1) == b"", "ACL-tightened TUN flow survived"
            except ConnectionResetError:
                pass
            changed["acl"] = {"default_action": "allow", "entries": [], "version": 2}
            api("PUT", "/api/v1/rules/" + changed["id"], changed)
            wait_until(lambda: api("GET", "/api/v1/rules/" + rules[0]["id"])["status"] == "listening")
        if not args.target_container:
            bad_rule = api("POST", "/api/v1/rules", {"name": "tun-wrong-source-must-drop", "protocol": "udp", "device_id": device, "edge_id": edge["id"], "public_port": public_ports[2], "target": "127.0.0.1:38083", "source_mode": "native", "transport": "tls_only", "enabled": True})
            wait_until(lambda: api("GET", "/api/v1/rules/" + bad_rule["id"])["status"] == "listening")
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as visitor:
                visitor.bind((visitor_host, 0))
                visitor.settimeout(1)
                visitor.sendto(b"must-not-bypass-edge", (host, public_ports[2]))
                wait_until(lambda: "wrong-source-reply-attempted" in (work / "target.log").read_text())
                try:
                    escaped, sender = visitor.recvfrom(256)
                except socket.timeout:
                    pass
                else:
                    raise AssertionError(f"wrong-source UDP escaped: sender={sender} bytes={len(escaped)}")
        active, peer = visitor_tcp(public_ports[0])
        with active, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as active_udp:
            active_udp.bind((visitor_host, 0))
            active_udp.settimeout(3)
            udp_peer = f"{active_udp.getsockname()[0]}:{active_udp.getsockname()[1]}".encode()
            active_udp.sendto(b"before-revoke", (host, public_ports[1]))
            assert active_udp.recvfrom(256) == (udp_peer + b"|before-revoke", (host, public_ports[1]))
            active.sendall(b"before-revoke")
            assert recv_exact(active, 13) == b"before-revoke"
            api("DELETE", "/api/v1/devices/" + device)
            try:
                assert active.recv(1) == b"", "revoked native flow survived"
            except ConnectionResetError:
                pass
            active_udp.settimeout(1)
            active_udp.sendto(b"after-revoke", (host, public_ports[1]))
            try:
                escaped, sender = active_udp.recvfrom(256)
            except socket.timeout:
                pass
            else:
                raise AssertionError(f"revoked native UDP replied: sender={sender} bytes={len(escaped)}")
        owned = remote_json(prefix + "/device/tun-network.json")
        remote("pkill", "-TERM", "-f", prefix + "/client")
        agent_process.wait(timeout=8)
        assert remote_json(prefix + "/device/tun-network.json") is None, "ownership state survived clean Agent shutdown"
        assert owned["Chain"] not in remote("iptables", "-t", "filter", "-S").stdout, "TUN chain survived shutdown"
        assert "lookup " + str(owned["Table"]) not in remote("ip", "-4", "rule", "show").stdout, "TUN policy route survived shutdown"
        remote("pkill", "-TERM", "-f", prefix + "/edge", where=args.edge_container)
        edge_process.wait(timeout=8)
        assert edge_network_snapshot() == edge_network_before, "socket edge changed its network objects"
        def settled_usage():
            items = api("GET", "/api/v1/usage-summary")["items"]
            usage = next((item for item in items if item["edge_id"] == edge["id"]), None)
            history = api("GET", "/api/v1/usage-history?edge_id=" + edge["id"])
            if usage and usage["upload_bytes"] == history["upload_bytes"] and usage["download_bytes"] == history["download_bytes"]:
                assert usage["upload_bytes"] > 2 * (131072 + 60000)
                assert usage["download_bytes"] > 2 * (131072 + 60000)
                return {"cumulative_matches_minutes": True, "upload_bytes": usage["upload_bytes"], "download_bytes": usage["download_bytes"], "unit": "application payload bytes"}
            return None
        accounting = wait_until(settled_usage)
        result = {"status": "passed", "binary_roles": ["cloud", "edge", "client"], "data_path": "ordinary socket edge, application-data carrier, Linux client netstack and TUN", "edge_nonroot_no_capabilities_no_tun": True, "edge_network_objects_unchanged": True, "tcp_connections": "independent public and target handshakes", "target": target_ip, "separate_lan_target": bool(args.target_container), "different_visitor_edge_agent_namespaces": True, "native_source": "IPv4 IP and port", "capabilities": sorted(capabilities), "cases": checked, "wrong_source_udp_dropped": True if not args.target_container else "covered in local-target run", "udp_public_response_source_checked": True, "all_four_rules_ready": True, "active_flow_revocation": True, "revoked_protocols": ["tcp", "udp"], "binding_fingerprint_matches_cloud": True, "owned_network_cleanup": True, "host_network_mutations": False}
        result["accounting"] = accounting
        result["carrier_address"] = carrier_address(carrier_port)
        result["carrier_observations"] = observed_carriers
        result["udp_same_tuple_reenable"] = True
        result["acl_tightening_closes_active_tcp"] = True
        (work / "result.json").write_text(json.dumps(result, indent=2))
        print(json.dumps(result, indent=2))
    finally:
        try:
            rules_have_status(set())
        except Exception:
            pass
        diagnostics = {}
        for where in (container, args.edge_container):
            diagnostics[where] = {}
            for name, command in (("routes", ("ip", "-4", "route", "show", "table", "all")), ("rules", ("ip", "-4", "rule", "show")), ("filter", ("iptables", "-t", "filter", "-nvL")), ("nat", ("iptables", "-t", "nat", "-nvL"))):
                diagnostics[where][name] = remote(*command, check=False, where=where).stdout
        (work / "network-diagnostics.json").write_text(json.dumps(diagnostics, indent=2))
        for where, path in reversed(container_paths):
            remote("pkill", "-TERM", "-f", path, check=False, where=where)
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
        for process in reversed(processes):
            try:
                process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        for log in logs:
            log.close()
        # The Agent's ownership record is retained if graceful cleanup failed,
        # so a later startup can recover its exact network objects safely.
        if remote_json(prefix + "/device/tun-network.json") is None:
            remote("rm", "-rf", "--", prefix, check=False)
        if remote_json(prefix + "/edge-state/tun-network.json", where=args.edge_container) is None:
            remote("rm", "-rf", "--", prefix, check=False, where=args.edge_container)
        if origin_container != container:
            remote("rm", "-rf", "--", prefix, check=False, where=origin_container)


if __name__ == "__main__":
    main()
