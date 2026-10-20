#!/usr/bin/env python3
"""Own an isolated real-cloud browser QA database and process (Windows host).

Requires Python 3, OpenSSL, SSH access to the dedicated test MySQL container and
an existing local forwarded port. Browser actions use Playwright CLI separately.
No production API, fixture backend or DNS resolver override is installed.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import subprocess
import time
import urllib.request
import uuid


ROOT = Path(__file__).resolve().parents[1]


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2), encoding="utf-8")
    path.chmod(0o600)


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def ssh(args, command, input=None):
    return subprocess.run(
        ["ssh", "-i", args.ssh_key, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", args.ssh_target, command],
        input=input, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        check=True,
    ).stdout


def sql(args, statement):
    # MYSQL_ROOT_PASSWORD is expanded inside the dedicated disposable container.
    # Neither the secret nor a DSN is included in process arguments or results.
    return ssh(args, "docker exec -i drafrp-test-mysql sh -c 'export MYSQL_PWD=\"$MYSQL_ROOT_PASSWORD\"; exec mysql --user=root --batch --skip-column-names'", statement)


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def launch(work):
    with (work / "cloud.log").open("ab") as log:
        p = subprocess.Popen([str(work / "cloud.exe"), "--config", str(work / "cloud.json")], stdout=log, stderr=log, creationflags=subprocess.CREATE_NO_WINDOW)
    state = read_json(work / "state.json")
    state["pid"] = p.pid
    write_json(work / "state.json", state)
    for _ in range(100):
        if p.poll() is not None:
            raise RuntimeError("owned cloud stopped before ready; inspect its cloud.log")
        try:
            if urllib.request.urlopen(state["url"] + "/readyz", timeout=0.5).status == 204:
                return state
        except OSError:
            time.sleep(0.1)
    raise TimeoutError("owned cloud did not become ready")


def stop_process(work, state):
    # Check the actual image path before terminating the PID from our state file.
    path = str(work / "cloud.exe").replace("'", "''")
    code = f"$ErrorActionPreference = 'Stop'; $p = Get-Process -Id {int(state['pid'])} -ErrorAction SilentlyContinue; if ($p) {{ if ($p.Path -ne '{path}') {{ throw 'PID no longer belongs to this QA run' }}; Stop-Process -Id $p.Id -Force; $p.WaitForExit() }}; exit 0"
    subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", code], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["start", "restart", "upgrade", "inspect", "stop"])
    parser.add_argument("--work-dir", required=True)
    parser.add_argument("--cloud-binary", default=str(ROOT / ".runtime" / "browser-e2e-cloud.exe"))
    parser.add_argument("--ssh-target", default="<redacted SSH target>")
    parser.add_argument("--ssh-key", default=str(Path.home() / ".ssh" / "id_codex_ubuntu"))
    parser.add_argument("--remote-dsn", default="<redacted test workspace>/<redacted DSN file>")
    parser.add_argument("--mysql-port", type=int, default=33089)
    parser.add_argument("--with-captcha", action="store_true", help="enable real image captcha for a new QA run")
    args = parser.parse_args()
    work = Path(args.work_dir).resolve()
    if not work.is_relative_to((ROOT / ".runtime").resolve()) or work == (ROOT / ".runtime").resolve():
        parser.error("work-dir must be a dedicated child of this repository's .runtime")
    if args.action == "start":
        work.mkdir(mode=0o700, parents=True, exist_ok=False)
        db = "drafrp_browser_e2e_" + uuid.uuid4().hex
        dsn = ssh(args, "cat " + args.remote_dsn).strip()
        replaced, count = re.subn(r"@tcp\([^)]*\)/[^?]*", f"@tcp(127.0.0.1:{args.mysql_port})/{db}", dsn)
        if count != 1:
            raise ValueError("dedicated DSN did not have one TCP database endpoint")
        sql(args, f"CREATE DATABASE `{db}`;\n")
        state = {"database": db, "url": f"http://127.0.0.1:{free_port()}", "pid": 0, "scope": "drafrp-browser-e2e-owned", "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
        write_json(work / "state.json", state)
        credentials = {"username": "browser-" + secrets.token_hex(4), "password": secrets.token_urlsafe(24)}
        write_json(work / "credentials.json", credentials)
        config = {"listen": state["url"].removeprefix("http://"), "mysql_dsn": replaced, "storage_key": base64.b64encode(secrets.token_bytes(32)).decode(), "admin_username": credentials["username"], "admin_password": credentials["password"], "snapshot_ttl": "10s", "captcha_disabled": not args.with_captcha}
        write_json(work / "cloud.json", config)
        shutil.copy2(args.cloud_binary, work / "cloud.exe")
        state = launch(work)
        subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(work / "agent-key.pem")], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        (work / "agent-key.pem").chmod(0o600)
        public_der = subprocess.run(["openssl", "pkey", "-in", str(work / "agent-key.pem"), "-pubout", "-outform", "DER"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout
        if not public_der.startswith(bytes.fromhex("302a300506032b6570032100")) or len(public_der) != 44:
            raise ValueError("unexpected Ed25519 SPKI encoding")
        public = public_der[-32:]
        req = urllib.request.Request(state["url"] + "/api/v1/runtime/client/bind", data=json.dumps({"name": "Browser E2E Agent", "public_key": base64.b64encode(public).decode()}).encode(), headers={"Content-Type": "application/json"})
        binding = json.load(urllib.request.urlopen(req, timeout=5))
        write_json(work / "binding.json", binding)
        public_state = {**state, "binding_url": binding["verification_uri"], "public_key_fingerprint": hashlib.sha256(base64.b64encode(public)).hexdigest()}
        write_json(work / "public.json", public_state)
        print(json.dumps(public_state))
        return
    state = read_json(work / "state.json")
    db = state["database"]
    if state.get("scope") != "drafrp-browser-e2e-owned" or not re.fullmatch(r"drafrp_browser_e2e_[a-f0-9]{32}", db):
        raise ValueError("state does not identify an owned disposable QA database")
    if args.action in ("restart", "upgrade"):
        if args.action == "upgrade":
            binary = Path(args.cloud_binary).resolve(strict=True)
            if binary == (work / "cloud.exe").resolve():
                raise ValueError("upgrade source must differ from the owned running executable")
        stop_process(work, state)
        if args.action == "upgrade":
            shutil.copy2(binary, work / "cloud.exe")
            config = read_json(work / "cloud.json")
            config.pop("build_id", None) # Exercise the release binary's real upgrade identity.
            write_json(work / "cloud.json", config)
        launch(work)
        print(json.dumps({"restarted": True, "upgraded": args.action == "upgrade", "url": state["url"]}))
    elif args.action == "inspect":
        print(sql(args, f"SELECT 'devices', COUNT(*) FROM `{db}`.devices UNION ALL SELECT 'rules', COUNT(*) FROM `{db}`.rules UNION ALL SELECT 'templates', COUNT(*) FROM `{db}`.acl_templates UNION ALL SELECT 'domains', COUNT(*) FROM `{db}`.domains;\n"), end="")
    elif args.action == "stop":
        stop_process(work, state)
        sql(args, f"DROP DATABASE `{db}`;\n")
        for name in ["credentials.json", "cloud.json", "binding.json", "agent-key.pem", "registration-binding.json", "registration-agent-key.pem"]:
            (work / name).unlink(missing_ok=True)
        state.update({"pid": 0, "cleaned": True})
        write_json(work / "state.json", state)
        print(json.dumps({"owned_process_stopped": True, "owned_database_dropped": True, "credentials_removed": True}))


if __name__ == "__main__":
    main()
