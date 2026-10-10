#!/usr/bin/env python3
"""
Runs on the Insights server, next to Docker: starts and removes the hosted pilot gateways the admin dashboard asks for.
The web app itself never touches Docker; this script asks it what to do and reports back.

  each hosted pilot  ->  a container sbp-<subdomain> from HOSTED_IMAGE, on the same Docker network as Caddy,
                         with its own data volume, served by Caddy at https://<subdomain>.<HOSTED_DOMAIN>
                         and joined to its pilot, so the dashboard shows its counts

Settings (environment): INSIGHTS_ADMIN_KEY, INSIGHTS_URL (http://127.0.0.1:8090), HOSTED_IMAGE, HOSTED_NETWORK,
PILOT_SERVER_INTERNAL (http://insights:8090), HOSTED_MEMORY (192m), HOSTED_CPUS (0.5: one busy pilot can't
slow down the pilots site and everyone else on this small server). Python 3.8+, standard library only.
"""
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request

INSIGHTS = os.environ.get("INSIGHTS_URL", "http://127.0.0.1:8090").rstrip("/")
KEY = os.environ.get("INSIGHTS_ADMIN_KEY", "")
IMAGE = os.environ.get("HOSTED_IMAGE", "ghcr.io/batrapulkit/squidbrake:latest")
NETWORK = os.environ.get("HOSTED_NETWORK", "tool-gateway_default")
PILOT_SERVER = os.environ.get("PILOT_SERVER_INTERNAL", "http://insights:8090")
MEMORY = os.environ.get("HOSTED_MEMORY", "192m")
CPUS = os.environ.get("HOSTED_CPUS", "0.5")
KEY_RE = re.compile(r"^\s*(admin|agent)\s+(gw_[A-Za-z0-9_\-]+)", re.M)


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


def api(path, body=None):
    req = urllib.request.Request(INSIGHTS + path, method="POST" if body is not None else "GET",
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"X-Admin-Key": KEY, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read() or b"{}")


def docker(*args, check=True):
    p = subprocess.run(["docker", *args], capture_output=True, text=True)
    if check and p.returncode:
        raise RuntimeError(f"docker {args[0]}: {(p.stderr or p.stdout).strip()[:300]}")
    return p.stdout.strip()


def state(name):
    return docker("inspect", "-f", "{{.State.Running}}", name, check=False) or None   # "true" | "false" | None


def start(p):
    name = "sbp-" + p["subdomain"]
    existing = state(name)
    if existing and p.get("keys_ready") is False:
        # Its keys never reached the start page (a first start that failed), so nobody can use it: start clean.
        log("recreating", name, "(its keys were never captured)")
        docker("rm", "-f", name, check=False)
        docker("volume", "rm", name, check=False)
        existing = None
    if existing == "false":
        docker("start", name)
    if existing:
        api("/v1/admin/provisioned", {"code": p["code"], "state": "running"})
        return
    log("starting", name)
    docker("pull", "-q", IMAGE, check=False)
    docker("run", "-d", "--name", name, "--network", NETWORK, "--restart", "unless-stopped", "--memory", MEMORY, "--cpus", CPUS,
           "--label", "squidbrake.hosted=1", "--label", f"squidbrake.pilot={p['code']}",
           "-v", f"{name}:/app/data", "-e", f"PUBLIC_URL={p['dashboard']}", "-e", "FORWARDED_ALLOW_IPS=*",
           "-e", "SQUIDBRAKE_PILOT_INTERVAL=120", "--log-opt", "max-size=20m", "--log-opt", "max-file=3", IMAGE)
    keys = {}
    for _ in range(60):                       # the first start prints the admin and agent keys once
        keys = dict(KEY_RE.findall(docker("logs", name, check=False) + "\n"))
        if "admin" in keys and "agent" in keys:
            break
        time.sleep(1)
    else:
        raise RuntimeError("the gateway didn't print its keys: " + docker("logs", "--tail", "20", name, check=False)[-300:])
    docker("exec", name, "python", "server.py", "pilot", "join", p["code"], "--server", PILOT_SERVER, "--yes")
    api("/v1/admin/provisioned", {"code": p["code"], "state": "running",
                                  "admin_key": keys["admin"], "agent_key": keys["agent"]})
    log("running", name, p["dashboard"])


def remove(p):
    name = "sbp-" + p["subdomain"]
    log("removing", name)
    docker("rm", "-f", name, check=False)
    docker("volume", "rm", name, check=False)
    api("/v1/admin/provisioned", {"code": p["code"], "state": "deleted"})


last_failure = {}   # code -> time: a failed setup is retried every 5 minutes, not every tick


def tick():
    for p in api("/v1/admin/provision")["pilots"]:
        try:
            if p["state"] == "deleting":
                remove(p)
            elif p["state"] == "failed" and time.time() - last_failure.get(p["code"], 0) < 300:
                continue
            elif p["state"] in ("requested", "failed") or (p["state"] == "running" and (
                    p.get("keys_ready") is False or state("sbp-" + p["subdomain"]) != "true")):
                start(p)
        except Exception as e:
            last_failure[p["code"]] = time.time()
            log("failed", p["code"], e)
            try:
                api("/v1/admin/provisioned", {"code": p["code"], "state": "failed", "error": str(e)[:900]})
            except Exception:
                pass


def main():
    if not KEY:
        sys.exit("INSIGHTS_ADMIN_KEY is not set")
    log("provisioner started; image", IMAGE, "network", NETWORK)
    while True:
        try:
            tick()
        except (urllib.error.URLError, OSError, ValueError) as e:
            log("insights not reachable:", e)
        time.sleep(10)


if __name__ == "__main__":
    main()
