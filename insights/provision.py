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
        # the end of the output says why (the start of `pilot join`'s is always the same disclosure text)
        said = (p.stdout.strip() + "\n" + p.stderr.strip()).strip()
        raise RuntimeError(f"docker {args[0]} (exit {p.returncode}): ...{said[-400:]}")
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
        give_license(name, p)
        api("/v1/admin/provisioned", {"code": p["code"], "state": "running"})
        return
    log("starting", name)
    docker("pull", "-q", IMAGE, check=False)
    docker("run", "-d", "--name", name, "--network", NETWORK, "--restart", "unless-stopped", "--memory", MEMORY, "--cpus", CPUS,
           "--label", "squidbrake.hosted=1", "--label", f"squidbrake.pilot={p['code']}",
           "-v", f"{name}:/app/data", "-e", f"PUBLIC_URL={p['dashboard']}", "-e", "FORWARDED_ALLOW_IPS=*",
           "-e", "SQUIDBRAKE_PILOT_INTERVAL=20",     # counts only go out when they changed: the start page sees the first action soon
           "-e", "SQUIDBRAKE_PILOT_HEARTBEAT=600",   # an idle hosted dashboard still checks in every 10 minutes
           # a signed-up plan: the gateway blocks and holds only with that plan's license (insights _license_for), and
           # only watches without one (server.py hosted_watch_only). A pilot set up by hand has no plan: as before
           *(["-e", f"SQUIDBRAKE_PLAN={p['plan']}"] if p.get("plan") else []),
           *(["-e", f"SQUIDBRAKE_TRIAL_ENDS={p['trial_ends']}"] if p.get("plan") == "free" and p.get("trial_ends") else []),
           "--log-opt", "max-size=20m", "--log-opt", "max-file=3", IMAGE)
    keys = {}
    for _ in range(60):                       # the first start prints the admin and agent keys once
        keys = dict(KEY_RE.findall(docker("logs", name, check=False) + "\n"))
        if "admin" in keys and "agent" in keys:
            break
        time.sleep(1)
    else:
        raise RuntimeError("the gateway didn't print its keys: " + docker("logs", "--tail", "20", name, check=False)[-300:])
    # The founder gets these keys once: make sure they open this very gateway before saying it's ready. If not,
    # this raises, keys_ready stays false, and the next tick recreates the gateway cleanly.
    for label in ("admin", "agent"):
        if not key_works(name, keys[label]):
            raise RuntimeError(f"the {label} key from the gateway's log doesn't open it")
    join(name, p["code"])
    give_license(name, p)
    api("/v1/admin/provisioned", {"code": p["code"], "state": "running",
                                  "admin_key": keys["admin"], "agent_key": keys["agent"]})
    log("running", name, p["dashboard"])


# Small Python snippets run inside the gateway's container: they don't import server.py, so they stay well under
# the container's memory cap next to the running gateway (a full `server.py` CLI could be killed there).
KEY_CHECK = ("import sys, time, urllib.request, urllib.error\n"
             "for _ in range(30):\n"
             "    try:\n"
             "        urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:8080/v1/me',"
             " headers={'X-Gateway-Key': sys.argv[1]}), timeout=5); sys.exit(0)\n"
             "    except urllib.error.HTTPError as e:\n"
             "        sys.exit(3 if e.code == 401 else 4)\n"
             "    except Exception:\n"
             "        time.sleep(2)\n"
             "sys.exit(5)\n")
JOIN = ("import sys\nfrom pathlib import Path\nimport pilot\nfrom squidbrake import __version__\n"
        "sys.exit(pilot.join(Path('/app/data'), sys.argv[1], sys.argv[2], True, __version__))\n")


def key_works(name, key):
    """True when the key opens the gateway (asked from inside its container, once it answers)."""
    try:
        docker("exec", name, "python", "-c", KEY_CHECK, key)
        return True
    except RuntimeError:
        return False


def join(name, code):
    """Share usage counts (pilot.py). Only counts depend on it, never the dashboard: tried 3 times, then left."""
    for attempt in range(3):
        try:
            docker("exec", name, "python", "-c", JOIN, code, PILOT_SERVER)
            return True
        except RuntimeError as e:
            log("pilot join failed", name, str(e)[-200:])
            time.sleep(5 * (attempt + 1))
    return False


# New keys written straight into keys.json the way server.py's KeyStore does (sha256 only, atomic, integrity noted):
# the full `server.py add-key` gets killed under the container's memory cap. shortcut: no audit-trail entry in the
# gateway for these keys, add one if a pilot needs it.
KEYS_IO = ("import hashlib, json, os, re, secrets, sys, time\nfrom pathlib import Path\nimport integrity\n"
           "d = Path('/app/data'); p = d / 'keys.json'; data = json.loads(p.read_text(encoding='utf-8'))\n"
           "def save():\n"
           "    tmp = p.with_suffix('.tmp'); tmp.write_text(json.dumps(data, indent=2), encoding='utf-8')\n"
           "    os.chmod(tmp, 0o600); os.replace(tmp, p); integrity.note_keys(d)\n")
NEW_KEYS = KEYS_IO + (
    "old = [n for n, k in data['keys'].items() if re.fullmatch(r'admin(-\\d{14})?', n) and k.get('kind') == 'person']\n"
    "now = time.strftime('%Y-%m-%dT%H:%M:%S.000Z', time.gmtime())\n"
    "new = {'admin': 'gw_' + secrets.token_urlsafe(24), 'agent': 'gw_' + secrets.token_urlsafe(24)}\n"
    "h = lambda s: hashlib.sha256(s.encode()).hexdigest()\n"
    "data['keys']['admin-' + sys.argv[1]] = {'sha256': h(new['admin']), 'kind': 'person', 'approver': True,"
    " 'roles': ['owner', 'admin'], 'created_at': now}\n"
    "data['keys']['agent-' + sys.argv[1]] = {'sha256': h(new['agent']), 'kind': 'agent', 'approver': False,"
    " 'roles': [], 'created_at': now}\n"
    "save(); print(json.dumps({'old': old, **new}))\n")
DROP_KEYS = KEYS_IO + "[data['keys'].pop(n, None) for n in sys.argv[1:]]; save()\n"
# One agent key for one computer signing in to the Squidbrake app (insights /v1/app/connect). Nothing else changes:
# the admin key and agents already connected keep working. Named after the computer, so the Team page shows it and
# it can be removed there on its own.
APP_KEY = KEYS_IO + (
    "name = sys.argv[1]; i = 2\n"
    "while name in data['keys']:\n    name = sys.argv[1] + '-' + str(i); i += 1\n"
    "key = 'gw_' + secrets.token_urlsafe(24)\n"
    "data['keys'][name] = {'sha256': hashlib.sha256(key.encode()).hexdigest(), 'kind': 'agent', 'approver': False,"
    " 'roles': [], 'created_at': time.strftime('%Y-%m-%dT%H:%M:%S.000Z', time.gmtime())}\n"
    "save(); print(json.dumps({'name': name, 'key': key}))\n")


def new_keys(p):
    """A founder lost their keys (admin page: New keys). A new admin key replaces the old ones, which stop working.
    The new agent key is added beside the old one, so agents already connected keep working. Both are checked, then
    shown once more on the founder's start page."""
    name = "sbp-" + p["subdomain"]
    try:
        made = json.loads(docker("exec", name, "python", "-c", NEW_KEYS, time.strftime("%Y%m%d%H%M%S")))
    except (RuntimeError, ValueError):
        raise RuntimeError("couldn't make new keys in the gateway") from None   # its output may hold a key: not stored
    for label in ("admin", "agent"):
        if not key_works(name, made[label]):
            raise RuntimeError(f"the new {label} key doesn't open the gateway")
    if made["old"]:
        docker("exec", name, "python", "-c", DROP_KEYS, *made["old"])
    api("/v1/admin/provisioned", {"code": p["code"], "state": "running",
                                  "admin_key": made["admin"], "agent_key": made["agent"]})
    log("new keys", name)


def app_key_name(device):
    """'Karishma's MacBook Air' -> 'app-karishmas-macbook-air' (a key name the gateway accepts)."""
    slug = re.sub(r"[^a-z0-9]+", "-", device.lower()).strip("-")[:40].strip("-")
    return "app-" + (slug or "computer")


def app_keys(p):
    """Computers signing in to the Squidbrake app whose start-page agent key was already taken: one key each."""
    name = "sbp-" + p["subdomain"]
    for link in p.get("app_links") or []:
        if time.time() - last_failure.get(link["id"], 0) < 60:
            continue
        try:
            made = json.loads(docker("exec", name, "python", "-c", APP_KEY, app_key_name(link["device"])))
        except (RuntimeError, ValueError):
            last_failure[link["id"]] = time.time()
            api("/v1/admin/app-key", {"id": link["id"], "error": "couldn't make a key in the gateway"})
            continue
        if not key_works(name, made["key"]):
            last_failure[link["id"]] = time.time()
            docker("exec", name, "python", "-c", DROP_KEYS, made["name"], check=False)
            api("/v1/admin/app-key", {"id": link["id"], "error": "the new key doesn't open the gateway"})
            continue
        api("/v1/admin/app-key", {"id": link["id"], "key": made["key"], "key_name": made["name"]})
        log("app key", name, made["name"])


_licensed = {}   # gateway name -> the license it was given (the server runs an older Python)


# What `server.py license set` does, without loading the whole gateway: under the container's memory cap that second
# copy of the gateway got the container OOM-killed, so it restarted, the license never counted as set, and the next
# tick tried again (a restart loop on every licensed pilot). Unchanged license: nothing written.
LICENSE_SET = ("import sys\nfrom pathlib import Path\nimport license\n"
               "t = sys.argv[1].strip(); f = Path('/app/data') / license.FILE\n"
               "if not license.check(t):\n    sys.exit('that license is not valid')\n"
               "if not f.exists() or f.read_text(encoding='utf-8').strip() != t:\n"
               "    f.write_text(t + '\\n', encoding='utf-8')\n")


def give_license(name, p):
    """A hosted gateway has the Team plan: its license goes into its data folder (once, and again when renewed)."""
    if p.get("license") and _licensed.get(name) != p["license"]:
        try:
            docker("exec", name, "python", "-c", LICENSE_SET, p["license"])
            _licensed[name] = p["license"]
        except Exception as e:      # an older gateway without `license`: tried again until it's upgraded
            log("license not set yet", name, str(e)[:120])


def remove(p):
    name = "sbp-" + p["subdomain"]
    log("removing", name)
    docker("rm", "-f", name, check=False)
    docker("volume", "rm", name, check=False)
    api("/v1/admin/provisioned", {"code": p["code"], "state": "deleted"})


def sleep(p):
    """An unused dashboard put to sleep (insights _reclaim_unused): stop its container to free the memory, and keep
    the container, its data volume and its logs. `--restart unless-stopped` keeps a stopped one stopped across
    reboots; waking it (state requested) is start(), which finds it stopped and starts it again as it was."""
    name = "sbp-" + p["subdomain"]
    if state(name) == "true":
        log("sleeping", name)
        docker("stop", "-t", "20", name, check=False)   # tried again next round if it didn't stop
        _licensed.pop(name, None)       # set again (or checked) when it wakes


last_failure = {}   # code -> time: a failed setup is retried every 5 minutes, not every tick


def tick():
    for p in api("/v1/admin/provision")["pilots"]:
        try:
            if p["state"] == "deleting":
                remove(p)
            elif p["state"] == "sleeping":
                sleep(p)
            elif p["state"] == "failed" and time.time() - last_failure.get(p["code"], 0) < 300:
                continue
            elif p["state"] in ("requested", "failed") or (p["state"] == "running" and (
                    p.get("keys_ready") is False or state("sbp-" + p["subdomain"]) != "true")):
                start(p)
            elif p["state"] == "running" and p.get("rekey"):
                new_keys(p)
            elif p["state"] == "running" and p.get("app_links"):
                app_keys(p)
            elif p["state"] == "running":            # a healthy gateway: only its license, when new or renewed
                give_license("sbp-" + p["subdomain"], p)
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
