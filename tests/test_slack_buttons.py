"""Approve / Reject buttons in Slack: Squidbrake's Slack app sends the click to /v1/slack/actions, signed with the app's
signing secret; the button carries the event's one-event token."""
import hashlib
import hmac
import json
import sys
import time
from pathlib import Path
from urllib.parse import urlencode

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from test_server import BOSS, H, c, server  # noqa: E402,F401

SECRET = "8f742231b10e8888abcd99yyyzzz85a5"


def click(c, token, action="approve", secret=SECRET, ts=None, user="pulkit", response_url=None):
    payload = {"type": "block_actions", "user": {"id": "U1", "username": user},
               "actions": [{"action_id": action, "value": token}],
               "message": {"blocks": [{"type": "section", "text": {"type": "mrkdwn", "text": "*Approve x?*"}}]}}
    if response_url:
        payload["response_url"] = response_url
    body = urlencode({"payload": json.dumps(payload)})
    ts = str(int(time.time()) if ts is None else ts)
    sig = "v0=" + hmac.new(secret.encode(), f"v0:{ts}:{body}".encode(), hashlib.sha256).hexdigest()
    return c.post("/v1/slack/actions", content=body, headers={
        "Content-Type": "application/x-www-form-urlencoded", "X-Slack-Request-Timestamp": ts, "X-Slack-Signature": sig})


def held(c):
    d = c.post("/v1/events", headers=H, json={"name": "payments.refund", "input": {"charge": "ch_9", "amount": 5},
                                              "session_id": f"slack-{time.time_ns()}"}).json()
    assert d["decision"] == "review"
    return d["event_id"]


def test_buttons_decide_one_event(c, monkeypatch, tmp_path):
    rules = tmp_path / "slack.yaml"
    rules.write_text("default: review\n")
    monkeypatch.setattr(server, "policy", server.Policy(rules))
    eid = held(c)
    token = server.make_link_token(eid, "boss")
    assert click(c, token).status_code == 404                               # not set up: nothing to click
    assert c.put("/v1/settings", headers=BOSS, json={"slack_signing_secret": SECRET}).status_code == 200

    assert click(c, token, secret="wrong").status_code == 401               # not from Slack
    assert click(c, token, ts=int(time.time()) - 600).status_code == 401    # an old click, replayed
    sent = []

    async def fake_post(url, json=None, timeout=None):
        sent.append((url, json))
    monkeypatch.setattr(c.app.state.http, "post", fake_post)
    r = click(c, token, user="pulkit", response_url="https://hooks.slack.com/actions/T1/1/abc")
    assert r.status_code == 200
    d = c.get(f"/v1/events/{eid}/decision", headers=H).json()
    assert d["decision"] == "allow" and d["decided_by"] == "boss" and d["decision_note"] == "in Slack by @pulkit"
    for _ in range(50):                                                      # the message update runs in the background
        if sent:
            break
        time.sleep(0.05)
    assert sent and "Approved by @pulkit" in sent[0][1]["text"] and sent[0][1]["replace_original"] is True

    r = click(c, token, action="reject", response_url="https://evil.example/steal")   # already decided; never posts there
    assert r.status_code == 200 and len(sent) == 1
    eid2 = held(c)
    assert click(c, server.make_link_token(eid2, "boss"), action="reject").status_code == 200
    assert c.get(f"/v1/events/{eid2}/decision", headers=H).json()["decision"] == "deny"
    assert click(c, token[:-2] + "xx").status_code == 404                    # a forged token
    c.put("/v1/settings", headers=BOSS, json={"slack_signing_secret": ""})


def test_messages_get_buttons_and_the_manifest_points_here(c):
    blocks = server.slack_blocks("Approve x?", "agent wants <!channel>", "tok", "https://gw/a/tok", "2026-10-07T10:00Z")
    actions = next(b for b in blocks if b["type"] == "actions")["elements"]
    assert [a["action_id"] for a in actions] == ["approve", "reject", "open"] and actions[0]["value"] == "tok"
    assert "<!channel>" not in json.dumps(blocks)                            # agent text can't ping the channel
    m = c.get("/v1/slack/manifest", headers=BOSS).json()["manifest"]
    assert m["settings"]["interactivity"]["request_url"].endswith("/v1/slack/actions")
    assert c.get("/v1/slack/manifest", headers=H).status_code == 403
