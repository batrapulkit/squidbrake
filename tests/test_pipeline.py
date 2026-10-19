"""The admin's Pipeline: contacts sync in from a file, hand edits stick, and the doors stay locked."""
import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "insights"))
os.environ.setdefault("INSIGHTS_DB", str(Path(tempfile.mkdtemp()) / "insights.db"))
os.environ.setdefault("INSIGHTS_ADMIN_KEY", "admin-test-key")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

ADMIN = {"X-Admin-Key": os.environ["INSIGHTS_ADMIN_KEY"]}


@pytest.fixture(scope="module")
def c():
    import app as insights_app
    with TestClient(insights_app.app) as client:
        yield client


def contact(c, cid):
    return next(x for x in c.get("/v1/admin/contacts", headers=ADMIN).json()["contacts"] if x["id"] == cid)


def test_contacts_need_the_admin(c):
    assert c.get("/v1/admin/contacts").status_code == 401
    assert c.post("/v1/admin/contacts/import", json={"contacts": []}).status_code == 401
    assert c.post("/v1/admin/contacts/read", json={"text": "x" * 30}).status_code == 401


def test_import_creates_and_updates_without_duplicating_the_log(c):
    file = {"contacts": [{"name": "Test Person", "org": "Acme", "lane": "US platform buyers", "stage": "Live call, Oct 20",
                          "signal": "for", "said": "Agents touch prod.", "next": "Send LOI", "update": "Call on Oct 20"}]}
    assert c.post("/v1/admin/contacts/import", headers=ADMIN, json=file).json()["new"] == 1
    again = c.post("/v1/admin/contacts/import", headers=ADMIN, json=file).json()
    assert again["new"] == 0 and again["changed"] == 0 and again["same"] == 1
    p = contact(c, "test-person")
    assert p["stage"] == "Live call, Oct 20" and p["signal"] == "for"
    assert [x["text"] for x in p["log"]].count("Call on Oct 20") == 1

    file["contacts"][0].update(stage="Pilot agreed", update="Said yes to a pilot")
    assert c.post("/v1/admin/contacts/import", headers=ADMIN, json=file).json()["changed"] == 1
    p = contact(c, "test-person")
    assert p["stage"] == "Pilot agreed" and p["log"][0]["text"] == "Said yes to a pilot"


def test_a_hand_edit_is_not_overwritten_by_the_sync(c):
    r = c.post("/v1/admin/contacts", headers=ADMIN, json={"id": "test-person", "stage": "Signed LOI", "loi": 1})
    assert r.json()["ok"]
    sync = {"contacts": [{"name": "Test Person", "stage": "Pilot agreed", "next": "Book feedback call"}]}
    c.post("/v1/admin/contacts/import", headers=ADMIN, json=sync)
    p = contact(c, "test-person")
    assert p["stage"] == "Signed LOI" and p["loi"] == 1           # kept: edited by hand
    assert p["next"] == "Book feedback call"                       # not edited by hand: the sync still updates it
    assert "stage" in p["locked"]


def test_bad_values_are_cleaned_and_totals_add_up(c):
    c.post("/v1/admin/contacts/import", headers=ADMIN, json={"contacts": [
        {"name": "Intro Only", "talked": 0, "signal": "nonsense", "last_contact": "yesterday", "monthly": "50"},
        {"stage": "no name"}, "not a dict"]})
    p = contact(c, "intro-only")
    assert p["signal"] == "pending" and p["last_contact"] is None and p["monthly"] == 50
    t = c.get("/v1/admin/contacts", headers=ADMIN).json()["totals"]
    assert t["intros"] >= 1 and t["monthly"] >= 50 and t["loi"] >= 1


def test_a_new_contact_needs_a_name_and_delete_works(c):
    assert c.post("/v1/admin/contacts", headers=ADMIN, json={"stage": "x"}).status_code == 400
    c.post("/v1/admin/contacts", headers=ADMIN, json={"name": "Gone Soon"})
    assert c.delete("/v1/admin/contacts/gone-soon", headers=ADMIN).json()["ok"]
    assert c.delete("/v1/admin/contacts/gone-soon", headers=ADMIN).status_code == 404


def test_sync_and_reader_say_what_is_missing(c):
    d = c.get("/v1/admin/contacts", headers=ADMIN).json()
    assert d["sync"]["configured"] is False and d["reader"] is False
    r = c.post("/v1/admin/contacts/pull", headers=ADMIN)
    assert r.status_code == 502 and "PIPELINE_REPO" in r.json()["detail"]
    r = c.post("/v1/admin/contacts/read", headers=ADMIN, json={"text": "We talked about agents for a while today."})
    assert r.status_code == 502 and "OPENAI_API_KEY" in r.json()["detail"]


def test_the_sync_file_example_imports_cleanly():
    import pipeline
    import sqlite3
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    db.executescript(pipeline.SCHEMA)
    data = json.loads((ROOT / "insights" / "contacts.example.json").read_text())
    counts = pipeline.import_file(db, data, "sync", "2026-10-20T00:00:00+00:00")
    assert counts["new"] == len(data["contacts"]) and counts["skipped"] == 0
