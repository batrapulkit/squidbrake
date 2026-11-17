"""The dashboard's enforce / observe switch (PUT /v1/policy/mode): observe lets a held action through, only recorded."""
from test_server import BOSS, H, c, server  # noqa: F401
from test_team_features import shipped  # noqa: F401


def test_observe_toggle_lets_held_actions_through_and_back(c, shipped):
    refund = {"name": "payments.refund", "source": "claude-code", "input": {"charge": "ch_1", "amount": 500}}
    assert c.post("/v1/events", headers=H, json=refund).json()["decision"] == "review"

    r = c.put("/v1/policy/mode", headers=BOSS, json={"mode": "observe"}).json()
    assert r["mode"] == "shadow" and server.policy.mode == "shadow"
    assert "mode: shadow" in server.policy.path.read_text()
    d = c.post("/v1/events", headers=H, json=refund).json()
    assert d["decision"] == "allow" and "Shadow mode" in d["reason"]

    assert c.put("/v1/policy/mode", headers=BOSS, json={"mode": "enforce"}).json()["mode"] == "enforce"
    assert c.post("/v1/events", headers=H, json=refund).json()["decision"] == "review"


def test_docker_keeps_rules_on_the_data_volume(monkeypatch, tmp_path):
    # the image's /app/rules.yaml is root-owned and replaced by each new image; the volume copy is what gets edited
    (tmp_path / "rules.yaml").write_text("mode: enforce\nrules: []\n")
    monkeypatch.setattr(server, "BASE_DIR", tmp_path)
    monkeypatch.setenv("IN_DOCKER", "1")
    path = server._default_rules()
    assert path == tmp_path / "data" / "rules.yaml" and path.read_text() == "mode: enforce\nrules: []\n"
    path.write_text("mode: shadow\nrules: []\n")      # switched from the dashboard, then a new image starts
    assert server._default_rules().read_text() == "mode: shadow\nrules: []\n"


def test_mode_toggle_needs_admin_and_a_real_mode(c, shipped):
    assert c.put("/v1/policy/mode", headers=H, json={"mode": "observe"}).status_code in (401, 403)
    assert c.put("/v1/policy/mode", headers=BOSS, json={"mode": "off"}).status_code == 400
    assert server.policy.mode == "enforce"
