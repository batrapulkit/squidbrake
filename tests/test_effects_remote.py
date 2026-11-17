"""What a database, terraform, AWS or Kubernetes command would take with it, measured before it's approved."""
import json
import sqlite3
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import effects  # noqa: E402


@pytest.fixture()
def shop(tmp_path):
    db = tmp_path / "shop.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE orders (id INTEGER PRIMARY KEY, created TEXT, status TEXT)")
    con.executemany("INSERT INTO orders (created, status) VALUES (?, 'paid')",
                    [("2024-06-01",)] * 3 + [("2026-01-01",)] * 7)
    con.commit()
    con.close()
    return tmp_path


def rows(db):
    con = sqlite3.connect(db)
    try:
        return con.execute("SELECT count(*) FROM orders").fetchone()[0]
    finally:
        con.close()


def test_sqlite_counts_rows_with_the_same_where_and_changes_nothing(shop):
    p = lambda sql: effects.predict(f'sqlite3 shop.db "{sql}"', str(shop))
    assert p("DELETE FROM orders WHERE created < '2025-01-01'") == ["Deletes 3 rows of 10 in orders (shop.db)"]
    assert p("DELETE FROM orders") == ["Deletes all 10 rows in orders (shop.db): there's no WHERE"]
    assert p("delete from orders o where o.id > 0") == ["Deletes all 10 rows in orders (shop.db): the WHERE matches every row"]
    assert p("UPDATE orders SET status = 'refunded' WHERE id <= 2") == ["Changes 2 rows of 10 in orders (shop.db)"]
    assert p("DROP TABLE orders") == ["Drops table orders (shop.db) with its 10 rows"]
    assert p("DELETE FROM orders WHERE id = 1; DROP TABLE IF EXISTS orders") == [
        "Deletes 1 row of 10 in orders (shop.db)", "Drops table orders (shop.db) with its 10 rows"]
    assert rows(shop / "shop.db") == 10                          # counting never changes anything


def test_sql_that_is_not_counted(shop):
    p = lambda sql: effects.predict(f'sqlite3 shop.db "{sql}"', str(shop))
    assert p("DELETE FROM orders WHERE id = load_extension('x')") == []     # side-effect functions never run
    assert p("DELETE FROM orders WHERE id IN (SELECT pg_sleep(60))") == []
    assert p("SELECT * FROM orders") == []
    assert effects.sql_targets("DELETE FROM orders USING users WHERE orders.uid = users.id") is None
    assert effects.sql_targets("UPDATE orders SET x = 1 FROM users WHERE orders.uid = users.id") is None
    assert effects.sql_targets("DELETE FROM a; DELETE FROM b; DELETE FROM c; DELETE FROM d") is None
    assert effects.sql_targets("DELETE FROM orders WHERE note = 'a; b' RETURNING id") == [("delete", "orders", "note = 'a; b'")]
    assert effects.sql_targets("TRUNCATE TABLE orders, public.items CASCADE") == [
        ("truncate", "orders", None), ("truncate", "public.items", None)]
    assert effects.sql_targets("UPDATE t SET note = 'where it was' WHERE id = 3") == [("update", "t", "id = 3")]


class FakeTools:
    """Stands in for psql, mysql, terraform, aws and kubectl: records each call and answers from a script."""
    def __init__(self, answers):
        self.answers, self.calls = answers, []

    def __call__(self, args, timeout, env=None, cwd=None):
        self.calls.append((args, env))
        line = " ".join(args)
        for key, answer in self.answers.items():
            if key in line:
                return answer
        return None, False


def test_psql_counts_in_a_read_only_session(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgres://app:pw@db.prod.internal:5432/shop")
    tools = FakeTools({"SELECT": ("3|10\n", True)})
    monkeypatch.setattr(effects, "_run", tools)
    sql = "DELETE FROM orders WHERE created_at < now() - interval '1 year'"
    assert effects.predict(f'psql "$DATABASE_URL" -c "{sql}"') == ["Deletes 3 rows of 10 in orders (shop on db.prod.internal)"]
    [(args, env)] = tools.calls
    assert args[:2] == ["psql", "postgres://app:pw@db.prod.internal:5432/shop"]
    assert args[-1] == ("SELECT (SELECT count(*) FROM orders WHERE created_at < now() - interval '1 year'), "
                        "(SELECT count(*) FROM orders)")
    assert not any("DELETE" in a for a in args)                 # the delete itself is never sent
    assert "default_transaction_read_only=on" in env["PGOPTIONS"] and "statement_timeout" in env["PGOPTIONS"]

    tools.calls.clear()
    tools.answers = {"SELECT": ("10\n", True)}
    assert effects.predict('PGPASSWORD=s psql -h db -d shop -tAc "TRUNCATE orders"') == ["Empties orders (shop on db): 10 rows"]
    [(args, env)] = tools.calls
    assert args[1:5] == ["-h", "db", "-d", "shop"] and env["PGPASSWORD"] == "s"


def test_mysql_counts_read_only(monkeypatch):
    tools = FakeTools({"SELECT": ("120\n", True)})
    monkeypatch.setattr(effects, "_run", tools)
    assert effects.predict('mysql -u root -psecret shop -e "DROP TABLE orders"') == ["Drops table orders with its 120 rows"]
    [(args, _)] = tools.calls
    assert "-psecret" in args and "shop" in args
    assert args[-1] == "SET SESSION TRANSACTION READ ONLY; SELECT /*+ MAX_EXECUTION_TIME(5000) */ count(*) FROM orders"


def test_terraform_destroy_names_what_holds_data(monkeypatch):
    tools = FakeTools({"workspace show": ("prod\n", True), "state list": (
        "aws_db_instance.main\naws_s3_bucket.assets\naws_iam_role.app\ndata.aws_caller_identity.me\n"
        "module.net.aws_vpc.this\n", True)})
    monkeypatch.setattr(effects, "_run", tools)
    assert effects.predict("terraform destroy -auto-approve") == [
        "Destroys 4 resources in workspace prod, including 2 that hold data: aws_db_instance.main, aws_s3_bucket.assets"]
    tools.calls.clear()
    effects.predict("terraform -chdir=infra destroy -target=aws_db_instance.main")
    assert ["terraform", "-chdir=infra", "state", "list", "aws_db_instance.main"] in [a for a, _ in tools.calls]


def test_terraform_apply_reads_the_plan(monkeypatch):
    plan = {"resource_changes": [
        {"address": "aws_db_instance.main", "mode": "managed", "change": {"actions": ["delete", "create"]}},
        {"address": "aws_s3_bucket.logs", "mode": "managed", "change": {"actions": ["delete"]}},
        {"address": "aws_iam_role.app", "mode": "managed", "change": {"actions": ["create"]}},
        {"address": "data.aws_ami.x", "mode": "data", "change": {"actions": ["read"]}}]}
    tools = FakeTools({"workspace show": ("default\n", True), " plan ": ("", True), "show -json": (json.dumps(plan), True)})
    monkeypatch.setattr(effects, "_run", tools)
    [msg] = effects.predict("terraform apply -auto-approve -var env=prod")
    assert msg.startswith("Destroys 1 resource, including 1 that holds data: aws_s3_bucket.logs")
    assert "Replaces (destroys, then creates again) 1 resource, including 1 that holds data: aws_db_instance.main" in msg
    planned = next(a for a, _ in tools.calls if "plan" in a)
    assert "-refresh=false" in planned and "-lock=false" in planned and "-var=env=prod" in planned

    tools.answers["show -json"] = (json.dumps({"resource_changes": [plan["resource_changes"][2]]}), True)
    assert effects.predict("terraform apply tfplan") == [
        "Destroys nothing: adds 1 and changes 0 resources (plan against the saved state)"]


def test_aws_s3_and_rds(monkeypatch):
    tools = FakeTools({"s3 ls": ("2026-01-01 00:00:00 10 a\n\nTotal Objects: 8200\n   Total Size: 15032385536\n", True),
                       "describe-db-instances": (json.dumps({"DBInstances": [
                           {"Engine": "postgres", "AllocatedStorage": 100, "DeletionProtection": False}]}), True)})
    monkeypatch.setattr(effects, "_run", tools)
    assert effects.predict("aws s3 rb s3://backups --force --profile prod") == [
        "Deletes the bucket and all 8,200 objects (14.0 GB) in s3://backups"]
    assert ["aws", "s3", "ls", "s3://backups", "--recursive", "--summarize", "--profile", "prod"] == tools.calls[0][0]
    assert effects.predict("aws s3 rm --recursive s3://backups/logs/")[0].startswith("Deletes all 8,200 objects")
    assert effects.predict("aws s3 rm s3://backups/one.txt") == []           # one object: nothing to count
    assert effects.predict("aws s3 rm --recursive --dryrun s3://backups/") == []

    tools.answers["s3 ls"] = ("2026-01-01 00:00:00 100 a\n2026-01-01 00:00:00 200 b\n", False)  # still listing
    assert effects.predict("aws s3 rb --force s3://huge") == ["Deletes the bucket and all 2+ objects (300 bytes+) in s3://huge"]

    assert effects.predict("aws rds delete-db-instance --db-instance-identifier prod-db --skip-final-snapshot") == [
        "Deletes RDS database prod-db (postgres, 100 GB); no final snapshot is taken (--skip-final-snapshot); "
        "its automated backups are removed with it (AWS's default)"]


def test_kubectl_delete_lists_what_matches(monkeypatch):
    tools = FakeTools({" get ": ("pod/web-1\npod/web-2\n", True), "current-context": ("prod-eks\n", True)})
    monkeypatch.setattr(effects, "_run", tools)
    assert effects.predict("kubectl delete pods -l app=web -n prod --grace-period 0 --force") == [
        "Deletes 2 Kubernetes objects in namespace prod on cluster prod-eks: pod/web-1, pod/web-2"]
    assert tools.calls[0][0] == ["kubectl", "get", "pods", "-l", "app=web", "-n", "prod", "-o", "name", "--ignore-not-found"]
    assert effects.predict("kubectl delete pod web-1 --dry-run=client") == []


def test_missing_tools_are_left_out(tmp_path, monkeypatch):
    monkeypatch.setattr(effects.shutil, "which", lambda name: None)
    assert effects.predict('psql -c "DROP TABLE orders"', str(tmp_path)) == []
    assert effects.predict("terraform destroy", str(tmp_path)) == []
    assert effects.predict("aws s3 rb s3://b --force", str(tmp_path)) == []
