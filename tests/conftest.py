import os
import tempfile

# Hooks run by the tests (in this process or as subprocesses) note their calls here, never in the real
# ~/.squidbrake/hooks.log, where they would look like real agents using Squidbrake to `squidbrake doctor`.
os.environ["SQUIDBRAKE_HOOKLOG"] = os.path.join(tempfile.mkdtemp(prefix="squidbrake-tests-"), "hooks.log")

# Never ask about or send usage stats from the tests.
os.environ["SQUIDBRAKE_TELEMETRY"] = "0"

# The hooks keep a copy of the rules' offline settings (offline.py): in a temporary folder, never the real ~/.squidbrake.
os.environ["SQUIDBRAKE_OFFLINE_DIR"] = tempfile.mkdtemp(prefix="squidbrake-offline-")

# The agents a person took out (connect.py remember_off): in a temporary folder, never the real ~/.squidbrake.
os.environ["SQUIDBRAKE_AGENTS_OFF"] = os.path.join(tempfile.mkdtemp(prefix="squidbrake-off-"), "agents-off.json")

# setup's "Squidbrake dashboard" icon: never on the real desktop (test_auto_connect.py makes one in a temporary home).
os.environ["SQUIDBRAKE_NO_SHORTCUT"] = "1"

# `squidbrake doctor` tells the team's gateway which agents a computer has: never from the tests.
os.environ["SQUIDBRAKE_NO_INVENTORY"] = "1"

# The start page's App tab asks GitHub whether the newest release has the app (insights app_downloads): never from
# the tests (test_pilot.py checks it with a stand-in GitHub).
os.environ["INSIGHTS_APP_DOWNLOADS"] = "off"

# The Team plan's license (license.py): the tests check its gates on purpose (test_license.py); everywhere else the
# Team features are on, whatever today's date is.
import sys  # noqa: E402
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))   # plain `pytest` (CI) doesn't add the repo
import license  # noqa: E402
license.GRACE_UNTIL = "9999-12-31"
