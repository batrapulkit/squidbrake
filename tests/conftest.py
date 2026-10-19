import os
import tempfile

# Hooks run by the tests (in this process or as subprocesses) note their calls here, never in the real
# ~/.squidbrake/hooks.log, where they would look like real agents using Squidbrake to `squidbrake doctor`.
os.environ["SQUIDBRAKE_HOOKLOG"] = os.path.join(tempfile.mkdtemp(prefix="squidbrake-tests-"), "hooks.log")

# Never ask about or send usage stats from the tests.
os.environ["SQUIDBRAKE_TELEMETRY"] = "0"

# The hooks keep a copy of the rules' offline settings (offline.py): in a temporary folder, never the real ~/.squidbrake.
os.environ["SQUIDBRAKE_OFFLINE_DIR"] = tempfile.mkdtemp(prefix="squidbrake-offline-")

# `squidbrake doctor` tells the team's gateway which agents a computer has: never from the tests.
os.environ["SQUIDBRAKE_NO_INVENTORY"] = "1"

# The Team plan's license (license.py): the tests check its gates on purpose (test_license.py); everywhere else the
# Team features are on, whatever today's date is.
import license  # noqa: E402
license.GRACE_UNTIL = "9999-12-31"
