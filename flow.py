"""
Setting Squidbrake up by hand is three commands (pip install squidbrake, squidbrake connect all, squidbrake).
Between them a terminal fills with questions, keys and per-agent lines, and people lose the thread: the one most
often forgotten is the last command, so the agents stay blocked. Every step prints the same short header saying
which step it is, and ends by naming the next one.
"""
from __future__ import annotations

import os

STEPS = ("install", "connect your agents", "start the gateway")
BAR = "-" * 72


def start_command() -> str:
    """How the gateway is started on this install (the pip command, or the clone's start script)."""
    if os.getenv("SQUIDBRAKE_CLI"):
        return "squidbrake"
    return "./start.sh   (Windows: start.bat)"


def doctor_command() -> str:
    return "squidbrake doctor" if os.getenv("SQUIDBRAKE_CLI") else "python connect.py doctor"


_shown: set[int] = set()


def header(step: int) -> None:
    """    ------------------------------------------------------------------------
         Squidbrake setup   step 2 of 3: connect your agents
         1 install (done)   2 connect (now)   3 start (next)
        ------------------------------------------------------------------------
    Once per process: the `squidbrake` command prints it before anything else (the usage-stats notice, see
    telemetry.py), and the step itself prints it when run on its own (python connect.py all)."""
    if step in _shown:
        return
    _shown.add(step)
    short = ("install", "connect", "start")
    state = lambda i: "done" if i < step else "now" if i == step else "next"
    trail = "   ".join(f"{i} {short[i - 1]} ({state(i)})" for i in range(1, 4))
    print(f"\n{BAR}\n Squidbrake setup   step {step} of 3: {STEPS[step - 1]}\n {trail}\n{BAR}")


def next_step(lines: list[str]) -> None:
    """The last thing a step prints: what to do now, boxed so it can't be missed."""
    print("\n" + BAR + "\n" + "\n".join(f" {line}" if line else "" for line in lines) + "\n" + BAR + "\n")
