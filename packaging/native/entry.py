"""The program PyInstaller builds: the same `squidbrake` command pip installs."""
import sys

from pathlib import Path

from squidbrake.cli import main

if __name__ == "__main__":
    if Path(sys.executable).stem.lower() == "squidbrake-app":    # Windows: the tray app, no console window
        sys.argv[1:1] = ["app"]
    sys.exit(main())
