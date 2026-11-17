"""The program PyInstaller builds: the same `squidbrake` command pip installs."""
import os
import sys

from pathlib import Path

# The bundled OpenSSL looks for CA certificates where they were on the build machine, which isn't there on the user's
# Mac, so every HTTPS call fails with CERTIFICATE_VERIFY_FAILED. Point it at the certifi bundle we ship.
if getattr(sys, "frozen", False) and not os.environ.get("SSL_CERT_FILE"):
    import certifi
    os.environ["SSL_CERT_FILE"] = certifi.where()

from squidbrake.cli import main  # noqa: E402

if __name__ == "__main__":
    if Path(sys.executable).stem.lower() == "squidbrake-app":    # Windows: the tray app, no console window
        sys.argv[1:1] = ["app"]
    sys.exit(main())
