"""KeyGuard entrypoint."""

from __future__ import annotations

import logging
import os
import sys

logger = logging.getLogger("keyguard")


def main():
    """Application entry point."""
    # 1. Check dependencies
    from keyguard import check_dependencies

    check_dependencies()

    # 2. Check for display (Linux headless detection)
    if sys.platform.startswith("linux"):
        if not os.environ.get("DISPLAY") and not os.environ.get("WAYLAND_DISPLAY"):
            print(
                "ERROR: No display found ($DISPLAY / $WAYLAND_DISPLAY not set).\n"
                "KeyGuard requires a graphical environment.",
                file=sys.stderr,
            )
            sys.exit(1)

    # 3. Resolve data directory (with migration)
    from keyguard.paths import get_data_dir, migrate_legacy_directory

    data_dir = get_data_dir()
    data_dir.mkdir(parents=True, exist_ok=True)

    migrate_legacy_directory(data_dir)

    # 4. Initialise logging
    from keyguard.logging_setup import setup_secure_logging

    setup_secure_logging(data_dir)

    # 5. Platform hardening
    from keyguard.util.platform_harden import (
        apply_platform_hardening,
        validate_system_requirements,
    )

    try:
        validate_system_requirements()
    except SystemError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)

    apply_platform_hardening()

    # 6. KDF calibration on first run
    from keyguard.config import Config
    from keyguard.paths import get_vault_path

    if not Config.config_exists(data_dir):
        logger.info("First run — calibrating KDF...")
        try:
            Config.calibrate_kdf(data_dir)
        except RuntimeError as exc:
            logger.error("KDF calibration failed: %s", exc)
            # Import tk lazily to show error dialog
            try:
                import tkinter as tk
                from tkinter import messagebox as mb

                root = tk.Tk()
                root.withdraw()
                mb.showerror(
                    "System Error",
                    f"Could not calibrate the security system:\n\n{exc}\n\n"
                    "KeyGuard cannot run on this hardware.",
                )
                root.destroy()
            except Exception:
                pass
            sys.exit(1)

    # 7. Launch GUI
    try:
        from keyguard.ui.app import KeyGuardApp

        vault_path = get_vault_path(data_dir)
        app = KeyGuardApp(vault_path=vault_path, data_dir=data_dir)
        app.mainloop()
    except KeyboardInterrupt:
        logger.info("Application interrupted by user")
    except Exception as exc:
        logger.critical("Critical error: %s", exc)
        raise
    finally:
        try:
            if "app" in locals() and hasattr(app, "vault"):
                app.vault.close()
        except Exception:
            pass


if __name__ == "__main__":
    main()
