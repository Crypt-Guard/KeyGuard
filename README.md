# KeyGuard – Secure Password Manager

![license](https://img.shields.io/badge/license-Apache%202.0-blue.svg) ![python](https://img.shields.io/badge/python-3.9%2B-blue)

KeyGuard is a cross-platform desktop password manager built with Python.
It uses Argon2id key derivation, ChaCha20-Poly1305 AEAD encryption, and secure memory handling to protect your passwords.

---

## Features

- **Argon2id + ChaCha20-Poly1305** — industry-standard KDF and AEAD
- **Self-descriptive vault header** — KDF parameters stored in the vault (v4 format)
- **Configurable KDF profiles** — `compat` (64 MiB), `balanced` (256 MiB), `high` (512 MiB)
- **Secure memory** — mlock/VirtualLock, multi-pass wipe, key obfuscation
- **Cross-platform** — Windows + Linux (XDG-compliant directories via `platformdirs`)
- **Auto-migration** — v3 vaults and legacy `~/.keyguard3` directories migrate automatically
- **Clipboard safety** — auto-clears clipboard after 15 seconds
- **GUI** — Tkinter/ttkbootstrap with vault viewer, search, drag-and-drop reorder

---

## Getting Started

### Requirements

- Python 3.9+
- Dependencies: `argon2-cffi`, `cryptography`, `psutil`, `ttkbootstrap`, `platformdirs`

### Install

```bash
git clone https://github.com/Crypt-Guard/KeyGuard.git
cd KeyGuard

# (Optional) virtual environment
python -m venv .venv
source .venv/bin/activate   # Linux/macOS
# .venv\Scripts\activate    # Windows

# Install
pip install -e ".[dev]"
```

### Run

```bash
python -m keyguard
# or, after pip install:
keyguard
```

### Run Tests

```bash
pytest tests/ -v
```

### Lint / Format

```bash
pip install ruff black
ruff check keyguard/ tests/
black --check keyguard/ tests/
```

---

## Project Structure

```
keyguard/
  __init__.py              # version, dependency check
  main.py                  # entrypoint
  config.py                # Config, KDF profiles, config.ini I/O
  paths.py                 # cross-platform dirs, legacy migration
  logging_setup.py         # secure logging
  crypto/
    engine.py              # CryptoEngine, PasswordGenerator
    formats.py             # VaultHeaderV3/V4, constants
  storage/
    backend.py             # atomic writes, backup, locking
  vault/
    models.py              # VaultEntry
    manager.py             # VaultManager, v3→v4 migration
  ui/
    dialogs.py             # SecurePasswordDialog
    app.py                 # KeyGuardApp
    views.py               # UI builders
  util/
    memory.py              # SecureMemory, KeyObfuscator, TimedExposure
    rate_limit.py          # RateLimiter
    platform_harden.py     # OS hardening (no debug detection)
tests/
  test_crypto.py
  test_formats.py
  test_storage.py
  test_vault.py
  test_migration.py
  test_memory.py
  test_password_gen.py
  test_rate_limit.py
```

---

## Data Directories

| OS      | Location                                  |
|---------|-------------------------------------------|
| Linux   | `~/.local/share/KeyGuard/`                |
| Windows | `%LOCALAPPDATA%\CryptGuard\KeyGuard\`     |
| macOS   | `~/Library/Application Support/KeyGuard/` |

Legacy `~/.keyguard3` directories are auto-migrated on first run.

---

## Vault Migration (v3 → v4)

When KeyGuard opens a v3 vault (`KG3` magic):

1. Decrypts using config.ini KDF params as fallback
2. Creates a timestamped backup (`.v3backup-<timestamp>`)
3. Re-saves in v4 format with KDF parameters embedded in the header
4. Future opens use the self-descriptive v4 header (no external config dependency)

---

## Security & Privacy

- All data stored locally, never transmitted
- No debugger detection or kill switches (removed in v4.0)
- OS hardening: DEP enforcement (Windows), core dump disable (Linux), DLL restriction
- Secrets never logged; log rotation with restricted permissions

| File                   | Purpose                | Encrypted |
|------------------------|------------------------|-----------|
| `vault.kg3`            | Password vault         | ChaCha20-Poly1305 |
| `vault.kg3.backup`     | Automatic backup       | ChaCha20-Poly1305 |
| `keyguard.log`         | Application log        | No (no secrets) |
| `config.ini`           | KDF calibration result | No |

---

## License

[Apache 2.0](LICENSE)
