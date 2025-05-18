# Secure Password Generator GUI

![license](https://img.shields.io/badge/license-Apache%202.0-blue.svg) ![python](https://img.shields.io/badge/python-3.8%2B-blue)

A cross‑platform desktop application (Tkinter + ttkbootstrap) that generates cryptographically strong passwords, copies them to the clipboard, optionally saves them to a local file, and offers one‑click export as a standalone **.exe** via PyInstaller.

> **Why?** Online random‑password sites leak entropy to the network and many GUI generators still rely on `random`. This project uses Pythonʼs [`secrets`](https://docs.python.org/3/library/secrets.html) module for true OS‑level randomness and keeps everything local.

---

## ✨ Features

* **Cryptographically secure RNG** (`secrets.choice`)
* **Theme switcher** – Dark (default) ↔ Light in real‑time
* **Strength bar** – visual score (0‑100) based on length and class diversity
* **Clipboard & auto‑copy** – plus a dedicated *Copy* button
* **Optional local storage** – passwords saved plain‑text to `~/Documents/Senha/senha.txt` (disabled by default)
* **One‑file build** – `pyinstaller --onefile --noconsole`
* Runs on **Windows 10/11, macOS 12+, Linux (X11/Wayland)**

![screenshot dark](docs/screenshot-dark.png)

---

## 📦 Getting Started

### Prerequisites

* Python ≥ 3.8 ([https://www.python.org/downloads/](https://www.python.org/downloads/))
* `pip install ttkbootstrap`

```bash
# clone the repo
$ git clone https://github.com/youruser/secure-pass-gen.git
$ cd secure-pass-gen

# (optional) create a virtual env
$ python -m venv .venv && .\.venv\Scripts\activate  # Windows

# install dependencies
$ pip install -r requirements.txt   # only ttkbootstrap + pyinstaller for build
```

### Run in dev mode

```bash
python src/passgen_gui.py
```

### Build a standalone *.exe* (Windows)

```bash
pyinstaller --onefile --noconsole --icon=assets/key.ico src/passgen_gui.py
```

Output will be in `dist/passgen_gui.exe`.

> See [`docs/BUILD.md`](docs/BUILD.md) for advanced options (icons, UPX, splash, hidden‑imports).

---

## 🛠️ Usage

1. Choose the **length** (default 16).
2. Select the **character set**: numbers, letters, alphanum, or *all*.
3. *(Optional)* toggle **Save to file** and enter an application label.
4. Click **Generate** – the password is shown, copied to clipboard, and the strength bar updates.
5. **Copy** again later or hit **Clear** to reset the form.

---

## 🔧 Configuration

All user data is stored locally:

| Path                          | Purpose                   | Created                             |  Secure?                                  |
| ----------------------------- | ------------------------- | ----------------------------------- | ----------------------------------------- |
| `~/Documents/Senha/senha.txt` | password log (plain‑text) | When *Salvar em arquivo* is checked | **No** – disable if security is a concern |

If you need encrypted storage, integrate [`cryptography.Fernet`](https://cryptography.io/) or a secrets‑manager.

---

## 🤝 Contributing

1. Fork the project
2. Create your feature branch (`git checkout -b feature/awesome`)
3. Commit your changes (`git commit -m 'feat: add awesome'`)
4. Push to the branch (`git push origin feature/awesome`)
5. Open a pull request

All PRs must pass **pre‑commit** hooks (`black`, `flake8`, `isort`) and include unit tests.

---

## 📜 License

Distributed under the [Apache 2.0 License](LICENSE). See [`LICENSE`](LICENSE) for more information.
---

## 🙏 Acknowledgements

* [Tkinter](https://docs.python.org/3/library/tkinter.html) – native GUI toolkit
* [ttkbootstrap](https://github.com/israel-dryer/ttkbootstrap) – modern themes + widgets
* [PyInstaller](https://www.pyinstaller.org/) – freezing Python apps
* [shields.io](https://shields.io/) – README badges
