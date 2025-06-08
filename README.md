### 🚀 **README.md**

# 🔒 KeyGuard – Secure Password Manager

![license](https://img.shields.io/badge/license-Apache%202.0-blue.svg) ![python](https://img.shields.io/badge/python-3.8%2B-blue)

KeyGuard is a cross-platform, highly secure desktop application designed for managing and safeguarding your passwords. Built with Python's robust cryptography and security best practices, KeyGuard provides seamless encryption, memory protection, and advanced zeroization techniques.

---

## ✨ Key Features

* **Cryptographically Strong Encryption** – Uses Argon2id and AES-GCM to securely encrypt your data.
* **Secure Memory Handling** – Implements zeroization and obfuscation techniques to ensure passwords and keys aren't exposed in memory.
* **Master Password Management** – Allows secure changing of the master password, automatically re-encrypting the vault.
* **Detailed Password Viewer** – Password masking by default with secure toggling visibility.
* **Interactive Menu** – User-friendly interface with built-in password strength analysis.
* **Portable Executable** – Easily build and distribute as a single-file binary via PyInstaller.

---

## 📦 Getting Started

### Requirements

* Python 3.8 or higher ([download](https://www.python.org/downloads/))
* Dependencies: `ttkbootstrap`, `cryptography`, `argon2-cffi`

```bash
# Clone repository
git clone [https://github.com/youruser/keyguard.git](https://github.com/Crypt-Guard/KeyGuard.git)
cd keyguard

# Create a virtual environment (optional but recommended)
python -m venv .venv
source .venv/bin/activate   # Linux/macOS
.\.venv\Scripts\activate    # Windows

# Install dependencies
pip install -r requirements.txt
```

### Running KeyGuard

```bash
python src/KeyGuard.py
```

### Building Standalone Executable

```bash
pyinstaller --onefile --noconsole --icon=assets/key.ico src/KeyGuard.py
```

Executable will be available at `dist/KeyGuard.exe`.

---

## 🛡️ Security & Privacy

KeyGuard never transmits or exposes your passwords online. All sensitive information is securely encrypted, stored locally, and managed entirely offline.

| File                        | Purpose                  | Encrypted?                         |
| --------------------------- | ------------------------ | ---------------------------------- |
| `.keyguard/vault.kgv`       | Encrypted password vault | ✅ AES-GCM                          |
| `.keyguard/logKeyGuard.log` | Application error log    | ❌ Plain text (no passwords logged) |

---

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository.
2. Create your feature branch (`git checkout -b feature/your-feature`).
3. Commit your changes (`git commit -m "feat: describe your feature"`).
4. Push your changes (`git push origin feature/your-feature`).
5. Open a pull request.

All pull requests must pass pre-commit hooks (`black`, `flake8`, `isort`) and include unit tests when applicable.

---

## 📜 License

Licensed under [Apache 2.0 License](LICENSE).

---

## 🙏 Acknowledgments

* [Python Cryptography](https://cryptography.io/)
* [Tkinter](https://docs.python.org/3/library/tkinter.html)
* [ttkbootstrap](https://github.com/israel-dryer/ttkbootstrap)
* [PyInstaller](https://www.pyinstaller.org/)
