"""
KeyGuard 1.3.2 – nonce determinístico, AAD, zeroização, mlock opcional
---------------------------------------------------------------------
"""
from __future__ import annotations
import json, math, secrets, logging, string, base64, hmac, hashlib, struct, mmap
from pathlib import Path
from collections import Counter
from typing import Optional

import tkinter.simpledialog as sd
from tkinter import messagebox as mb
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from ttkbootstrap.tooltip import ToolTip
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# ───────── SecureBytes ─────────
class SecureBytes:
    def __init__(self, data: bytes | bytearray | str):
        self._data = bytearray(data.encode() if isinstance(data, str) else data)
    def to_bytes(self):    return bytes(self._data)
    def clear(self):
        for i in range(len(self._data)): self._data[i] = 0
        self._data = bytearray()
    def __del__(self):     self.clear()

# ───────── logging & paths ─────────
DATA_DIR = Path.home() / ".keyguard"
DATA_DIR.mkdir(exist_ok=True)
logging.basicConfig(
    filename=DATA_DIR / "logKeyGuard.log",          # renomeado
    level=logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s"
)

VAULT_FILE = DATA_DIR / "vault.enc"
MAGIC = b"CG1"
ARGON = dict(t=16, m=2**20, p=4)                    # Argon2id params

MIN_TOTAL_BITS, MIN_CLASS_BITS = 64, 2

CHARSETS = {
    1: string.digits,
    2: string.ascii_letters,
    3: string.ascii_letters + string.digits,
    4: string.ascii_letters + string.digits + string.punctuation,
}
CLASS_MAP = {
    "lower":  string.ascii_lowercase,
    "upper":  string.ascii_uppercase,
    "digit":  string.digits,
    "symbol": string.punctuation,
}

# ───────── crypto helpers ─────────
def _derive_key(pw: SecureBytes, salt: bytes) -> SecureBytes:
    key = hash_secret_raw(pw.to_bytes(), salt,
                          time_cost=ARGON["t"], memory_cost=ARGON["m"],
                          parallelism=ARGON["p"], hash_len=32, type=Type.ID)
    k = SecureBytes(key)
    try:                           # mlock opcional
        mm = mmap.mmap(-1, len(k._data)); mm.write(k._data); mm.mlock(); mm.close()
    except (OSError, AttributeError):
        pass
    return k

def _nonce(key: SecureBytes, counter: int) -> bytes:
    return hmac.new(key.to_bytes(), counter.to_bytes(8, 'big'),
                    hashlib.sha256).digest()[:12]

def _header(salt: bytes, cnt: int) -> bytes:
    hdr = {"v": 2, "salt": base64.b64encode(salt).decode(),
           "argon": ARGON, "cnt": cnt}
    blob = json.dumps(hdr, separators=(",", ":")).encode()
    return struct.pack(">H", len(blob)) + blob      # 2-bytes len

def _parse_header(buf: bytes) -> tuple[dict, int]:
    ln = struct.unpack(">H", buf[:2])[0]
    return json.loads(buf[2:2+ln]), 2 + ln

# ───────── vault I/O ─────────
def load_vault(pw: SecureBytes) -> tuple[dict, int, bytes]:
    if not VAULT_FILE.exists():
        return {}, 0, secrets.token_bytes(16)
    blob = VAULT_FILE.read_bytes()
    if not blob.startswith(MAGIC):
        raise ValueError("formato inválido")
    hdr, off = _parse_header(blob[len(MAGIC):])
    salt = base64.b64decode(hdr["salt"]); cnt = hdr["cnt"]
    key = _derive_key(pw, salt)
    nonce = _nonce(key, cnt)
    stored_nonce = blob[len(MAGIC)+off : len(MAGIC)+off+12]
    if nonce != stored_nonce:
        raise ValueError("nonce mismatch")
    aad = MAGIC + blob[len(MAGIC):len(MAGIC)+off]
    plain = ChaCha20Poly1305(key.to_bytes()).decrypt(
        nonce, blob[len(MAGIC)+off+12:], aad)
    key.clear()
    return json.loads(plain.decode()), cnt, salt

def save_vault(obj: dict, pw: SecureBytes, cnt_prev: int, salt: bytes) -> int:
    cnt = cnt_prev + 1
    header = _header(salt, cnt)
    aad = MAGIC + header
    key = _derive_key(pw, salt)
    nonce = _nonce(key, cnt)
    ct = ChaCha20Poly1305(key.to_bytes()).encrypt(
        nonce, json.dumps(obj).encode(), aad)
    VAULT_FILE.write_bytes(MAGIC + header + nonce + ct)
    key.clear()
    return cnt

# ───────── password generator ─────────
def secure_password(n: int, alpha: str) -> str:
    m, thr = len(alpha), (256 // len(alpha)) * len(alpha)
    while True:
        pw = ''.join(alpha[b % m] for b in secrets.token_bytes(n*2) if b < thr)[:n]
        if len(pw) == n and _valid(pw, alpha):
            return pw

def _valid(pw: str, a: str) -> bool:
    need = [cls for cls in CLASS_MAP.values() if set(cls) & set(a)]
    return len(pw) < len(need) or all(any(c in cls for c in pw) for cls in need)

def entropy_bits(pw: str, alpha: str) -> float:
    return len(pw) * math.log2(len(alpha))

def class_entropy(pw: str) -> dict[str, float]:
    cnt = Counter(pw)
    return {n: sum(cnt[b] for b in cls)*math.log2(len(cls))
            for n, cls in CLASS_MAP.items() if any(b in cnt for b in cls)}

# ───────── GUI ─────────
class KeyGuard(ttk.Window):
    def __init__(self):
        super().__init__(themename="superhero")
        self.title("KeyGuard 1.3.2"); self.geometry("560x460"); self.resizable(False, False)

        raw = sd.askstring("Senha-mestra", "Digite a senha do vault:", show="*")
        if not raw:
            super().destroy()          # encerra sem tentar limpar senha
            return
        self._pw = SecureBytes(raw); raw = None

        try:
            self.vault, self._cnt, self._salt = load_vault(self._pw)
        except ValueError:
            mb.showerror("Erro", "Senha inválida ou arquivo corrompido.")
            self.destroy(); return

        self._ui()

    # interface (idêntica às versões anteriores, inclui Copiar, Limpar, Vault etc.)
    def _ui(self):
        root = ttk.Frame(self); root.place(relx=.5, rely=.5, anchor="c")
        frm = ttk.LabelFrame(root, text="Parâmetros"); frm.grid(row=0, column=0)
        frm.columnconfigure(1, weight=1)
        ttk.Label(frm, text="Comprimento:").grid(row=0, column=0, sticky="e", padx=6, pady=4)
        self.spin = ttk.Spinbox(frm, from_=4, to=128, width=6, bootstyle=PRIMARY); self.spin.set(16)
        self.spin.grid(row=0, column=1, sticky="w", padx=(2, 8), pady=4)
        ToolTip(self.spin, text="Tamanho da senha")

        self.opt = ttk.IntVar(value=4)
        for i, t in enumerate(("Números", "Letras", "Letras+Números", "Todos"), 1):
            ttk.Radiobutton(frm, text=t, value=i, variable=self.opt)\
               .grid(row=i, column=0 if i % 2 else 1, sticky="w", padx=8)

        self.flag_save = ttk.BooleanVar()
        ttk.Checkbutton(frm, text="Salvar no vault", variable=self.flag_save)\
           .grid(row=5, column=0, columnspan=2, sticky="w", padx=8, pady=(6, 2))

        ttk.Label(frm, text="Aplicação:").grid(row=6, column=0, sticky="e", padx=6)
        self.ent_app = ttk.Entry(frm, width=24)
        self.ent_app.grid(row=6, column=1, sticky="w", padx=(2, 8))

        out = ttk.Frame(root); out.grid(row=1, column=0, pady=12, sticky="ew")
        out.columnconfigure(0, weight=1)
        self.var_pwd = ttk.StringVar()
        self.ent_pwd = ttk.Entry(out, textvariable=self.var_pwd, font=("Consolas", 14),
                                 state="readonly", width=38, show="•")
        self.ent_pwd.grid(row=0, column=0, sticky="ew", ipadx=6, ipady=4)
        self.chk_eye = ttk.Checkbutton(out, text="👁", style="toolbutton",
                                       command=lambda: self.ent_pwd.config(
                                           show="" if self.chk_eye.instate(['selected']) else "•"))
        self.chk_eye.grid(row=0, column=1, padx=4)

        self.bar = ttk.Progressbar(out, maximum=120, length=400, bootstyle=SUCCESS)
        self.bar.grid(row=1, column=0, columnspan=2, pady=6)
        self.lbl = ttk.Label(out, text="Entropia / força"); self.lbl.grid(row=2, column=0, columnspan=2)

        btn = ttk.Frame(root); btn.grid(row=2, column=0, pady=6)
        ttk.Button(btn, text="Gerar", bootstyle=PRIMARY, command=self._on_generate).pack(side=LEFT, padx=6)
        ttk.Button(btn, text="Copiar", command=self._on_copy).pack(side=LEFT, padx=6)
        ttk.Button(btn, text="Limpar", command=self._on_clear).pack(side=LEFT, padx=6)
        ttk.Button(btn, text="Vault", command=self._vault_view).pack(side=LEFT, padx=6)
        ttk.Button(btn, text="Sair", bootstyle=DANGER, command=self.destroy).pack(side=LEFT, padx=6)

        # atalhos
        self.bind_all('<Control-g>', lambda *_: self._on_generate())
        self.bind_all('<Control-c>', lambda *_: self._on_copy())
        self.bind_all('<Control-l>', lambda *_: self._on_clear())
        self.bind_all('<Escape>',    lambda *_: self.destroy())

    # ---------- main callbacks ----------
    def _on_generate(self, *_):
        n = int(self.spin.get()); alpha = CHARSETS[self.opt.get()]
        pw = secure_password(n, alpha)
        bits = entropy_bits(pw, alpha)
        self.var_pwd.set(pw); self.bar['value'] = min(bits, 120)
        txt = f"Entropia: {bits:.1f} bits"
        if bits < MIN_TOTAL_BITS: txt += " ⚠️"
        if any(b < MIN_CLASS_BITS for b in class_entropy(pw).values()):
            txt += " (classe fraca ⚠️)"
        self.lbl.config(text=txt)
        if self.flag_save.get():
            app = self.ent_app.get().strip() or "Sem_nome"
            self.vault[app] = pw
            self._cnt = save_vault(self.vault, self._pw, self._cnt, self._salt)

    def _on_copy(self, value: str = None, *_):
        txt = value or self.var_pwd.get()
        if txt:
            self.clipboard_clear(); self.clipboard_append(txt)

    def _on_clear(self, *_):
        self.clipboard_clear(); self.var_pwd.set(""); self.bar['value'] = 0
        self.lbl.config(text="Entropia / força")
        if self.chk_eye.instate(['selected']):
            self.chk_eye.state(['!selected']); self.ent_pwd.config(show="•")

    # ---------- vault viewer ----------
    def _vault_view(self):
        top = ttk.Toplevel(self); top.title("Vault"); top.geometry("380x280")
        tree = ttk.Treeview(top, columns=("app", "pwd"), show="headings")
        tree.heading("app", text="Aplicação"); tree.heading("pwd", text="Senha")
        tree.pack(fill=BOTH, expand=True)
        for a, p in self.vault.items():
            tree.insert("", END, values=(a, p))

        bar = ttk.Frame(top); bar.pack(pady=6)
        ttk.Button(bar, text="Copiar", command=lambda: self._copy_sel(tree)).pack(side=LEFT, padx=6)
        ttk.Button(bar, text="Excluir", bootstyle=DANGER,
                   command=lambda: self._delete_sel(tree)).pack(side=LEFT, padx=6)

    def _copy_sel(self, tree):
        sel = tree.selection()
        if sel:
            self._on_copy(tree.item(sel[0])["values"][1])

    def _delete_sel(self, tree):
        sel = tree.selection()
        if not sel: return
        app = tree.item(sel[0])["values"][0]
        if not mb.askyesno("Confirmar", f"Remover “{app}” do vault?"):
            return
        tree.delete(sel[0]); self.vault.pop(app, None)
        self._cnt = save_vault(self.vault, self._pw, self._cnt, self._salt)

    # ----------
    def destroy(self):
        if hasattr(self, "_pw"):
            self._pw.clear()
        super().destroy()

# ───────── main ─────────
if __name__ == "__main__":
    KeyGuard().mainloop()
