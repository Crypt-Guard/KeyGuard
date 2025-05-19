"""
KeyGuard 1.5.2
"""

from __future__ import annotations
import tkinter as tk
import tkinter.simpledialog as sd
from tkinter import messagebox as mb
import json, math, secrets, logging, string, base64, hmac, hashlib, struct, mmap
from pathlib import Path
from collections import Counter
from typing import Optional

import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from ttkbootstrap.tooltip import ToolTip
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# ───────────────── SecureBytes ──────────────────
class SecureBytes:
    """
    Secure container for sensitive byte data with explicit zeroization and wipe capabilities.
    """
    def __init__(self, data: bytes | bytearray | str):
        if isinstance(data, str):
            self._data = bytearray(data.encode('utf-8'))
        else:
            self._data = bytearray(data)

    def to_bytes(self) -> bytes:
        return bytes(self._data)

    def clear(self) -> None:
        """Sobrescreve com zeros e esvazia."""
        for i in range(len(self._data)):
            self._data[i] = 0
        self._data = bytearray()

    def wipe(self) -> None:
        """
        Primeiro sobrescreve com dados aleatórios, depois zera.
        Isso dificulta ainda mais a recuperação forense dos dados.
        """
        if self._data:
            rnd = secrets.token_bytes(len(self._data))
            for i in range(len(self._data)):
                self._data[i] = rnd[i]
            # agora zera de verdade
            self.clear()

    def __del__(self):
        # garante sempre limpar ao destruir o objeto
        self.clear()

# ──────── KeyObfuscator ────────
class KeyObfuscator:
    def __init__(self, key_bytes: SecureBytes):
        self._key = key_bytes
        self._obfuscated = False
        self._mask: Optional[SecureBytes] = None
        self._parts: list[SecureBytes] = []

    def obfuscate(self):
        if self._obfuscated:
            return
        kb = self._key.to_bytes()
        length = len(kb)
        mask = bytearray(secrets.token_bytes(length))
        obf = bytearray(length)
        for i in range(length):
            obf[i] = kb[i] ^ mask[i]
        self._mask = SecureBytes(mask)
        self._parts = [SecureBytes(obf)]
        self._key.clear()
        self._obfuscated = True

    def deobfuscate(self) -> SecureBytes:
        if not self._obfuscated:
            return self._key
        mask = self._mask.to_bytes()
        obf = self._parts[0].to_bytes()
        recovered = bytearray(len(mask))
        for i in range(len(mask)):
            recovered[i] = obf[i] ^ mask[i]
        return SecureBytes(recovered)

    def clear(self):
        if hasattr(self, "_key"):
            self._key.clear()
        if self._obfuscated:
            if self._mask:
                self._mask.clear()
            for part in self._parts:
                part.clear()
        self._parts = []
        self._mask = None
        self._obfuscated = False

    def __del__(self):
        self.clear()

# ──────── Helpers & Config ────────
DATA_DIR = Path.home() / ".keyguard"
DATA_DIR.mkdir(exist_ok=True)
logging.basicConfig(
    filename=DATA_DIR / "logKeyGuard.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s"
)

VAULT_FILE     = DATA_DIR / "vault.enc"
MAGIC          = b"CG1"
ARGON          = dict(t=16, m=2**20, p=4)
MIN_TOTAL_BITS = 64
MIN_CLASS_BITS = 2

CHARSETS = {
    1: string.digits,
    2: string.ascii_letters,
    3: string.ascii_letters + string.digits,
    4: string.ascii_letters + string.digits + string.punctuation,
}
CLASS_MAP = {
    "lower": string.ascii_lowercase,
    "upper": string.ascii_uppercase,
    "digit": string.digits,
    "symbol": string.punctuation,
}

def _nonce(key_bytes: bytes, counter: int) -> bytes:
    return hmac.new(key_bytes, counter.to_bytes(8, 'big'), hashlib.sha256).digest()[:12]

def _header(salt: bytes, cnt: int) -> bytes:
    hdr = {"v":2, "salt":base64.b64encode(salt).decode(),
           "argon":ARGON, "cnt":cnt}
    b = json.dumps(hdr, separators=(",",":")).encode()
    return struct.pack(">H", len(b)) + b

def _parse_header(buf: bytes) -> tuple[dict,int]:
    ln = struct.unpack(">H", buf[:2])[0]
    return json.loads(buf[2:2+ln]), 2 + ln

def _derive_key(pw: SecureBytes, salt: bytes) -> KeyObfuscator:
    raw = hash_secret_raw(
        pw.to_bytes(), salt,
        time_cost=ARGON["t"], memory_cost=ARGON["m"],
        parallelism=ARGON["p"], hash_len=32, type=Type.ID
    )
    sec = SecureBytes(raw)
    ko = KeyObfuscator(sec)
    ko.obfuscate()
    return ko

# ──────── Vault I/O ────────
def load_vault(pw: SecureBytes) -> tuple[dict,int,bytes]:
    if not VAULT_FILE.exists():
        return {}, 0, secrets.token_bytes(16)
    blob = VAULT_FILE.read_bytes()
    if not blob.startswith(MAGIC):
        raise ValueError("Formato inválido")
    hdr, off = _parse_header(blob[len(MAGIC):])
    salt, cnt = base64.b64decode(hdr["salt"]), hdr["cnt"]

    ko = _derive_key(pw, salt)
    plain = ko.deobfuscate()
    key_bytes = plain.to_bytes()
    plain.clear()

    nonce = _nonce(key_bytes, cnt)
    stored_nonce = blob[len(MAGIC)+off:len(MAGIC)+off+12]
    if nonce != stored_nonce:
        ko.clear()
        raise ValueError("Nonce mismatch")

    aad = MAGIC + blob[len(MAGIC):len(MAGIC)+off]
    ct = blob[len(MAGIC)+off+12:]
    pt = ChaCha20Poly1305(key_bytes).decrypt(nonce, ct, aad)

    ko.clear()
    return json.loads(pt.decode()), cnt, salt

def save_vault(vault: dict, pw: SecureBytes, cnt_prev: int, salt: bytes) -> int:
    cnt = cnt_prev + 1
    header = _header(salt, cnt)
    aad = MAGIC + header

    ko = _derive_key(pw, salt)
    plain = ko.deobfuscate()
    key_bytes = plain.to_bytes()
    plain.clear()

    nonce = _nonce(key_bytes, cnt)
    ct = ChaCha20Poly1305(key_bytes).encrypt(nonce, json.dumps(vault).encode(), aad)
    VAULT_FILE.write_bytes(MAGIC + header + nonce + ct)

    ko.clear()
    return cnt

# ───────────────── Password Generator ────────────
def secure_password(n:int, alpha:str) -> str:
    m,thr = len(alpha),(256//len(alpha))*len(alpha)
    while True:
        pw = ''.join(alpha[b%m] for b in secrets.token_bytes(n*2) if b<thr)[:n]
        if len(pw)==n and _valid(pw, alpha):
            return pw

def _valid(pw:str,a:str) -> bool:
    need = [cls for cls in CLASS_MAP.values() if set(cls)&set(a)]
    return len(pw)<len(need) or all(any(c in cls for c in pw) for cls in need)

def entropy_bits(pw:str,a:str) -> float:
    return len(pw)*math.log2(len(a))

def class_entropy(pw:str) -> dict[str,float]:
    cnt = Counter(pw)
    return {n:sum(cnt[c] for c in cls)*math.log2(len(cls))
            for n,cls in CLASS_MAP.items() if any(c in cnt for c in cls)}

# ──────── GUI ────────
class KeyGuard(ttk.Window):
    def __init__(self):
        super().__init__(themename="superhero")
        self.title("KeyGuard 1.5.2"); self.geometry("560x460"); self.resizable(False,False)

        raw = sd.askstring("Senha-mestra","Digite a senha do vault:",show="*")
        if not raw:
            super().destroy(); return
        self._pw = SecureBytes(raw); raw = None

        try:
            self.vault, self._cnt, self._salt = load_vault(self._pw)
        except ValueError:
            mb.showerror("Erro","Senha inválida ou vault corrompido.")
            self.destroy(); return

        self._build_menu()
        self._build_ui()

    def _build_menu(self):
        menubar = tk.Menu(self)
        m = tk.Menu(menubar, tearoff=0)
        m.add_command(label="Trocar Senha", command=self._change_master)
        menubar.add_cascade(label="Menu", menu=m)
        self.config(menu=menubar)

    def _change_master(self):
        # 1) Verifica senha antiga
        old = sd.askstring("Trocar Senha","Senha atual:",show="*", parent=self)
        if old is None: return
        try:
            vault, cnt_old, salt_old = load_vault(SecureBytes(old))
        except ValueError:
            mb.showerror("Erro","Senha atual incorreta.", parent=self)
            return

        # 2) Nova senha + confirmação
        new = sd.askstring("Trocar Senha","Nova senha-mestra:",show="*", parent=self)
        if new is None: return
        conf = sd.askstring("Trocar Senha","Confirme a nova senha:",show="*", parent=self)
        if conf is None: return
        if new != conf:
            mb.showerror("Erro","Confirmação não confere.", parent=self)
            return

        # 3) Recriptografa todo o vault com nova senha
        new_salt = secrets.token_bytes(16)
        cnt_new = 0
        header = _header(new_salt, cnt_new)
        aad = MAGIC + header

        ko_new = _derive_key(SecureBytes(new), new_salt)
        plain_new = ko_new.deobfuscate()
        key_bytes = plain_new.to_bytes()
        plain_new.clear()

        nonce = _nonce(key_bytes, cnt_new)
        ct = ChaCha20Poly1305(key_bytes).encrypt(nonce, json.dumps(vault).encode(), aad)
        VAULT_FILE.write_bytes(MAGIC + header + nonce + ct)
        ko_new.clear()

        # 4) Atualiza estado
        self._pw.clear()
        self._pw = SecureBytes(new)
        self._salt = new_salt
        self._cnt = cnt_new
        self.vault = vault

        mb.showinfo("Sucesso","Senha-mestra alterada.", parent=self)

    # ── build UI ──
    def _build_ui(self):
        root = ttk.Frame(self); root.place(relx=.5, rely=.5, anchor="c")

        # parâmetros
        frm = ttk.LabelFrame(root, text="Parâmetros"); frm.grid(row=0, column=0)
        frm.columnconfigure(1, weight=1)
        ttk.Label(frm, text="Comprimento:").grid(row=0, column=0, sticky="e", padx=6, pady=4)
        self.spin = ttk.Spinbox(frm, from_=4, to=128, width=6, bootstyle=PRIMARY)
        self.spin.set(16); self.spin.grid(row=0, column=1, sticky="w", padx=(2, 8), pady=4)
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

        # resultado
        out = ttk.Frame(root); out.grid(row=1, column=0, pady=12, sticky="ew")
        out.columnconfigure(0, weight=1)
        self.var_pwd = ttk.StringVar()
        self.ent_pwd = ttk.Entry(out, textvariable=self.var_pwd,
                                 font=("Consolas", 14), state="readonly",
                                 width=38, show="•")
        self.ent_pwd.grid(row=0, column=0, sticky="ew", ipadx=6, ipady=4)

        self.chk_eye = ttk.Checkbutton(out, text="👁", style="toolbutton",
                                       command=lambda: self.ent_pwd.config(
                                           show="" if self.chk_eye.instate(['selected']) else "•"))
        self.chk_eye.grid(row=0, column=1, padx=4)

        self.bar = ttk.Progressbar(out, maximum=120, length=400, bootstyle=SUCCESS)
        self.bar.grid(row=1, column=0, columnspan=2, pady=6)

        self.lbl = ttk.Label(out, text="Entropia / força")
        self.lbl.grid(row=2, column=0, columnspan=2)

        # botões
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

    # ── callbacks principais ──
    def _on_generate(self, *_):
        n = int(self.spin.get()); alpha = CHARSETS[self.opt.get()]
        pw = secure_password(n, alpha)
        bits = entropy_bits(pw, alpha)
        self.var_pwd.set(pw); self.bar['value'] = min(bits, 120)
        msg = f"Entropia: {bits:.1f} bits"
        if bits < MIN_TOTAL_BITS: msg += " ⚠️"
        if any(b < MIN_CLASS_BITS for b in class_entropy(pw).values()):
            msg += " (classe fraca ⚠️)"
        self.lbl.config(text=msg)

        if self.flag_save.get():
            app = self.ent_app.get().strip() or "Sem_nome"
            self.vault[app] = pw
            self._cnt = save_vault(self.vault, self._pw, self._cnt, self._salt)

    def _on_copy(self, value: str = None, *_):
        txt = value or self.var_pwd.get()
        if txt:
            self.clipboard_clear(); self.clipboard_append(txt)

    def _on_clear(self, *_):
        self.clipboard_clear()
        self.var_pwd.set(""); self.bar['value'] = 0
        self.lbl.config(text="Entropia / força")
        if self.chk_eye.instate(['selected']):
            self.chk_eye.state(['!selected']); self.ent_pwd.config(show="•")

    # ── Vault viewer ──
    def _vault_view(self):
        top = ttk.Toplevel(self); top.title("Vault"); top.geometry("380x300")
        tree = ttk.Treeview(top, columns=("app","pwd"), show="headings")
        tree.heading("app", text="Aplicação"); tree.heading("pwd", text="Senha")
        tree.column("pwd", width=120, anchor="center")
        tree.pack(fill=BOTH, expand=True)

        for app in self.vault:
            tree.insert("", END, iid=app, values=(app, "••••••••"))

        tree.bind("<Double-1>", lambda e: self._detail(tree))

        bar = ttk.Frame(top); bar.pack(pady=6)
        ttk.Button(bar, text="Ver detalhes", command=lambda: self._detail(tree))\
           .pack(side=LEFT, padx=6)
        ttk.Button(bar, text="Copiar", command=lambda: self._copy_sel(tree))\
           .pack(side=LEFT, padx=6)
        ttk.Button(bar, text="Excluir", bootstyle=DANGER,
                   command=lambda: self._delete_sel(tree))\
           .pack(side=LEFT, padx=6)

    # ── Modal de detalhe limitado a 16 chars ──
    def _detail(self, tree):
        sel = tree.selection()
        if not sel:
            return
        app = sel[0]
        pwd = self.vault[app]
        show_len = min(len(pwd), 16)
        mask     = "•" * show_len
        first16  = pwd[:show_len]

        dlg = ttk.Toplevel(self); dlg.title(app); dlg.grab_set()
        dlg.geometry("360x150"); dlg.resizable(False,False)

        ttk.Label(dlg, text=f"Aplicação: {app}",
                  font=("Segoe UI",11,"bold")).pack(pady=(12,4))

        frm = ttk.Frame(dlg); frm.pack(padx=12,pady=4, fill="x")
        lbl = ttk.Label(frm, text=mask, font=("Consolas",12))
        lbl.pack(side=LEFT, fill="x", expand=True)

        var_eye = ttk.IntVar(value=0)
        chk = ttk.Checkbutton(frm, text="👁", style="toolbutton",
                              variable=var_eye,
                              command=lambda:
                                  lbl.config(text=first16 if var_eye.get() else mask))
        chk.pack(side=LEFT, padx=6)

        ttk.Button(dlg, text="Copiar",
                   command=lambda: (self._on_copy(pwd), dlg.destroy()))\
           .pack(pady=8)

    # ── Copiar/Excluir ──
    def _copy_sel(self, tree):
        sel = tree.selection()
        if sel:
            pwd = self.vault[sel[0]]
            self._on_copy(pwd)

    def _delete_sel(self, tree):
        sel = tree.selection()
        if not sel: return
        app = sel[0]
        if not mb.askyesno("Confirmar", f"Remover “{app}” do vault?"):
            return
        tree.delete(app)
        self.vault.pop(app, None)
        self._cnt = save_vault(self.vault, self._pw, self._cnt, self._salt)

    # ── destruição segura ──
    def destroy(self):
        if hasattr(self, "_pw"):
            self._pw.clear()
        super().destroy()
        
if __name__=="__main__":
    KeyGuard().mainloop()
