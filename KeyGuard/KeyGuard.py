from __future__ import annotations
import string, secrets
from pathlib import Path
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from ttkbootstrap.tooltip import ToolTip

# ---------- configuração ---------- #
VAULT_DIR  = Path.home() / ".keyguard"
VAULT_FILE = VAULT_DIR / "vault.txt"

CHARSETS = {
    1: string.digits,
    2: string.ascii_letters,
    3: string.ascii_letters + string.digits,
    4: string.ascii_letters + string.digits + string.punctuation,
}

# ---------- utilitários ---------- #
def gen_pwd(n: int, chars: str) -> str:
    while True:
        pwd = ''.join(secrets.choice(chars) for _ in range(n))
        if all(any(c in cls for c in pwd) for cls in [
                string.ascii_lowercase, string.ascii_uppercase,
                string.digits, string.punctuation] if set(cls) & set(chars)):
            return pwd

def score(pwd: str) -> int:
    cls = sum(map(bool, (any(c.islower() for c in pwd),
                         any(c.isupper() for c in pwd),
                         any(c.isdigit()  for c in pwd),
                         any(c in string.punctuation for c in pwd))))
    return min(100, int(len(pwd) * 6 + cls * 10))

def save_pwd(app: str, pwd: str) -> None:
    VAULT_DIR.mkdir(parents=True, exist_ok=True)
    with VAULT_FILE.open("a", encoding="utf-8") as fh:
        fh.write(f"{app}: {pwd}\n")

# ---------- aplicação ---------- #
class KeyGuard(ttk.Window):
    def __init__(self):
        super().__init__(themename="superhero")
        self.title("KeyGuard – Gerador de Senhas Seguras")
        self.geometry("500x400")
        self.resizable(False, False)
        self._build_ui()

    # ---------- interface ---------- #
    def _build_ui(self):
        container = ttk.Frame(self)
        container.place(relx=0.5, rely=0.5, anchor="c")

        # Parâmetros
        frm_opts = ttk.LabelFrame(container, text="Parâmetros")
        frm_opts.grid(row=0, column=0, sticky="n")
        frm_opts.columnconfigure(1, weight=1)

        ttk.Label(frm_opts, text="Comprimento:").grid(row=0, column=0, sticky="e", padx=(6,2), pady=4)
        self.spin_len = ttk.Spinbox(frm_opts, from_=1, to=9999, width=6, bootstyle=PRIMARY)
        self.spin_len.set(16)
        self.spin_len.grid(row=0, column=1, sticky="w", padx=(2,8), pady=4)
        ToolTip(self.spin_len, text="Tamanho da senha (≥ 1)")

        self.opt_charset = ttk.IntVar(value=4)
        for i, txt in enumerate(("Números", "Letras", "Letras + Números", "Todos"), 1):
            ttk.Radiobutton(frm_opts, text=txt, value=i, variable=self.opt_charset)\
               .grid(row=i, column=0 if i % 2 else 1, sticky="w", padx=8, pady=2)

        self.var_save = ttk.BooleanVar()
        ttk.Checkbutton(frm_opts, text="Salvar em arquivo", variable=self.var_save)\
           .grid(row=5, column=0, columnspan=2, sticky="w", padx=8, pady=(6,2))

        ttk.Label(frm_opts, text="Aplicação:").grid(row=6, column=0, sticky="e", padx=(6,2), pady=4)
        self.ent_app = ttk.Entry(frm_opts, width=24)
        self.ent_app.grid(row=6, column=1, sticky="w", padx=(2,8), pady=4)

        # Resultado
        frm_out = ttk.Frame(container)
        frm_out.grid(row=1, column=0, pady=(12,6), sticky="ew")
        frm_out.columnconfigure(0, weight=1)

        self.var_pwd = ttk.StringVar()
        self.ent_pwd = ttk.Entry(frm_out, textvariable=self.var_pwd,
                                 font=("Consolas", 14), state="readonly",
                                 width=32, show="•")
        self.ent_pwd.grid(row=0, column=0, sticky="ew", ipadx=6, ipady=4)

        self.chk_eye = ttk.Checkbutton(frm_out, text="👁", style="toolbutton",
                                       command=self._toggle_eye)
        self.chk_eye.grid(row=0, column=1, padx=4)

        self.bar_strength = ttk.Progressbar(frm_out, maximum=100, length=350, bootstyle=SUCCESS)
        self.bar_strength.grid(row=1, column=0, columnspan=2, pady=6)

        # Botões
        frm_btn = ttk.Frame(container)
        frm_btn.grid(row=2, column=0, pady=6)
        ttk.Button(frm_btn, text="Gerar",  bootstyle=PRIMARY, command=self._on_generate)\
           .pack(side=LEFT, padx=6)
        ttk.Button(frm_btn, text="Copiar", command=self._on_copy)\
           .pack(side=LEFT, padx=6)
        ttk.Button(frm_btn, text="Limpar", command=self._on_clear)\
           .pack(side=LEFT, padx=6)
        ttk.Button(frm_btn, text="Sair",   bootstyle=DANGER, command=self.destroy)\
           .pack(side=LEFT, padx=6)

        # Tema
        frm_theme = ttk.Frame(container)
        frm_theme.grid(row=3, column=0, pady=(8,0))
        ttk.Label(frm_theme, text="Tema:").pack(side=LEFT, padx=(0,4))
        self.var_theme = ttk.IntVar(value=1)
        ttk.Checkbutton(frm_theme, text="Dark", variable=self.var_theme,
                        bootstyle="round-toggle", command=self._switch_theme)\
           .pack(side=LEFT)

        # Atalhos
        self.bind_all('<Control-g>', lambda *_: self._on_generate())
        self.bind_all('<Control-c>', lambda *_: self._on_copy())
        self.bind_all('<Control-l>', lambda *_: self._on_clear())
        self.bind_all('<Escape>',    lambda *_: self.destroy())

    # ---------- callbacks ---------- #
    def _on_generate(self):
        try:
            n = int(self.spin_len.get())
            if n <= 0:
                raise ValueError
        except ValueError:
            return  # entrada inválida — apenas ignora

        pwd = gen_pwd(n, CHARSETS[self.opt_charset.get()])
        self.var_pwd.set(pwd)
        self.bar_strength['value'] = score(pwd)

        if self.var_save.get():
            app = self.ent_app.get().strip() or "Sem_nome"
            save_pwd(app, pwd)

    def _on_copy(self):
        pwd = self.var_pwd.get()
        if pwd:
            self.clipboard_clear()
            self.clipboard_append(pwd)

    def _on_clear(self):
        """Esvazia clipboard, campo de senha e barra de força."""
        self.clipboard_clear()
        self.var_pwd.set("")
        self.bar_strength['value'] = 0
        # volta a esconder caso o olho esteja aberto
        if self.chk_eye.instate(['selected']):
            self.chk_eye.state(['!selected'])
        self.ent_pwd.config(show="•")

    def _toggle_eye(self):
        show = "" if self.chk_eye.instate(['selected']) else "•"
        self.ent_pwd.config(show=show)

    def _switch_theme(self):
        self.style.theme_use("superhero" if self.var_theme.get() else "flatly")

# ---------- main ---------- #
if __name__ == "__main__":
    KeyGuard().mainloop()
