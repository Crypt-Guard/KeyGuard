import string, secrets, getpass
from pathlib import Path
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from ttkbootstrap.tooltip import ToolTip

# ---------- util ---------- #

def gen_pwd(n: int, chars: str) -> str:
    return ''.join(secrets.choice(chars) for _ in range(n))

def save_pwd(user, app, pwd):
    p = Path.home() / "Documents" / "Senha"
    p.mkdir(parents=True, exist_ok=True)
    with (p / "senha.txt").open("a", encoding="utf-8") as fh:
        fh.write(f"{app}: {pwd}\n")

def score(pwd: str) -> int:
    cls = sum(map(bool, (any(c.islower() for c in pwd),
                         any(c.isupper() for c in pwd),
                         any(c.isdigit() for c in pwd),
                         any(c in string.punctuation for c in pwd))))
    return min(100, int(len(pwd)*6 + cls*10))

# ---------- callbacks ---------- #

def on_generate():
    try:
        n = int(spin_len.get())
        if n <= 0:
            raise ValueError
    except ValueError:
        ttk.Messagebox.show_error("Comprimento deve ser > 0")
        return

    chars = {
        1: string.digits,
        2: string.ascii_letters,
        3: string.ascii_letters + string.digits,
        4: string.ascii_letters + string.digits + string.punctuation,
    }[opt_charset.get()]

    pwd = gen_pwd(n, chars)
    var_pwd.set(pwd)
    bar_strength['value'] = score(pwd)
    root.clipboard_clear(); root.clipboard_append(pwd)

    if var_save.get():
        app = ent_app.get().strip()
        if not app:
            ttk.Messagebox.show_error("Digite o nome da aplicação.")
            return
        save_pwd(USER, app, pwd)
        ttk.Messagebox.show_info("Senha salva!")

def on_copy():
    pwd = var_pwd.get()
    if pwd:
        root.clipboard_clear(); root.clipboard_append(pwd)
        ttk.Messagebox.show_info("Copiada!")

def toggle_eye():
    ent_pwd.configure(show="" if chk_eye.instate(['selected']) else "•")

def switch_theme():
    new_theme = DARK if sw_theme.instate(['selected']) else LIGHT
    root.style.theme_use(new_theme)

# ---------- interface ---------- #

DARK, LIGHT = "superhero", "flatly"
root = ttk.Window(themename=DARK)
root.geometry("500x400")
root.minsize(500, 400)
root.resizable(False, False)
root.title("KeyGuard - Seu Gerador de Senhas Seguras")

USER = getpass.getuser()

# --- contêiner central ---
container = ttk.Frame(root)
container.place(relx=0.5, rely=0.5, anchor="c")   # centraliza tudo

# 1) Parâmetros
frm_opts = ttk.LabelFrame(container, text="Parâmetros")
frm_opts.grid(row=0, column=0, sticky="n")
frm_opts.columnconfigure(1, weight=1)             # coluna 1 (widgets) expande

ttk.Label(frm_opts, text="Comprimento:").grid(row=0, column=0, sticky="e", padx=(6,2), pady=4)
spin_len = ttk.Spinbox(frm_opts, from_=4, to=64, width=5, bootstyle=PRIMARY)
spin_len.set(16)
spin_len.grid(row=0, column=1, sticky="w", padx=(2,8), pady=4)
ToolTip(spin_len, text="Tamanho da senha")

opt_charset = ttk.IntVar(value=4)
labels = ["Números", "Letras", "Letras + Números", "Todos os Caracteres"]
for i, txt in enumerate(labels, 1):
    ttk.Radiobutton(frm_opts, text=txt, value=i, variable=opt_charset)\
       .grid(row=i, column=0 if i % 2 else 1, sticky="w", padx=8, pady=2)

var_save = ttk.BooleanVar()
ttk.Checkbutton(frm_opts, text="Salvar em arquivo", variable=var_save)\
   .grid(row=5, column=0, columnspan=2, sticky="w", padx=8, pady=(6,2))

ttk.Label(frm_opts, text="Aplicação:").grid(row=6, column=0, sticky="e", padx=(6,2), pady=4)
ent_app = ttk.Entry(frm_opts, width=24)
ent_app.grid(row=6, column=1, sticky="w", padx=(2,8), pady=4)

# 2) Resultado
frm_out = ttk.Frame(container)
frm_out.grid(row=1, column=0, pady=(12,6), sticky="ew")
frm_out.columnconfigure(0, weight=1)

var_pwd = ttk.StringVar()
ent_pwd = ttk.Entry(frm_out, textvariable=var_pwd, font=("Consolas", 14),
                    state="readonly", width=32)
ent_pwd.grid(row=0, column=0, sticky="ew", ipadx=6, ipady=4)

chk_eye = ttk.Checkbutton(frm_out, text="👁", style="toolbutton", command=toggle_eye)
chk_eye.grid(row=0, column=1, padx=4)

bar_strength = ttk.Progressbar(frm_out, maximum=100, length=350, bootstyle=SUCCESS)
bar_strength.grid(row=1, column=0, columnspan=2, pady=6)

# 3) Botões
frm_btn = ttk.Frame(container)
frm_btn.grid(row=2, column=0, pady=6)
ttk.Button(frm_btn, text="Gerar",  bootstyle=PRIMARY, command=on_generate)\
   .pack(side=LEFT, padx=6)
ttk.Button(frm_btn, text="Copiar", command=on_copy)\
   .pack(side=LEFT, padx=6)
ttk.Button(frm_btn, text="Sair", bootstyle=DANGER, command=root.destroy)\
   .pack(side=LEFT, padx=6)

# 4) Tema
frm_theme = ttk.Frame(container)
frm_theme.grid(row=3, column=0, pady=(8,0))
ttk.Label(frm_theme, text="Tema:").pack(side=LEFT, padx=(0,4))
sw_theme = ttk.Checkbutton(frm_theme, text="Dark", variable=ttk.IntVar(value=1),
                           bootstyle="round-toggle", command=switch_theme)
sw_theme.pack(side=LEFT)

root.mainloop()
