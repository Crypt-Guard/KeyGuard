"""UI construction helpers — separated from app logic for maintainability."""

from __future__ import annotations

import string
import tkinter as tk

import ttkbootstrap as ttk
from ttkbootstrap.constants import DANGER, INFO, PRIMARY, SUCCESS
from ttkbootstrap.tooltip import ToolTip

from keyguard.config import CHARSETS, MIN_TOTAL_BITS, OPT_TO_KEY, Config


def build_main_view(app) -> None:
    """Build the main password-generator UI inside *app*."""
    container = ttk.Frame(app)
    container.place(relx=0.5, rely=0.5, anchor="c")

    # ----- parameters frame -----
    frm = ttk.LabelFrame(container, text="Parâmetros")
    frm.grid(row=0, column=0, sticky="n")
    frm.columnconfigure(1, weight=1)

    ttk.Label(frm, text="Comprimento:").grid(row=0, column=0, sticky="e", padx=6, pady=4)

    def validate_length(value):
        if value == "":
            return True
        try:
            num = int(value)
            return 1 <= num <= Config.MAX_GENERATED_PASSWORD_LENGTH
        except ValueError:
            return False

    vcmd = (app.register(validate_length), "%P")
    app.spin = ttk.Spinbox(
        frm,
        from_=Config.MIN_GENERATED_PASSWORD_LENGTH,
        to=Config.MAX_GENERATED_PASSWORD_LENGTH,
        width=6,
        bootstyle=PRIMARY,
        validate="key",
        validatecommand=vcmd,
    )
    app.spin.set(16)
    app.spin.grid(row=0, column=1, sticky="w", padx=(2, 8), pady=4)
    ToolTip(
        app.spin,
        text=f"Password length ({Config.MIN_GENERATED_PASSWORD_LENGTH}"
        f"-{Config.MAX_GENERATED_PASSWORD_LENGTH})",
    )

    app.opt = ttk.IntVar(value=4)
    labels = ("Números", "Letras", "Letras+Números", "Todos")
    for i, txt in enumerate(labels, 1):
        r = ttk.Radiobutton(frm, text=txt, value=i, variable=app.opt)
        r.grid(row=i, column=0 if i % 2 else 1, sticky="w", padx=8, pady=2)

    app.flag_save = ttk.BooleanVar()
    ttk.Checkbutton(frm, text="Salvar no vault", variable=app.flag_save).grid(
        row=5, column=0, columnspan=2, sticky="w", padx=8, pady=(6, 2)
    )

    ttk.Label(frm, text="Aplicação:").grid(row=6, column=0, sticky="e", padx=6)
    app.ent_app = ttk.Entry(frm, width=24)
    app.ent_app.grid(row=6, column=1, sticky="w", padx=(2, 8), pady=4)

    # ----- output frame -----
    out = ttk.Frame(container)
    out.grid(row=1, column=0, pady=12, sticky="ew")
    out.columnconfigure(0, weight=1)

    app.var_pwd = ttk.StringVar()
    app.ent_pwd = ttk.Entry(
        out,
        textvariable=app.var_pwd,
        font=("Consolas", 14),
        state="readonly",
        width=38,
        show="•",
    )
    app.ent_pwd.grid(row=0, column=0, sticky="ew", ipadx=6, ipady=4)

    app.chk_eye = ttk.Checkbutton(
        out,
        text="👁",
        style="toolbutton",
        command=lambda: app.ent_pwd.config(
            show="" if app.chk_eye.instate(["selected"]) else "•"
        ),
    )
    app.chk_eye.grid(row=0, column=1, padx=4)

    app.bar = ttk.Progressbar(out, maximum=120, length=400, bootstyle=SUCCESS)
    app.bar.grid(row=1, column=0, columnspan=2, pady=6)
    app.lbl = ttk.Label(out, text="Entropia / força")
    app.lbl.grid(row=2, column=0, columnspan=2)

    # ----- buttons -----
    btn = ttk.Frame(container)
    btn.grid(row=2, column=0, pady=6)
    ttk.Button(btn, text="Gerar", bootstyle=PRIMARY, command=app._on_generate).pack(
        side="left", padx=6
    )
    ttk.Button(btn, text="Copiar", command=app._on_copy).pack(side="left", padx=6)
    ttk.Button(btn, text="Limpar", command=app._on_clear).pack(side="left", padx=6)
    ttk.Button(btn, text="Vault", command=app._vault_view).pack(side="left", padx=6)
    ttk.Button(btn, text="Sair", bootstyle=DANGER, command=app.destroy).pack(
        side="left", padx=6
    )

    # -- shortcuts
    app.bind_all("<Control-g>", lambda *_: app._on_generate())
    app.bind_all("<Control-c>", lambda *_: app._on_copy())
    app.bind_all("<Control-l>", lambda *_: app._on_clear())
    app.bind_all("<Escape>", lambda *_: app.destroy())


def build_vault_viewer(app) -> None:
    """Build the vault viewer window."""
    top = ttk.Toplevel(app)
    top.title("Vault")
    top.geometry("380x350")

    # -- search
    sf = ttk.Frame(top)
    sf.pack(fill=tk.X, padx=5, pady=5)
    ttk.Label(sf, text="Buscar:").pack(side=tk.LEFT, padx=5)
    search_var = ttk.StringVar()
    ttk.Entry(sf, textvariable=search_var).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

    # -- treeview
    tree = ttk.Treeview(top, columns=("app", "pwd"), show="headings")
    tree.heading("app", text="Aplicação")
    tree.heading("pwd", text="Senha")
    tree.column("pwd", width=120, anchor="center")
    tree.pack(fill=tk.BOTH, expand=True)

    def filter_entries(*_args):
        query = search_var.get().lower()
        tree.delete(*tree.get_children())
        for name in app.vault.list_entries():
            if query in name.lower():
                tree.insert("", tk.END, iid=name, values=(name, "••••••••"))

    search_var.trace_add("write", lambda *_: filter_entries())
    filter_entries()

    # -- bindings
    tree.bind("<Double-1>", lambda _: _detail(app, tree))
    tree.bind("<Return>", lambda _: _detail(app, tree))
    tree.bind("<Delete>", lambda _: _delete_sel(app, tree))
    tree.bind("<Control-c>", lambda _: _copy_sel(app, tree))
    top.bind("<Escape>", lambda _: top.destroy())

    # -- drag & drop reorder
    tree._drag = {"item": None, "moved": False}

    def _press(e):
        tree._drag["item"] = tree.identify_row(e.y)
        tree._drag["moved"] = False

    def _motion(e):
        iid = tree._drag["item"]
        if not iid:
            return
        target = tree.identify_row(e.y)
        if not target or target == iid:
            return
        idx = tree.index(target)
        tree.move(iid, "", idx)
        tree._drag["moved"] = True

    def _release(_e):
        if not tree._drag["moved"]:
            return
        new_order = [tree.item(iid, "values")[0] for iid in tree.get_children()]
        _persist_order(app, new_order)

    tree.bind("<ButtonPress-1>", _press)
    tree.bind("<B1-Motion>", _motion)
    tree.bind("<ButtonRelease-1>", _release)

    # -- buttons
    bar = ttk.Frame(top)
    bar.pack(pady=6)
    ttk.Button(bar, text="Ver detalhes", command=lambda: _detail(app, tree)).pack(
        side="left", padx=6
    )
    ttk.Button(bar, text="Copiar", command=lambda: _copy_sel(app, tree)).pack(
        side="left", padx=6
    )
    ttk.Button(
        bar, text="Excluir", bootstyle=DANGER, command=lambda: _delete_sel(app, tree)
    ).pack(side="left", padx=6)


# ---------------------------------------------------------------------------
#  Helper functions used by vault viewer
# ---------------------------------------------------------------------------
def _detail(app, tree) -> None:
    from tkinter import messagebox as mb

    sel = tree.selection()
    if not sel:
        return
    name = sel[0]
    entry = app.vault.entries.get(name)
    if not entry:
        return
    pwd = entry.get_password()
    show = pwd[: min(16, len(pwd))]
    mask = "•" * len(show)

    dlg = ttk.Toplevel(app)
    dlg.title(name)
    dlg.grab_set()

    ttk.Label(dlg, text=f"Aplicação: {name}", font=("Segoe UI", 11, "bold")).pack(
        pady=(12, 4)
    )
    frame = ttk.Frame(dlg)
    frame.pack(padx=12, pady=4, fill="x")
    lbl = ttk.Label(frame, text=mask, font=("Consolas", 12))
    lbl.pack(side=tk.LEFT, fill="x", expand=True)
    var_eye = ttk.IntVar(value=0)
    ttk.Checkbutton(
        frame,
        text="👁",
        style="toolbutton",
        variable=var_eye,
        command=lambda: lbl.config(text=show if var_eye.get() else mask),
    ).pack(side=tk.LEFT, padx=6)
    ttk.Button(
        dlg,
        text="Copiar",
        command=lambda: (app.clipboard_clear(), app.clipboard_append(pwd), dlg.destroy()),
    ).pack(pady=8)

    def auto_hide():
        try:
            if dlg and dlg.winfo_exists():
                var_eye.set(0)
                lbl.config(text=mask)
        except (tk.TclError, AttributeError):
            pass

    dlg.after(Config.AUTO_HIDE_DELAY, auto_hide)


def _copy_sel(app, tree) -> None:
    sel = tree.selection()
    if sel:
        entry = app.vault.entries.get(sel[0])
        if entry:
            app.clipboard_clear()
            app.clipboard_append(entry.get_password())
            # schedule clipboard clear
            app.after(Config.CLIPBOARD_TIMEOUT * 1000, app.clipboard_clear)


def _delete_sel(app, tree) -> None:
    from tkinter import messagebox as mb

    sel = tree.selection()
    if not sel:
        return
    name = sel[0]
    if not mb.askyesno(
        "Confirmar", f"Remover '{name}' do vault?", parent=tree.winfo_toplevel()
    ):
        return
    try:
        app.vault.delete_entry(name)
        tree.delete(name)
    except ValueError as exc:
        mb.showerror("Erro", f"Erro ao excluir: {exc}", parent=tree.winfo_toplevel())
    except Exception as exc:
        mb.showerror("Erro", f"Erro inesperado: {exc}", parent=tree.winfo_toplevel())


def _persist_order(app, new_order: list) -> None:
    if set(new_order) != set(app.vault.entries.keys()):
        return
    app.vault.entry_order = new_order.copy()
    app.vault._modified = True
    app.vault._save()
