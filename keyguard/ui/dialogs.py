"""Secure password dialogs for KeyGuard."""

from __future__ import annotations

import tkinter as tk
from tkinter import messagebox as mb

from keyguard.ui.ttk_compat import ttk

from keyguard.util.memory import SecureMemory


class SecurePasswordDialog:
    """Modal dialog that returns a SecureMemory object (never a plain string)."""

    @staticmethod
    def ask(parent, title="Password", prompt="Enter the password:"):
        dlg = tk.Toplevel(parent)
        dlg.title(title)
        dlg.grab_set()

        var = tk.StringVar()
        ttk.Label(dlg, text=prompt).pack(padx=20, pady=10)
        ent = ttk.Entry(dlg, textvariable=var, show="*", width=30)
        ent.pack(padx=20, pady=5)
        ent.focus()

        res = {"pw": None}

        def _ok():
            raw = var.get()
            if not raw:
                mb.showerror("Error", "Password must not be empty.", parent=dlg)
                return
            res["pw"] = SecureMemory(raw)
            var.set("")
            dlg.destroy()

        def _cancel():
            var.set("")
            dlg.destroy()

        btns = ttk.Frame(dlg)
        btns.pack(pady=10)
        ttk.Button(btns, text="OK", command=_ok).pack(side="left", padx=5)
        ttk.Button(btns, text="Cancel", command=_cancel).pack(side="left", padx=5)
        ent.bind("<Return>", lambda *_: _ok())
        dlg.bind("<Escape>", lambda *_: _cancel())
        dlg.wait_window()
        return res["pw"]
