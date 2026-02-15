"""KeyGuardApp — main GUI application (Tkinter / ttkbootstrap)."""

from __future__ import annotations

import hashlib
import logging
import string
import sys
import tkinter as tk
from pathlib import Path
from tkinter import messagebox as mb
from tkinter import simpledialog as sd
from typing import Optional

from keyguard.config import CHARSETS, MIN_TOTAL_BITS, OPT_TO_KEY, Config
from keyguard.crypto.engine import CryptoEngine, PasswordGenerator
from keyguard.storage.backend import StorageBackend
from keyguard.ui.dialogs import SecurePasswordDialog
from keyguard.ui.ttk_compat import INFO, ttk
from keyguard.ui.views import build_main_view, build_vault_viewer
from keyguard.util.memory import PasswordTimeout, SecureMemory
from keyguard.vault.manager import VaultManager

logger = logging.getLogger("keyguard.ui")


class KeyGuardApp(ttk.Window):
    """Main GUI application, coupled to the security core."""

    def __init__(self, vault_path: Path, data_dir: Path):
        super().__init__(themename="superhero")

        self._master_pw: Optional[SecureMemory] = None
        self.title("KeyGuard 4.0")
        self.geometry("580x480")
        self.resizable(False, False)

        # -- backend --
        self.storage = StorageBackend(vault_path)
        self.crypto = CryptoEngine(Config.get_kdf_params(data_dir))
        self.vault = VaultManager(self.storage, self.crypto)
        self.password_gen = PasswordGenerator()

        # -- master password --
        pw_mem = SecurePasswordDialog.ask(
            self, title="Senha-mestra", prompt="Digite a senha do vault:"
        )
        if pw_mem is None or len(pw_mem) == 0:
            self.destroy()
            return
        self._master_pw = pw_mem

        try:
            if self.storage.exists():
                try:
                    self.vault.open(self._master_pw)
                except Exception as exc:
                    mb.showerror("Erro", f"Senha incorreta ou vault corrompido:\n{exc}")
                    self.destroy()
                    return
            else:
                if not mb.askyesno("Novo vault", "Nenhum vault encontrado. Criar novo?"):
                    self.destroy()
                    return
                try:
                    self.vault.create_new(self._master_pw)
                except ValueError as exc:
                    mb.showerror("Erro", f"Erro ao criar vault:\n{exc}")
                    self.destroy()
                    return
        except Exception:
            if self._master_pw:
                self._master_pw.clear()
            raise

        # -- password timeout --
        self._pw_timeout = PasswordTimeout(self._master_pw, timeout=Config.SESSION_TIMEOUT)
        reset = self._pw_timeout.reset
        self.bind_all("<Any-KeyPress>", lambda _: reset())
        self.bind_all("<Any-Button>", lambda _: reset())

        # -- UI --
        self._build_menu()
        build_main_view(self)

    # ------------------------------------------------------------------ menu
    def _build_menu(self):
        menubar = tk.Menu(self)
        m = tk.Menu(menubar, tearoff=0)
        m.add_command(label="Trocar Senha Mestra", command=self._change_master)
        m.add_command(label="Atualizar Todas as Senhas", command=self._update_all_passwords)
        menubar.add_cascade(label="Menu", menu=m)
        self.config(menu=menubar)

    # ----------------------------------------------------------- change master
    def _change_master(self):
        old = sd.askstring("Trocar Senha", "Senha atual:", show="*", parent=self)
        if old is None:
            return
        new = sd.askstring("Trocar Senha", "Nova senha-mestra:", show="*", parent=self)
        if new is None:
            return
        conf = sd.askstring("Trocar Senha", "Confirme a nova senha-mestra:", show="*", parent=self)
        if conf is None or new != conf:
            mb.showerror("Erro", "Confirmação não confere", parent=self)
            return
        try:
            self.vault.change_password(SecureMemory(old), SecureMemory(new))
            mb.showinfo("Sucesso", "Senha-mestra alterada", parent=self)
        except Exception as exc:
            mb.showerror("Erro", str(exc), parent=self)

    # -------------------------------------------------------- bulk update
    def _update_all_passwords(self):
        if not self.vault.entries:
            mb.showinfo("Aviso", "O vault está vazio.", parent=self)
            return
        msg = (
            f"Serão geradas novas senhas para {len(self.vault.entries)} entradas.\n\n"
            "As senhas antigas serão PERMANENTEMENTE substituídas "
            "e um backup será criado.\n\nDeseja continuar?"
        )
        if not mb.askyesno("Confirmar Atualização", msg, icon="warning", parent=self):
            return
        if not mb.askyesno(
            "Última Confirmação",
            "Tem certeza? Esta ação não pode ser desfeita!",
            icon="warning",
            parent=self,
        ):
            return

        try:
            prog = ttk.Toplevel(self)
            prog.title("Atualizando")
            prog.geometry("280x110")
            prog.resizable(False, False)
            ttk.Label(prog, text="Gerando novas senhas...").pack(pady=10)
            bar = ttk.Progressbar(prog, mode="indeterminate", length=220, bootstyle=INFO)
            bar.pack(pady=10)
            bar.start(10)
            prog.update()

            total = self.vault.update_all_passwords(self.password_gen)
            prog.destroy()
            mb.showinfo("Concluído", f"{total} senhas atualizadas com sucesso.", parent=self)
        except Exception as exc:
            if "prog" in locals():
                prog.destroy()
            mb.showerror(
                "Erro",
                f"Falha ao atualizar senhas:\n{exc}\n\n"
                "O vault foi restaurado ao estado anterior.",
                parent=self,
            )
            try:
                self.vault.close()
                self.vault = VaultManager(self.storage, self.crypto)
                self.vault.open(self._master_pw)
            except Exception as reload_exc:
                logger.critical("Error reloading vault: %s", reload_exc)

    # -------------------------------------------------------- callbacks
    def _make_pwd(self) -> str:
        try:
            length = int(self.spin.get())
            length = max(Config.MIN_GENERATED_PASSWORD_LENGTH, min(128, length))
            if int(self.spin.get()) != length:
                self.spin.set(str(length))
        except ValueError:
            length = 16
            self.spin.set(str(length))
        charset = CHARSETS[OPT_TO_KEY[self.opt.get()]]
        return self.password_gen.generate(length, charset)

    def _on_generate(self, *_):
        pwd = self._make_pwd()
        keyset = OPT_TO_KEY[self.opt.get()]
        charset = CHARSETS[keyset]
        bits = PasswordGenerator.calculate_entropy(pwd, charset)
        self.var_pwd.set(pwd)
        self.bar["value"] = min(bits, 120)

        msg = "Entropia: %.1f bits" % bits
        if bits < MIN_TOTAL_BITS:
            msg += " (fraco)"
        classes = {
            "lower": any(c in string.ascii_lowercase for c in pwd),
            "upper": any(c in string.ascii_uppercase for c in pwd),
            "digit": any(c in string.digits for c in pwd),
            "symbol": any(c in string.punctuation for c in pwd),
        }
        if sum(classes.values()) < 2:
            msg += " (classe fraca)"
        self.lbl.config(text=msg)

        if self.flag_save.get():
            name = self.ent_app.get().strip() or "Sem_nome"
            try:
                self.vault.add_entry(name, pwd)
            except ValueError:
                self.vault.update_entry(name, password=pwd)

    def _on_copy(self, *_):
        s = self.var_pwd.get()
        if s:
            self.clipboard_clear()
            self.clipboard_append(s)
            # Auto-clear clipboard after timeout
            self.after(Config.CLIPBOARD_TIMEOUT * 1000, self.clipboard_clear)

    def _on_clear(self, *_):
        self.clipboard_clear()
        self.var_pwd.set("")
        self.bar["value"] = 0
        self.lbl.config(text="Entropia / força")
        if self.chk_eye.instate(["selected"]):
            self.chk_eye.state(["!selected"])
            self.ent_pwd.config(show="•")

    def _vault_view(self):
        build_vault_viewer(self)

    # -------------------------------------------------------- cleanup
    def destroy(self):
        try:
            if hasattr(self, "_pw_timeout"):
                self._pw_timeout.cancel()
            self.clipboard_clear()
            if hasattr(self, "var_pwd"):
                self.var_pwd.set("")
            if hasattr(self, "vault"):
                self.vault.close()
            if hasattr(self, "_master_pw") and self._master_pw is not None:
                self._master_pw.clear()
        except Exception as exc:
            logger.error("Error during cleanup: %s", exc)
        finally:
            super().destroy()
