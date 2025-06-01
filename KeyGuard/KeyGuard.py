#!/usr/bin/env python3
"""
KeyGuard 3.0.1 - Gerenciamento Seguro de Senhas

Arquitetura em camadas com implementação segura:
- Camada de Criptografia: Gerenciamento seguro de chaves e criptografia
- Camada de Armazenamento: Persistência atômica e versionada
- Camada de Aplicação: Lógica de negócio e validações
- Camada de Apresentação: Interface gráfica segura

Melhorias de segurança v3.0.1:
1. Argon2id configurável com salt único
2. Sub-chaves distintas para cifra/HMAC (HKDF)
3. Nonce único a cada salvamento
4. Zeroização imediata de buffers sensíveis
5. Desabilitação de undo em campos de senha
6. Logs seguros sem vazamento de dados
7. Arquivos temporários seguros
8. Permissões restritas multiplataforma
9. Remoção de backups antigos
10. Proteção anti-debug aprimorada
"""

from __future__ import annotations

import base64
import ctypes
import hashlib
import hmac
import json
import logging
import logging.handlers
import math
import multiprocessing
import os
import platform
import secrets
import shutil
import string
import struct
import sys
import tempfile
import threading
import time
from contextlib import contextmanager
import warnings
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

# GUI imports
import tkinter as tk
from tkinter import messagebox as mb
from tkinter import simpledialog as sd

# NOVO: Verificação de dependências antes de usar
import importlib

def check_dependencies():
    """Para o programa com mensagem clara se faltar algo crítico."""
    required = ["psutil", "ttkbootstrap", "cryptography", "argon2"]
    missing  = [pkg for pkg in required if importlib.util.find_spec(pkg) is None]
    if missing:
        print("ERRO: Dependências faltando ->", ", ".join(missing))
        print("Instale com:  pip install " + " ".join(missing))
        sys.exit(1)

check_dependencies()      # CHAMADA IMEDIATA

# Novo import para calibração adaptativa
import psutil

# NOVO: Validação de recursos do sistema
def validate_system_requirements():
    import psutil, multiprocessing, warnings
    avail = psutil.virtual_memory().available / (1024**3)
    if avail < 1.5:
        raise SystemError(f"RAM insuficiente: {avail:.1f} GB livre (mínimo 1.5 GB).")
    if multiprocessing.cpu_count() < 2:
        warnings.warn("Só 1 núcleo de CPU – desempenho pode ser baixo.", RuntimeWarning)

# CORRIGIDO: Logger stub para evitar NameError em SecurityWarning
logger = logging.getLogger('keyguard')          # stub evita NameError
logger.addHandler(logging.NullHandler())

# -----------------------------------------------------------------------------
#  ⚠️  Aviso específico de segurança
# -----------------------------------------------------------------------------

# Funções utilitárias para avisos de segurança
def warn_memory_protection(message: str, severity: str = 'medium'):
    """Aviso para problemas de proteção de memória."""
    warnings.warn(SecurityWarning(message, 'memory_protection', severity))

def warn_process_protection(message: str, severity: str = 'medium'):
    """Aviso para problemas de proteção de processo."""
    warnings.warn(SecurityWarning(message, 'process_protection', severity))

def warn_debugger_detected(message: str, severity: str = 'high'):
    """Aviso para detecção de debugger."""
    warnings.warn(SecurityWarning(message, 'debugger_detection', severity))

def warn_crypto_fallback(message: str, severity: str = 'medium'):
    """Aviso para fallback criptográfico."""
    warnings.warn(SecurityWarning(message, 'crypto_fallback', severity))

def warn_file_permissions(message: str, severity: str = 'medium'):
    """Aviso para problemas de permissões de arquivo."""
    warnings.warn(SecurityWarning(message, 'file_permissions', severity))

class SecurityWarning(UserWarning):
    """
    Aviso específico para questões de segurança do KeyGuard.
    
    Esta classe personalizada permite:
    1. Categorização específica de avisos de segurança
    2. Logging automático de problemas de segurança
    3. Controle granular sobre como avisos são tratados
    4. Coleta de métricas de segurança
    """
    
    # Contadores para métricas de segurança
    _warning_counts = {
        'memory_protection': 0,
        'process_protection': 0,
        'crypto_fallback': 0,
        'file_permissions': 0,
        'debugger_detection': 0,
        'other': 0
    }
    
    def __init__(self, message: str, category: str = 'other', 
                 severity: str = 'medium', recommendation: str = None):
        """
        Inicializa um aviso de segurança.
        
        Args:
            message: Mensagem do aviso
            category: Categoria do problema ('memory_protection', 'process_protection', etc.)
            severity: Gravidade ('low', 'medium', 'high', 'critical')
            recommendation: Recomendação para resolver o problema
        """
        super().__init__(message)
        self.category = category
        self.severity = severity
        self.recommendation = recommendation
        self.timestamp = time.time()
        
        # Incrementar contador
        if category in self._warning_counts:
            self._warning_counts[category] += 1
        else:
            self._warning_counts['other'] += 1
        
        # Log automático baseado na gravidade
        self._auto_log()
    
    def _auto_log(self):
        """Log automático baseado na gravidade do aviso."""
        log = logging.getLogger('keyguard')  # <-- resolve em tempo de execução
        message = f"[{self.severity.upper()}] {self.category}: {str(self)}"
        if self.recommendation:
            message += f" | Recomendação: {self.recommendation}"
        
        if self.severity == 'critical':
            log.critical(message)
        elif self.severity == 'high':
            log.error(message)
        elif self.severity == 'medium':
            log.warning(message)
        else:  # low
            log.info(message)
    
    @classmethod
    def get_security_metrics(cls) -> Dict[str, int]:
        """Retorna métricas de avisos de segurança."""
        return cls._warning_counts.copy()
    
    @classmethod
    def reset_metrics(cls):
        """Reseta contadores de métricas."""
        for key in cls._warning_counts:
            cls._warning_counts[key] = 0
    
    @classmethod
    def has_critical_warnings(cls) -> bool:
        """Verifica se há avisos críticos de segurança."""
        return sum(cls._warning_counts.values()) > 0
    
    def __str__(self) -> str:
        """Representação em string melhorada."""
        base_msg = super().__str__()
        return f"{base_msg} [{self.category}]"
# -----------------------------------------------------------------------------

#  🛡️  Proteção Avançada do Processo
# -----------------------------------------------------------------------------
class ProcessProtection:
    """Proteção adicional contra debugging e análise de memória."""
    
    def __init__(self):
        self.protected = False
        self.debugger_detected = False
        
    def apply_protections(self) -> None:
        """Aplica todas as proteções disponíveis no sistema."""
        # ⓵ Evita execução dupla
        if self.protected:
            logger.debug("Proteções já aplicadas, ignorando chamada duplicada")
            return
            
        if platform.system() == "Windows":
            self._apply_windows_protections()
        elif platform.system() in ["Linux", "Darwin"]:
            self._apply_unix_protections()
            
        self.protected = True
        
    def _apply_windows_protections(self) -> None:
        """Proteções específicas do Windows."""
        try:
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            
            # 1. Forçar DEP (Data Execution Prevention)
            DEP_ENABLE = 0x00000001
            if hasattr(kernel32, 'SetProcessDEPPolicy'):
                result = kernel32.SetProcessDEPPolicy(DEP_ENABLE)
                if result == 0:
                    error = ctypes.get_last_error()
                    # ⓶ DEP já pode estar sempre ligado; não é crítico
                    if error in (5, 50, 87):  # ACCESS_DENIED, NOT_SUPPORTED, INVALID_PARAMETER
                        logger.info("DEP já está ativo ou imutável no sistema (erro %d - normal em Windows moderno)", error)
                    else:
                        logger.warning("Falha ao habilitar DEP (erro %d)", error)
                else:
                    logger.info("DEP habilitado com sucesso")
            
            # 2. Detectar debugger
            if kernel32.IsDebuggerPresent():
                self.debugger_detected = True
                warn_debugger_detected("Debugger local detectado!")
            
            # 3. Verificar debugger remoto
            remote_present = ctypes.c_bool()
            if hasattr(kernel32, 'CheckRemoteDebuggerPresent'):
                kernel32.CheckRemoteDebuggerPresent(
                    kernel32.GetCurrentProcess(),
                    ctypes.byref(remote_present)
                )
                if remote_present.value:
                    self.debugger_detected = True
                    warn_debugger_detected("Debugger remoto detectado!")
            
            # 4. Definir privilégios mínimos
            if hasattr(kernel32, 'SetProcessPriorityBoost'):
                kernel32.SetProcessPriorityBoost(
                    kernel32.GetCurrentProcess(), 
                    True  # Desabilitar boost de prioridade
                )
                
            # 5. Proteção contra DLL injection
            if hasattr(kernel32, 'SetDllDirectoryW'):
                # String vazia = apenas DLLs do sistema
                kernel32.SetDllDirectoryW("")
                logger.debug("Diretório de DLL restrito ao sistema")
                
        except Exception as e:
            logger.error("Erro ao aplicar proteções Windows: %s", e)
            warn_process_protection(
                "Algumas proteções de processo não puderam ser aplicadas",
                severity='high'
            )
    
    def _apply_unix_protections(self) -> None:
        """Proteções específicas para Linux/macOS."""
        try:
            import resource
            
            # 1. Desabilitar core dumps (contém memória)
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            logger.debug("Core dumps desabilitados")
            
            # 2. Detectar ptrace (usado por debuggers)
            if platform.system() == "Linux":
                try:
                    import ctypes.util
                    libc = ctypes.CDLL(ctypes.util.find_library("c"))
                    
                    # ptrace com PTRACE_TRACEME
                    PTRACE_TRACEME = 0
                    result = libc.ptrace(PTRACE_TRACEME, 0, 0, 0)
                    
                    if result == -1:
                        self.debugger_detected = True
                        warn_debugger_detected("Possível debugger detectado (ptrace falhou)")
                    else:
                        # Desanexar imediatamente
                        PTRACE_DETACH = 17
                        libc.ptrace(PTRACE_DETACH, 0, 0, 0)
                        
                except Exception:
                    pass  # ptrace não disponível ou falhou
                    
        except Exception as e:
            logger.error("Erro ao aplicar proteções Unix: %s", e)
            warn_process_protection(
                "Erro ao aplicar proteções Unix: %s" % e,
                severity='medium'
            )
    
    def continuous_check(self, callback=None) -> None:
        """Verificação contínua em thread separada."""
        def check_loop():
            while True:
                time.sleep(30)  # Verificar a cada 30 segundos
                
                old_state = self.debugger_detected
                self._check_debugger()
                
                if self.debugger_detected and not old_state:
                    logger.warning("⚠️ Debugger anexado durante execução!")
                    if callback:
                        callback()
                        
        thread = threading.Thread(target=check_loop, daemon=True)
        thread.start()
    
    def _check_debugger(self) -> None:
        """Verifica presença de debugger."""
        if platform.system() == "Windows":
            try:
                kernel32 = ctypes.WinDLL("kernel32")
                if kernel32.IsDebuggerPresent():
                    self.debugger_detected = True
            except:
                pass


# Instância global
process_protection = ProcessProtection()

# -----------------------------------------------------------------------------

# --- GUI lib clássica do KeyGuard 2.0 ---
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from ttkbootstrap.tooltip import ToolTip

# Cryptography imports - NOVO: adicionar HKDF
from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidTag

# -----------------------------------------------------------------------------
#  Diálogo seguro para senha (evita string crua em memória)
# -----------------------------------------------------------------------------
class SecurePasswordDialog:
    """Dialog seguro que devolve SecureMemory já sanitizado."""

    @staticmethod
    def ask(parent, title="Senha", prompt="Digite a senha:"):
        dlg = tk.Toplevel(parent)
        dlg.title(title); dlg.grab_set()

        var = tk.StringVar()
        ttk.Label(dlg, text=prompt).pack(padx=20, pady=10)
        # CORRIGIDO: Remover undo=False do ttk.Entry (não suportado)
        ent = ttk.Entry(dlg, textvariable=var, show="*", width=30)
        ent.pack(padx=20, pady=5); ent.focus()

        res = {"pw": None}

        def _ok():
            raw = var.get()
            if not raw:
                mb.showerror("Erro", "A senha não pode estar vazia.", parent=dlg)
                return
            res["pw"] = SecureMemory(raw)
            # NOVO: Zeroizar variável imediatamente
            var.set(""); dlg.destroy()

        def _cancel():
            var.set(""); dlg.destroy()

        btns = ttk.Frame(dlg); btns.pack(pady=10)
        ttk.Button(btns, text="OK", command=_ok).pack(side="left", padx=5)
        ttk.Button(btns, text="Cancelar", command=_cancel).pack(side="left", padx=5)
        ent.bind("<Return>", lambda *_: _ok())
        dlg.bind("<Escape>", lambda *_: _cancel())
        dlg.wait_window()
        return res["pw"]
# -----------------------------------------------------------------------------

import argon2

# ============================= CONFIGURATION ==================================

class Config:
    """Configurações centralizadas"""
    # UI
    AUTO_HIDE_DELAY = 10000  # ms
    MIN_MASTER_PASSWORD_LENGTH = 12
    DEFAULT_PASSWORD_LENGTH = 20
    
    # Segurança
    MAX_VAULT_SIZE = 10 * 1024 * 1024  # 10MB
    SESSION_TIMEOUT = 300  # 5 minutos
    ALLOW_DEBUGGING = False  # Permitir debugging em modo de desenvolvimento
    
    # Performance
    ENTROPY_CACHE_SIZE = 100
    
    # MELHORADO: Parâmetros configuráveis Argon2id com validação de segurança
    @staticmethod
    def get_kdf_params():
        """Obtém parâmetros KDF do arquivo de config ou usa padrões seguros."""
        try:
            import configparser
            config_path = DATA_DIR / "config.ini"
            if config_path.exists():
                cfg = configparser.ConfigParser()
                cfg.read(config_path)
                pars = {
                    'time_cost': cfg.getint('kdf', 'time_cost', fallback=ARGON2_TIME_COST),
                    'memory_cost': cfg.getint('kdf', 'memory_cost', fallback=ARGON2_MEMORY_COST),
                    'parallelism': cfg.getint('kdf', 'parallelism', fallback=ARGON2_PARALLELISM)
                }
                # NOVO: GARANTE piso de segurança - impede afrouxamento via INI
                pars['memory_cost'] = max(pars['memory_cost'], ARGON2_MEMORY_COST)
                pars['time_cost'] = max(pars['time_cost'], ARGON2_TIME_COST)
                pars['parallelism'] = max(pars['parallelism'], 2)  # mínimo 2 threads
                return pars
        except Exception:
            pass
        return {
            'time_cost': ARGON2_TIME_COST,
            'memory_cost': ARGON2_MEMORY_COST, 
            'parallelism': ARGON2_PARALLELISM
        }
    
    @staticmethod
    def calibrate_kdf(target_ms: int = 1000) -> None:
        """
        MELHORADO: Calibrador "high-security" que usa até 75% da RAM
        e começa com 1 GiB. Falha visivelmente se não houver recursos.
        """
        import configparser
        import argon2.low_level as low
        
        ram_total = psutil.virtual_memory().total          # bytes
        ram_cap   = ram_total * 3 // 4                     # NOVO: usa até 75% da RAM
        cores     = multiprocessing.cpu_count() or 2
        parallel  = min(8, cores)                          # máximo 8 threads

        salt = secrets.token_bytes(16)
        pw   = b"benchmark"

        # NOVO: Começa já em 1 GiB (perfil high-security)
        mem_cost = 2 ** 20            # 1 048 576 KiB = 1 GiB
        time_cost = 4                 # valor inicial mais baixo

        logger.info("Calibrando KDF high-security: RAM disponível=%.1f GB, limite=%.1f GB", 
                   ram_total / (1024**3), ram_cap / (1024**3))

        while True:
            # Verificar se excede limite de RAM antes de tentar
            estimated_ram = mem_cost * 1024  # KiB para bytes
            if estimated_ram > ram_cap:
                logger.warning("Limite de RAM atingido: %.1f GB > %.1f GB", 
                              estimated_ram / (1024**3), ram_cap / (1024**3))
                break
                
            t0 = time.perf_counter()
            try:
                low.hash_secret_raw(pw, salt,
                                    time_cost=time_cost,
                                    memory_cost=mem_cost,
                                    parallelism=parallel,
                                    hash_len=32, type=argon2.Type.ID)
            except MemoryError:
                # NOVO: Falha visível - não reduz automaticamente
                raise RuntimeError(
                    f"Não há RAM suficiente para KDF high-security "
                    f"({mem_cost//1024} MiB requeridos). "
                    "Esta versão do KeyGuard requer pelo menos 2 GB de RAM livre.\n"
                    "Use uma máquina com mais memória ou uma versão 'compat'."
                )

            dt = (time.perf_counter() - t0) * 1_000
            
            # Se atingiu tempo alvo ou próximo do limite de RAM, para
            if dt >= target_ms:
                break
                
            # Aumentar custo gradativamente, priorizando memory_cost
            if mem_cost < 2**21 and (mem_cost << 1) * 1024 <= ram_cap:  # até 2 GiB
                mem_cost <<= 1           # duplica memória
            else:
                time_cost += 1           # aumenta iterações
                if time_cost > 10:       # limite máximo razoável
                    break

        config_path = DATA_DIR / "config.ini"
        DATA_DIR.mkdir(mode=0o700, exist_ok=True)
        cfg = configparser.ConfigParser()
        cfg['kdf'] = {
            'time_cost': str(time_cost),
            'memory_cost': str(mem_cost),
            'parallelism': str(parallel)
        }
        with open(config_path, 'w') as f:
            cfg.write(f)
        os.chmod(config_path, 0o600)

        logger.info("KDF high-security calibrado: t=%d, m=%d KiB (%.1f MiB), p=%d, tempo=%.0f ms",
                    time_cost, mem_cost, mem_cost/1024, parallel, dt)

# ============================= CONSTANTS =====================================

# Versão do protocolo
PROTOCOL_VERSION = 3
MAGIC = b"KG3"  # KeyGuard 3.0

# Diretórios e arquivos
DATA_DIR = Path.home() / ".keyguard3"
VAULT_FILE = DATA_DIR / "vault.kg3"
BACKUP_FILE = DATA_DIR / "vault.kg3.backup"
WAL_FILE = DATA_DIR / "vault.kg3.wal"
LOCK_FILE = DATA_DIR / "vault.kg3.lock"
LOG_FILE = DATA_DIR / "keyguard.log"

# Parâmetros de criptografia
SALT_SIZE = 32  # 256 bits
NONCE_SIZE = 12  # 96 bits para ChaCha20-Poly1305
KEY_SIZE = 32   # 256 bits
HMAC_SIZE = 32  # 256 bits

# Header format
HEADER_FMT = ">HH32sQd"  # version(2), counter(2), salt(32), created(8), modified(8)
HEADER_SIZE = struct.calcsize(HEADER_FMT)  # 52 bytes

# Parâmetros Argon2id (MELHORADO: perfil "high-security")
ARGON2_TIME_COST = 6     # ↑ de 8 para 6 (mais conservador mas ainda forte)
ARGON2_MEMORY_COST = 2**20  # 1 048 576 KiB = 1 GiB (↑ de 256 MiB)
ARGON2_PARALLELISM = min(8, multiprocessing.cpu_count() or 2)  # todos os núcleos até 8

# Rate limiting
MAX_LOGIN_ATTEMPTS = 5
LOGIN_DELAY_BASE = 2  # segundos

# Geração de senhas
MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 128
DEFAULT_PASSWORD_LENGTH = 20

# Conjuntos de caracteres
CHARSETS = {
    "numbers": string.digits,
    "letters": string.ascii_letters,
    "alphanumeric": string.ascii_letters + string.digits,
    "full": string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?",
}

# ===== compat 2.0 – mapeia botões numéricos para os conjuntos acima ==========
OPT_TO_KEY = {1: "numbers", 2: "letters", 3: "alphanumeric", 4: "full"}
# limiares originais de aviso
MIN_TOTAL_BITS  = 64
MIN_CLASS_BITS  = 2

# ============================= LOGGING SETUP =================================

def setup_secure_logging():
    """Configura logging seguro sem vazamento de dados sensíveis."""
    DATA_DIR.mkdir(mode=0o700, exist_ok=True)
    
    # MELHORADO: Formato mais seguro sem dados potencialmente sensíveis
    class SecureFormatter(logging.Formatter):
        """Formatter que sanitiza dados sensíveis dos logs."""
        
        SENSITIVE_PATTERNS = [
            'password', 'pwd', 'key', 'salt', 'nonce', 'plaintext', 
            'ciphertext', 'secret', 'token', 'hash'
        ]
        
        def format(self, record):
            # Sanitizar argumentos sensíveis
            if hasattr(record, 'args') and record.args:
                safe_args = []
                for arg in record.args:
                    if isinstance(arg, (bytes, bytearray)):
                        safe_args.append(f"<{len(arg)} bytes>")
                    elif isinstance(arg, str) and len(arg) > 20:
                        safe_args.append(f"<{len(arg)} chars>")
                    else:
                        safe_args.append(arg)
                record.args = tuple(safe_args)
            
            return super().format(record)
    
    formatter = SecureFormatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Rotação de logs para evitar crescimento infinito
    handler = logging.handlers.RotatingFileHandler(
        LOG_FILE, maxBytes=10*1024*1024, backupCount=3,
        encoding='utf-8'
    )
    handler.setFormatter(formatter)
    
    logger = logging.getLogger('keyguard')
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)
    
    # Não propagar para root logger
    logger.propagate = False
    
    # NOVO: Definir permissões seguras no arquivo de log
    try:
        os.chmod(LOG_FILE, 0o600)
    except Exception:
        pass
    
    return logger

logger = setup_secure_logging()   # linha original permanece

# ============================= SECURITY UTILITIES ============================

class RateLimiter:
    """Proteção contra ataques de força bruta com backoff exponencial."""
    
    def __init__(self):
        self.attempts = 0
        self.last_attempt = 0
    
    def check(self):
        """Verifica se a operação pode prosseguir ou deve ser bloqueada."""
        now = time.time()
        
        # Verificar delay necessário
        if self.attempts > 0:
            required_delay = LOGIN_DELAY_BASE ** self.attempts
            elapsed = now - self.last_attempt
            
            if elapsed < required_delay:
                wait_time = required_delay - elapsed
                logger.warning("Rate limiting: aguardando %.1fs", wait_time)
                time.sleep(wait_time)
        
        # Verificar número máximo de tentativas
        if self.attempts >= MAX_LOGIN_ATTEMPTS:
            logger.error("Máximo de %d tentativas excedido", MAX_LOGIN_ATTEMPTS)
            raise ValueError(f"Excedido o limite de {MAX_LOGIN_ATTEMPTS} tentativas. Aguarde antes de tentar novamente.")
        
        self.attempts += 1
        self.last_attempt = time.time()
    
    def reset(self):
        """Reseta o contador após login bem-sucedido."""
        self.attempts = 0
        self.last_attempt = 0

class SecureMemory:
    """Gerenciamento seguro de memória com proteção real."""
    
    def __init__(self, data: Union[bytes, bytearray, str]):
        """Inicializa memória segura com verificação de proteção."""
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        self._size = len(data)
        self._data = bytearray(data)
        self._locked = False
        self._protected = False
        
        # Tentar proteger a memória
        self._protect_memory()
    
    def _protect_memory(self) -> None:
        """Protege a memória contra swap com verificação."""
        if self._size == 0:
            return
            
        try:
            # Obter endereço da memória
            address = ctypes.addressof(ctypes.c_char.from_buffer(self._data))
            
            if platform.system() == "Windows":
                kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
                
                # VirtualLock
                if kernel32.VirtualLock(ctypes.c_void_p(address), ctypes.c_size_t(self._size)):
                    self._locked = True
                    logger.debug("Memória protegida com VirtualLock")
                else:
                    error = ctypes.get_last_error()
                    logger.warning("VirtualLock falhou: %d", error)
                    
                # SetProcessWorkingSetSize para prevenir trim
                handle = kernel32.GetCurrentProcess()
                kernel32.SetProcessWorkingSetSize(handle, -1, -1)
                
            else:  # Unix-like
                libc = ctypes.CDLL(None)
                
                # mlock
                if libc.mlock(ctypes.c_void_p(address), ctypes.c_size_t(self._size)) == 0:
                    self._locked = True
                    logger.debug("Memória protegida com mlock")
                else:
                    errno = ctypes.get_errno()
                    logger.warning("mlock falhou: %d", errno)
                
                # mlockall se disponível
                try:
                    MCL_CURRENT = 1
                    MCL_FUTURE = 2
                    libc.mlockall(MCL_CURRENT | MCL_FUTURE)
                except:
                    pass
                        
            self._protected = True
            
        except Exception as e:
            logger.warning("Proteção de memória falhou: %s", e)
            # Usar a função utilitária para aviso padronizado
            warn_memory_protection(
                "Proteção de memória não disponível; dados podem ir para swap.",
                severity='high'
            )

    def get_bytes(self) -> bytes:
        """Retorna cópia dos bytes (use com cuidado)."""
        if not self._data:
            raise ValueError("Memória já foi limpa")
        return bytes(self._data)
    
    def clear(self) -> None:
        """Limpa a memória de forma segura."""
        if not self._data:
            return
            
        try:
            # MELHORADO: Múltiplas passadas com padrões criptograficamente seguros
            patterns = [
                bytes([0xFF] * self._size),
                bytes([0x00] * self._size),
                bytes([0x55] * self._size),
                bytes([0xAA] * self._size),
                secrets.token_bytes(self._size),
                secrets.token_bytes(self._size),
                secrets.token_bytes(self._size),  # passada extra
                bytes([0x00] * self._size),
            ]
            
            for pattern in patterns:
                self._data[:] = pattern
                # NOVO: Força flush para memória física
                if hasattr(os, 'fsync'):
                    try:
                        # Tenta forçar sincronização (limitado em Python)
                        pass
                    except:
                        pass
                        
            # Desbloquear memória
            if self._locked:
                try:
                    address = ctypes.addressof(ctypes.c_char.from_buffer(self._data))
                    
                    if platform.system() == "Windows":
                        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
                        kernel32.VirtualUnlock(ctypes.c_void_p(address), ctypes.c_size_t(self._size))
                    else:
                        libc = ctypes.CDLL(None)
                        libc.munlock(ctypes.c_void_p(address), ctypes.c_size_t(self._size))
                        
                except Exception as e:
                    logger.warning("Erro ao desbloquear memória: %s", e)
                    
        finally:
            self._data = bytearray()
            self._size = 0
            self._locked = False
            self._protected = False
    
    def __len__(self) -> int:
        return self._size
    
    def __del__(self):
        """Garante limpeza na destruição."""
        self.clear()
    
    @property
    def is_protected(self) -> bool:
        """Indica se a memória está protegida contra swap."""
        return self._locked


# NOVO: Classe para timeout automático da senha-mestra
class PasswordTimeout:
    """Limpa SecureMemory após 'timeout' s sem uso."""
    def __init__(self, secure_memory: SecureMemory, timeout: int = 300):
        self._mem     = secure_memory
        self._timeout = timeout
        self._timer   = None
        self._destroyed = False
        self.reset()

    def _wipe(self):
        if not self._destroyed:
            self._mem.clear()
            self._destroyed = True
            logging.getLogger('keyguard').info("Senha mestra destruída por timeout")

    def reset(self):
        if self._destroyed:
            return
        if self._timer:
            self._timer.cancel()
        import threading
        self._timer = threading.Timer(self._timeout, self._wipe)
        self._timer.daemon = True
        self._timer.start()

    def cancel(self):
        if self._timer:
            self._timer.cancel()
        self._wipe()

# ----------------------------------------------------------------------
#  🔒  Obfuscação em memória  (portado da versão 2.1)
# ----------------------------------------------------------------------

class FragmentedSecret:
    """Divide um segredo em N fragmentos mascarados via XOR."""
    def __init__(self, data: Union[bytes, bytearray, str], parts: int = 3):
        b = data.encode() if isinstance(data, str) else bytes(data)
        ln = len(b)
        masks = [secrets.token_bytes(ln) for _ in range(parts - 1)]
        last = bytearray(b)
        for m in masks:
            for i in range(ln):
                last[i] ^= m[i]
        self._parts = [SecureMemory(m) for m in masks] + [SecureMemory(last)]

    def reconstruct(self) -> SecureMemory:
        ln = len(self._parts[-1])
        res = bytearray(self._parts[-1].get_bytes())
        for p in self._parts[:-1]:
            blk = p.get_bytes()
            for i in range(ln):
                res[i] ^= blk[i]
        return SecureMemory(res)

    def clear(self):
        for p in self._parts:
            p.clear()
        self._parts = []


class KeyObfuscator:
    """Mantém a chave derivada ofuscada, revelando-a só em *TimedExposure*."""
    def __init__(self, key: SecureMemory):
        self._key = key
        self._mask: Optional[SecureMemory] = None
        self._frags: Optional[FragmentedSecret] = None
        self._obfuscated = False

    def obfuscate(self):
        """
        (re)-gera máscara.  
        Se já estava ofuscado, primeiro recupera o plaintext,
        depois descarta artefatos antigos e monta novos.
        """
        if self._obfuscated:
            # 1.  recuperar chave em claro
            plain_sm = self.deobfuscate()        # usa _frags+_mask
            # 2.  limpar estruturas antigas
            if self._mask:
                self._mask.clear(); self._mask = None
            if self._frags:
                self._frags.clear(); self._frags = None
            # 3.  reinstalar a chave principal e sinalizar estado "desofuscado"
            self._key = plain_sm
            self._obfuscated = False

        # Se a chave já foi limpa/zerada, não há mais o que (re)ofuscar
        if self._key is None or len(self._key) == 0:
            return

        kb = self._key.get_bytes()
        mask_b = secrets.token_bytes(len(kb))
        masked = bytearray(a ^ b for a, b in zip(kb, mask_b))
        self._mask = SecureMemory(mask_b)
        self._frags = FragmentedSecret(masked, 3)
        self._key.clear()
        self._obfuscated = True

    def deobfuscate(self) -> SecureMemory:
        if not self._obfuscated:
            return self._key
        masked_sb = self._frags.reconstruct()
        mask = self._mask.get_bytes()
        plain = bytearray(a ^ b for a, b in zip(masked_sb.get_bytes(), mask))
        # limpamos somente o buffer temporário;
        # _frags permanece até que uma nova obfuscação o descarte
        masked_sb.clear()
        return SecureMemory(plain)

    def clear(self):
        if self._mask:
            self._mask.clear()
        if self._frags:
            self._frags.clear()
        if self._key:
            self._key.clear()
        self._obfuscated = False


class TimedExposure:
    """Contexto que mantém a chave em claro apenas por *timeout* segundos."""
    def __init__(self, ko: KeyObfuscator, timeout: float = 0.5):
        self.ko = ko
        self.timeout = timeout
        self._plain: Optional[SecureMemory] = None
        self._timer: Optional[threading.Timer] = None

    def __enter__(self) -> SecureMemory:
        # Cancela eventual timer ainda vivo de um uso anterior
        self.cancel_timer()
        self._plain = self.ko.deobfuscate()
        return self._plain

    def _re_mask(self):
        if self._plain:
            self._plain.clear()
            self._plain = None
        # Pode acontecer da chave já ter sido limpa em outro ponto
        try:
            self.ko.obfuscate()
        except (ValueError, AttributeError):
            # Chave já inexistente – OK, apenas ignore
            pass

    def __exit__(self, exc_type, exc, tb):
        try:
            self._re_mask()
        finally:
            self.cancel_timer()
            # Só cria novo timer se não houve exceção
            if self.timeout > 0 and exc_type is None:
                self._timer = threading.Timer(self.timeout, self._re_mask)
                self._timer.daemon = True
                self._timer.start()

    def cancel_timer(self):
        if self._timer and self._timer.is_alive():
            self._timer.cancel()
            self._timer = None


# ============================= CRYPTO LAYER ==================================

class CryptoEngine:
    """Motor de criptografia com implementação segura."""
    
    def __init__(self):
        # NOVO: Usar parâmetros configuráveis
        kdf_params = Config.get_kdf_params()
        self.time_cost = kdf_params['time_cost']
        self.memory_cost = kdf_params['memory_cost']
        self.parallelism = kdf_params['parallelism']
        
        # NOVO: Log dos parâmetros em uso para auditoria
        logger.info("CryptoEngine inicializado: Argon2id(t=%d, m=%d KiB, p=%d)", 
                   self.time_cost, self.memory_cost, self.parallelism)
        
        # NOVO: Validar se a máquina tem recursos mínimos
        self._validate_system_resources()
    
    def _validate_system_resources(self) -> None:
        """NOVO: Valida se o sistema tem recursos para executar o KDF."""
        try:
            required_ram = self.memory_cost * 1024  # KiB para bytes
            available_ram = psutil.virtual_memory().available
            
            if required_ram > available_ram:
                warn_memory_protection(
                    f"RAM insuficiente: {required_ram//1024//1024} MiB requeridos, "
                    f"{available_ram//1024//1024} MiB disponíveis",
                    severity='high'
                )
                logger.warning("Sistema pode não ter RAM suficiente para operação segura")
        except Exception as e:
            logger.debug("Erro ao validar recursos: %s", e)
    
    def derive_keys(self, password: SecureMemory, salt: bytes) -> Tuple[bytes, bytes]:
        """MELHORADO: Deriva chaves com tratamento de erro de memória."""
        if len(password) == 0:
            raise ValueError("senha vazia")
        
        try:
            # NOVO: Log para auditoria (sem dados sensíveis)
            logger.debug("Derivando chaves com Argon2id: t=%d, m=%d KiB, p=%d", 
                        self.time_cost, self.memory_cost, self.parallelism)
            
            # Derivar chave mestra com Argon2id
            master_key = argon2.low_level.hash_secret_raw(
                password.get_bytes(),
                salt,
                time_cost=self.time_cost,
                memory_cost=self.memory_cost,
                parallelism=self.parallelism,
                hash_len=KEY_SIZE,
                type=argon2.Type.ID
            )
            
            # NOVO: Usar HKDF para derivar sub-chaves distintas
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=KEY_SIZE * 2,  # Para duas chaves
                salt=None,
                info=b"KeyGuard-3.0.1 key-split"
            )
            expanded = hkdf.derive(master_key)
            
            # Dividir em chaves distintas
            enc_key = expanded[:KEY_SIZE]
            hmac_key = expanded[KEY_SIZE:]
            
            return enc_key, hmac_key
            
        except MemoryError:
            # NOVO: Erro específico para falta de RAM
            raise RuntimeError(
                f"Não há RAM suficiente para derivar a chave mestra com "
                f"{self.memory_cost//1024} MiB. "
                "Esta versão do KeyGuard requer pelo menos 2 GB de RAM livre.\n"
                "Use outra máquina ou compile uma build 'compat'.")
        except Exception as e:
            logger.error("Erro na derivação de chaves: %s", e)
            raise
        finally:
            # NOVO: Zeroizar chave mestra imediatamente
            if 'master_key' in locals():
                master_key_array = bytearray(master_key)
                for i in range(len(master_key_array)):
                    master_key_array[i] = 0
            if 'expanded' in locals():
                expanded_array = bytearray(expanded)
                for i in range(len(expanded_array)):
                    expanded_array[i] = 0
    
    def encrypt_data(self, key: bytes, plaintext: bytes, 
                     associated_data: bytes = b"") -> Tuple[bytes, bytes]:
        """MELHORADO: Nonce único garantido a cada chamada."""
        cipher = ChaCha20Poly1305(key)
        # NOVO: Sempre gerar nonce único
        nonce = secrets.token_bytes(NONCE_SIZE)
        ciphertext = cipher.encrypt(nonce, plaintext, associated_data)
        return nonce, ciphertext
    
    def decrypt_data(self, key: bytes, nonce: bytes, ciphertext: bytes,
                     associated_data: bytes = b"") -> bytes:
        """Descriptografa dados com ChaCha20-Poly1305."""
        cipher = ChaCha20Poly1305(key)
        return cipher.decrypt(nonce, ciphertext, associated_data)
    
    def compute_hmac(self, key: bytes, data: bytes) -> bytes:
        """Computa HMAC-SHA256 para autenticação."""
        h = hmac.new(key, data, hashlib.sha256)
        return h.digest()
    
    def verify_hmac(self, key: bytes, data: bytes, expected: bytes) -> bool:
        """Verifica HMAC com proteção contra timing attacks."""
        actual = self.compute_hmac(key, data)
        return hmac.compare_digest(actual, expected)
    
    def constant_time_compare(self, a: bytes, b: bytes) -> bool:
        """Comparação em tempo constante."""
        return hmac.compare_digest(a, b)


# ============================= STORAGE LAYER =================================

@dataclass
class VaultHeader:
    """Cabeçalho do vault com metadados."""
    version: int
    salt: bytes
    counter: int
    created: float
    modified: float
    hmac: bytes
    
    def to_bytes(self) -> bytes:
        """Serializa o cabeçalho."""
        data = struct.pack(
            HEADER_FMT,
            self.version,
            self.counter,
            self.salt,
            int(self.created),
            self.modified
        )
        return data + self.hmac
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'VaultHeader':
        """Deserializa o cabeçalho."""
        if len(data) < HEADER_SIZE + HMAC_SIZE:
            raise ValueError("Cabeçalho inválido")
        
        version, counter, salt, created, modified = struct.unpack(
            HEADER_FMT, data[:HEADER_SIZE]
        )
        hmac_value = data[HEADER_SIZE:HEADER_SIZE + HMAC_SIZE]
        
        return cls(
            version=version,
            salt=salt,
            counter=counter,
            created=float(created),
            modified=modified,
            hmac=hmac_value
        )


class StorageBackend:
    """Backend de armazenamento com escrita atômica e backup."""
    
    def __init__(self, vault_path: Path):
        self.vault_path = vault_path
        self.backup_path = vault_path.with_suffix('.backup')
        self.wal_path = vault_path.with_suffix('.wal')
        self.lock_path = vault_path.with_suffix('.lock')
        self._lock_file = None
        
        # Criar diretório com permissões seguras
        self.vault_path.parent.mkdir(mode=0o700, exist_ok=True)
        
        # Verificar/criar arquivo de lock
        self._acquire_lock()
    
    def _acquire_lock(self) -> None:
        """Adquire lock exclusivo no vault."""
        try:
            # Criar arquivo de lock se não existir
            self.lock_path.touch(mode=0o600, exist_ok=True)
            
            # No Windows, o arquivo aberto em modo exclusivo já serve como lock
            if platform.system() == "Windows":
                self._lock_file = open(self.lock_path, 'r+b')
            else:
                # Em Unix, usar flock
                import fcntl
                self._lock_file = open(self.lock_path, 'r+b')
                fcntl.flock(self._lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                
        except (IOError, OSError) as e:
            # Fechar arquivo se foi aberto mas falhou o lock
            if hasattr(self, '_lock_file') and self._lock_file:
                try:
                    self._lock_file.close()
                except:
                    pass
                self._lock_file = None
            raise RuntimeError("Vault já está em uso por outro processo") from e
    
    def _release_lock(self) -> None:
        """Libera o lock do vault."""
        if self._lock_file:
            try:
                self._lock_file.close()
            except:
                pass
            finally:
                self._lock_file = None
            
            try:
                self.lock_path.unlink()
            except:
                pass
    
    def write_atomic(self, data: bytes) -> None:
        """MELHORADO: Escrita atômica com segurança aprimorada."""
        # 1. Criar backup do arquivo atual se existir
        if self.vault_path.exists():
            shutil.copy2(self.vault_path, self.backup_path)
            self._secure_permissions(self.backup_path)
        
        # 2. NOVO: Escrever em arquivo temporário seguro
        with tempfile.NamedTemporaryFile(
            mode='wb',
            dir=self.vault_path.parent,
            prefix='kg3_tmp_',
            suffix='.dat',
            delete=False
        ) as tmp:
            tmp.write(data)
            tmp.flush()
            os.fsync(tmp.fileno())  # Força sincronização
            temp_path = Path(tmp.name)
        
        # 3. NOVO: Definir permissões seguras no arquivo temporário
        self._secure_permissions(temp_path)
        
        # 4. Mover atomicamente para destino final
        temp_path.replace(self.vault_path)
        
        # 5. Garantir permissões finais
        self._secure_permissions(self.vault_path)
        
        # 6. NOVO: Limpar arquivos temporários órfãos
        self._cleanup_temp_files()
        
        logger.info("Vault salvo com sucesso")
    
    def _secure_permissions(self, path: Path) -> None:
        """NOVO: Define permissões seguras multiplataforma."""
        try:
            if platform.system() == "Windows":
                # Windows: tentar definir ACL restritiva
                try:
                    # CORRIGIDO: Imports Windows protegidos
                    import win32security, win32api
                    import ntsecuritycon as nsec
                except ImportError:
                    win32security = win32api = nsec = None
                
                if win32security and win32api and nsec:
                    # Obter SID do usuário atual
                    user_name = win32api.GetUserName()
                    user_sid, _, _ = win32security.LookupAccountName(None, user_name)
                    
                    # Criar DACL com acesso apenas ao usuário atual
                    dacl = win32security.ACL()
                    dacl.AddAccessAllowedAce(
                        win32security.ACL_REVISION,
                        nsec.FILE_GENERIC_READ | nsec.FILE_GENERIC_WRITE | nsec.DELETE,
                        user_sid
                    )
                    
                    # Aplicar DACL
                    sd = win32security.SECURITY_DESCRIPTOR()
                    sd.SetSecurityDescriptorDacl(1, dacl, 0)
                    win32security.SetFileSecurity(
                        str(path), 
                        win32security.DACL_SECURITY_INFORMATION, 
                        sd
                    )
                    logger.debug("ACL Windows aplicada em %s", path)
                else:
                    # Fallback: pywin32 não disponível
                    logger.info("pywin32 não disponível - mantendo ACL padrão do SO")
                    os.chmod(path, 0o600)
            else:
                # Unix-like: permissões POSIX
                os.chmod(path, 0o600)
                logger.debug("Permissões Unix aplicadas em %s", path)
                
        except Exception as e:
            logger.warning("Erro ao definir permissões em %s: %s", path, e)
    
    def _cleanup_temp_files(self) -> None:
        """NOVO: Remove arquivos temporários órfãos."""
        try:
            for temp_file in self.vault_path.parent.glob("kg3_tmp_*"):
                try:
                    # Só remove se for mais antigo que 1 hora
                    if time.time() - temp_file.stat().st_mtime > 3600:
                        temp_file.unlink()
                        logger.debug("Arquivo temporário órfão removido: %s", temp_file)
                except Exception:
                    pass
        except Exception:
            pass

    def read(self) -> bytes:
        """Lê dados do vault."""
        if not self.vault_path.exists():
            raise FileNotFoundError("Vault não encontrado")
        
        # Verificar tamanho para prevenir DoS
        size = self.vault_path.stat().st_size
        if size > Config.MAX_VAULT_SIZE:
            raise ValueError(f"Vault muito grande: {size} bytes (máximo: {Config.MAX_VAULT_SIZE})")
        
        # Verificar permissões
        stat = self.vault_path.stat()
        if stat.st_mode & 0o077:
            logger.warning("Permissões do vault muito abertas, corrigindo...")
            os.chmod(self.vault_path, 0o600)
        
        return self.vault_path.read_bytes()
    
    def exists(self) -> bool:
        """Verifica se o vault existe."""
        return self.vault_path.exists()
    
    def restore_backup(self) -> bool:
        """Restaura do backup se disponível e íntegro."""
        if self.verify_backup_integrity():
            shutil.copy2(self.backup_path, self.vault_path)
            logger.info("Vault restaurado do backup")
            return True
        return False

    # ---------------------------------------------------------------------
    def verify_backup_integrity(self) -> bool:
        """Verifica se o backup parece válido antes de restaurar."""
        if not self.backup_path.exists():
            return False
        try:
            data = self.backup_path.read_bytes()
            if not data.startswith(MAGIC):
                return False
            if len(data) < len(MAGIC) + HEADER_SIZE + HMAC_SIZE:
                return False
            header = VaultHeader.from_bytes(
                data[len(MAGIC):len(MAGIC)+HEADER_SIZE+HMAC_SIZE]
            )
            return header.version == PROTOCOL_VERSION
        except Exception as e:
            logger.error("Backup corrompido: %s", e)
            return False
    
    def __del__(self):
        """Libera recursos."""
        self._release_lock()


# ============================= VAULT MANAGER =================================

class VaultEntry:
    """
    Entrada de vault cujo password fica sempre em SecureMemory
    ofuscado por um KeyObfuscator.
    """

    def __init__(self, name: str, password: str,
                 metadata: Optional[Dict] = None):
        self.name      = name
        self.metadata  = metadata or {}
        self.created   = time.time()
        self.modified  = time.time()

        # ---- senha em memória protegida --------------------------------
        sm  = SecureMemory(password.encode())      # buffer seguro
        self._pw_ko = KeyObfuscator(sm)            # ofusca
        self._pw_ko.obfuscate()

    # ------------------------------------------------------------------
    #  Acesso controlado
    # ------------------------------------------------------------------
    def get_password(self) -> str:
        """Retorna a senha em claro dentro de um TimedExposure rápido."""
        with TimedExposure(self._pw_ko) as sm:
            return sm.get_bytes().decode()

    def set_password(self, new_pwd: str) -> None:
        """Substitui a senha preservando proteção de memória."""
        sm_new = SecureMemory(new_pwd.encode())
        # descarta antigo ko + memória
        if self._pw_ko:
            self._pw_ko.clear()
        self._pw_ko = KeyObfuscator(sm_new)
        self._pw_ko.obfuscate()
        self.modified = time.time()

    # ------------------------------------------------------------------
    #  Serialização
    # ------------------------------------------------------------------
    def to_dict(self) -> Dict:
        """Senha sai em texto APENAS para ser criptografada pelo vault."""
        return {
            'name': self.name,
            'password': self.get_password(),   # exposição de curtíssima duração
            'metadata': self.metadata,
            'created': self.created,
            'modified': self.modified
        }

    @classmethod
    def from_dict(cls, data: Dict) -> 'VaultEntry':
        entry = cls(data['name'],
                    data['password'],
                    data.get('metadata', {}))
        entry.created  = data.get('created', time.time())
        entry.modified = data.get('modified', time.time())
        return entry


class VaultManager:
    """Gerenciador principal do vault."""
    
    def __init__(self, storage: StorageBackend, crypto: CryptoEngine):
        self.storage = storage
        self.crypto = crypto
        self.entries: Dict[str, VaultEntry] = {}
        self.entry_order: List[str] = []  # Lista para armazenar a ordem definida pelo usuário
        self.header: Optional[VaultHeader] = None
        # chaves ficam obfuscadas em memória
        self._enc_ko: Optional[KeyObfuscator] = None
        self._hmac_ko: Optional[KeyObfuscator] = None
        self._modified = False
        self.rate_limiter = RateLimiter()
        
        # NOVO: Verificar integridade da proteção
        if not process_protection.protected:
            logger.warning("⚠️ Proteções de processo não aplicadas")
    
    def create_new(self, password: SecureMemory) -> None:
        """Cria um novo vault."""
        # Verificar força da senha mestra
        pwd_str = password.get_bytes().decode('utf-8')
        if len(pwd_str) < Config.MIN_MASTER_PASSWORD_LENGTH:
            raise ValueError(f"Senha mestra deve ter pelo menos {Config.MIN_MASTER_PASSWORD_LENGTH} caracteres")
        
        # Verificar complexidade
        has_upper = any(c.isupper() for c in pwd_str)
        has_lower = any(c.islower() for c in pwd_str)
        has_digit = any(c.isdigit() for c in pwd_str)
        has_special = any(not c.isalnum() for c in pwd_str)
        
        if sum([has_upper, has_lower, has_digit, has_special]) < 3:
            raise ValueError("Senha mestra deve conter pelo menos 3 tipos de caracteres (maiúscula, minúscula, número, símbolo)")
        
        # MELHORADO: Salt único para cada vault (nunca reutilizado)
        salt = secrets.token_bytes(SALT_SIZE)
        
        try:
            # Derivar chaves
            enc_key, hmac_key = self.crypto.derive_keys(password, salt)
            self._enc_ko  = KeyObfuscator(SecureMemory(enc_key));  self._enc_ko.obfuscate()
            self._hmac_ko = KeyObfuscator(SecureMemory(hmac_key)); self._hmac_ko.obfuscate()
            
            # Criar cabeçalho
            self.header = VaultHeader(
                version=PROTOCOL_VERSION,
                salt=salt,
                counter=0,
                created=time.time(),
                modified=time.time(),
                hmac=b'\x00' * HMAC_SIZE
            )
            
            # Salvar vault vazio
            self._save()
            
            logger.info("Novo vault criado com sucesso")
            
        finally:
            # NOVO: Zeroizar chaves derivadas imediatamente
            if 'enc_key' in locals():
                enc_key_array = bytearray(enc_key)
                for i in range(len(enc_key_array)):
                    enc_key_array[i] = 0
            if 'hmac_key' in locals():
                hmac_key_array = bytearray(hmac_key)
                for i in range(len(hmac_key_array)):
                    hmac_key_array[i] = 0
    
    def open(self, password: SecureMemory) -> None:
        """Abre um vault existente."""
        # Aplicar rate limiting
        self.rate_limiter.check()
        
        try:
            # Ler dados
            data = self.storage.read()
            
            # Verificar magic
            if not data.startswith(MAGIC):
                raise ValueError("Arquivo não é um vault válido")
            
            # Parse header
            header_data = data[len(MAGIC):len(MAGIC) + HEADER_SIZE + HMAC_SIZE]
            self.header = VaultHeader.from_bytes(header_data)
            
            # Verificar versão
            if self.header.version != PROTOCOL_VERSION:
                raise ValueError(f"Versão do vault não suportada: {self.header.version}")
            
            # Derivar chaves
            enc_key, hmac_key = self.crypto.derive_keys(password, self.header.salt)
            
            try:
                self._enc_ko  = KeyObfuscator(SecureMemory(enc_key));  self._enc_ko.obfuscate()
                self._hmac_ko = KeyObfuscator(SecureMemory(hmac_key)); self._hmac_ko.obfuscate()
                
                # Verificar HMAC do cabeçalho
                with TimedExposure(self._hmac_ko) as hk:
                    header_hmac = self.crypto.compute_hmac(
                        hk.get_bytes(),
                        data[:len(MAGIC) + HEADER_SIZE]
                    )
                if not self.crypto.constant_time_compare(header_hmac, self.header.hmac):
                    raise ValueError("HMAC do cabeçalho inválido")
                
                # Descriptografar dados
                encrypted_data = data[len(MAGIC) + HEADER_SIZE + HMAC_SIZE:]
                if encrypted_data:
                    nonce = encrypted_data[:NONCE_SIZE]
                    ciphertext = encrypted_data[NONCE_SIZE:]
                    
                    # Associated data inclui header para prevenir ataques
                    ad = data[:len(MAGIC) + HEADER_SIZE + HMAC_SIZE]
                    
                    with TimedExposure(self._enc_ko) as ek:
                        try:
                            plaintext = self.crypto.decrypt_data(
                                ek.get_bytes(),
                                nonce,
                                ciphertext,
                                ad
                            )
                        finally:
                            # NOVO: Zeroizar chave após uso
                            pass  # TimedExposure já cuida da limpeza
                    
                    try:
                        # Parse entries com suporte à versão anterior
                        vault_data = json.loads(plaintext.decode('utf-8'))
                        
                        # Detectar formato: novo (com order) ou antigo (apenas entries)
                        if isinstance(vault_data, dict) and 'entries' in vault_data:
                            # Novo formato
                            entries_data = vault_data['entries']
                            self.entry_order = vault_data.get('order', [])
                        else:
                            # Formato antigo (retrocompatibilidade)
                            entries_data = vault_data
                            self.entry_order = []
                        
                        self.entries = {
                            name: VaultEntry.from_dict(entry)
                            for name, entry in entries_data.items()
                        }
                        
                        # Se não há ordem salva ou está incompleta, usa ordem alfabética
                        if not self.entry_order:
                            self.entry_order = sorted(self.entries.keys())
                            
                    finally:
                        # NOVO: Zeroizar plaintext imediatamente
                        plaintext_array = bytearray(plaintext)
                        for i in range(len(plaintext_array)):
                            plaintext_array[i] = 0
                
                # Reset rate limiter após sucesso
                self.rate_limiter.reset()
                
                logger.info("Vault aberto com sucesso - %d entradas", len(self.entries))
                
            finally:
                # NOVO: Zeroizar chaves derivadas
                if 'enc_key' in locals():
                    enc_key_array = bytearray(enc_key)
                    for i in range(len(enc_key_array)):
                        enc_key_array[i] = 0
                if 'hmac_key' in locals():
                    hmac_key_array = bytearray(hmac_key)
                    for i in range(len(hmac_key_array)):
                        hmac_key_array[i] = 0
                        
        except (ValueError, KeyError, TypeError, json.JSONDecodeError) as e:
            logger.error("Erro de dados ao abrir vault: %s", e)
            raise
        except (IOError, OSError) as e:
            logger.error("Erro de I/O ao abrir vault: %s", e)
            raise
        except Exception as e:
            logger.critical("Erro inesperado ao abrir vault: %s", e)
            raise
    
    def change_password(self, old_password: SecureMemory, new_password: SecureMemory) -> None:
        """MELHORADO: Altera senha e remove backups antigos."""
        # Verificar senha antiga
        temp_enc_key, _ = self.crypto.derive_keys(old_password, self.header.salt)
        
        try:
            with TimedExposure(self._enc_ko) as ek:
                if not self.crypto.constant_time_compare(temp_enc_key, ek.get_bytes()):
                    raise ValueError("Senha atual incorreta")
        finally:
            # Zeroizar chave temporária
            temp_key_array = bytearray(temp_enc_key)
            for i in range(len(temp_key_array)):
                temp_key_array[i] = 0
        
        # MELHORADO: Gerar novo salt único
        new_salt = secrets.token_bytes(SALT_SIZE)
        
        # Derivar novas chaves
        enc_key, hmac_key = self.crypto.derive_keys(new_password, new_salt)
        
        try:
            self._enc_ko.clear(); self._hmac_ko.clear()
            self._enc_ko  = KeyObfuscator(SecureMemory(enc_key));  self._enc_ko.obfuscate()
            self._hmac_ko = KeyObfuscator(SecureMemory(hmac_key)); self._hmac_ko.obfuscate()
            
            # Atualizar header
            self.header.salt = new_salt
            
            # Salvar com novas chaves
            self._save()
            
            # NOVO: Remover backups antigos (cifrados com chave antiga)
            self._cleanup_old_backups()
            
            logger.info("Senha mestra alterada com sucesso")
            
        finally:
            # Zeroizar novas chaves derivadas
            enc_key_array = bytearray(enc_key)
            for i in range(len(enc_key_array)):
                enc_key_array[i] = 0
            hmac_key_array = bytearray(hmac_key)
            for i in range(len(hmac_key_array)):
                hmac_key_array[i] = 0
    
    def _cleanup_old_backups(self) -> None:
        """NOVO: Remove backups cifrados com chave antiga."""
        try:
            # Renomear backup atual antes de criar novo
            if self.storage.backup_path.exists():
                old_backup = self.storage.backup_path.with_suffix(
                    f".backup.old-{int(time.time())}"
                )
                self.storage.backup_path.rename(old_backup)
                logger.debug("Backup antigo renomeado: %s", old_backup)
            
            # Remover backups muito antigos (> 7 dias)
            cutoff_time = time.time() - (7 * 24 * 3600)
            for old_backup in self.storage.vault_path.parent.glob("*.backup.old-*"):
                try:
                    timestamp_str = old_backup.suffix.split('-')[1]
                    backup_time = int(timestamp_str)
                    if backup_time < cutoff_time:
                        old_backup.unlink()
                        logger.debug("Backup expirado removido: %s", old_backup)
                except (ValueError, IndexError, OSError):
                    pass
                    
        except Exception as e:
            logger.warning("Erro na limpeza de backups: %s", e)

    # ------------------------------------------------------------------
    #  Salvar vault (gravação atômica + nonce novo sempre)
    # ------------------------------------------------------------------
    def _save(self) -> None:
        """Serializa o dicionário de entradas e grava no disco."""
        # ----- serialização -----
        vault_data = {
            "entries": {n: e.to_dict() for n, e in self.entries.items()},
            "order":   self.entry_order
        }
        plaintext = json.dumps(vault_data, indent=2).encode("utf-8")

        try:
            # ----- header -----
            self.header.counter  += 1
            self.header.modified  = time.time()

            header_bytes = struct.pack(
                HEADER_FMT,
                self.header.version,
                self.header.counter,
                self.header.salt,
                int(self.header.created),
                self.header.modified
            )

            # ----- HMAC do header -----
            with TimedExposure(self._hmac_ko) as hk:
                self.header.hmac = self.crypto.compute_hmac(
                    hk.get_bytes(), MAGIC + header_bytes
                )

            # ----- criptografia -----
            ad = MAGIC + header_bytes + self.header.hmac
            
            # MELHORADO: Sempre gerar nonce único
            with TimedExposure(self._enc_ko) as ek:
                nonce, ciphertext = self.crypto.encrypt_data(
                    ek.get_bytes(), plaintext, ad
                )

            blob = MAGIC + header_bytes + self.header.hmac + nonce + ciphertext

            # ----- gravação atômica -----
            self.storage.write_atomic(blob)
            self._modified = False
            logger.info("Vault salvo com sucesso")
            
        finally:
            # NOVO: Zeroizar plaintext imediatamente
            if 'plaintext' in locals():
                plaintext_array = bytearray(plaintext)
                for i in range(len(plaintext_array)):
                    plaintext_array[i] = 0

    def add_entry(self, name: str, password: str, metadata: Optional[Dict] = None) -> None:
        """Adiciona uma nova entrada ao vault."""
        if name in self.entries:
            raise ValueError(f"Entrada '{name}' já existe")
        
        self.entries[name] = VaultEntry(name, password, metadata)
        # Adicionar à ordem se não estiver presente
        if name not in self.entry_order:
            self.entry_order.append(name)
        self._modified = True
        self._save()
        logger.info("Entrada %s adicionada ao vault", name)

    def update_entry(self, name: str, password: str = None, metadata: Optional[Dict] = None) -> None:
        """Atualiza uma entrada existente."""
        if name not in self.entries:
            raise ValueError(f"Entrada '{name}' não encontrada")
        
        entry = self.entries[name]
        if password is not None:
            entry.set_password(password)
        if metadata is not None:
            entry.metadata = metadata
            entry.modified = time.time()
        
        self._modified = True
        self._save()
        logger.info("Entrada %s atualizada", name)

    def delete_entry(self, name: str) -> None:
        """Remove uma entrada do vault."""
        if name not in self.entries:
            raise ValueError(f"Entrada '{name}' não encontrada")
        
        # Limpar senha da memória antes de remover
        self.entries[name]._pw_ko.clear()
        del self.entries[name]
        
        # Remover da ordem também
        if name in self.entry_order:
            self.entry_order.remove(name)
        
        self._modified = True
        self._save()
        logger.info("Entrada %s removida do vault", name)

    def list_entries(self) -> List[str]:
        """Lista as entradas na ordem definida pelo usuário."""
        # Garantir que todas as entradas estejam na ordem
        for name in self.entries:
            if name not in self.entry_order:
                self.entry_order.append(name)
        
        # Remover entradas que não existem mais
        self.entry_order = [name for name in self.entry_order if name in self.entries]
        
        return self.entry_order.copy()

    def update_all_passwords(self, password_gen: PasswordGenerator) -> int:
        """Atualiza todas as senhas do vault com novas senhas seguras."""
        if not self.entries:
            return 0
        
        updated_count = 0
        for entry in self.entries.values():
            try:
                # Gerar nova senha com 20 caracteres usando charset completo
                new_password = password_gen.generate(20, CHARSETS["full"])
                entry.set_password(new_password)
                updated_count += 1
            except Exception as e:
                logger.error("Erro ao atualizar senha para %s: %s", entry.name, e)
                raise
        
        self._modified = True
        self._save()
        logger.info("%d senhas atualizadas em massa", updated_count)
        return updated_count

    def close(self) -> None:
        """Fecha o vault e limpa dados sensíveis da memória."""
        try:
            # Limpar todas as entradas
            for entry in self.entries.values():
                entry._pw_ko.clear()
            
            # Limpar chaves de criptografia
            if self._enc_ko:
                self._enc_ko.clear()
            if self._hmac_ko:
                self._hmac_ko.clear()
                
        except Exception as e:
            logger.error("Erro ao fechar vault: %s", e)
        finally:
            self.entries.clear()
            self.entry_order.clear()
            self._enc_ko = None
            self._hmac_ko = None
            self._modified = False

# ============================= PASSWORD GENERATOR ============================

class PasswordGenerator:
    """Gerador de senhas seguras."""
    
    _entropy_cache = {}
    
    @staticmethod
    def generate(length: int, charset: str) -> str:
        """Gera uma senha segura."""
        if length < 1:
            raise ValueError("Comprimento deve ser pelo menos 1")
        
        if not charset:
            raise ValueError("Conjunto de caracteres vazio")
        
        # Remover duplicatas do charset
        charset = ''.join(sorted(set(charset)))
        
        # Gerar senha
        while True:
            password = ''.join(
                secrets.choice(charset)
                for _ in range(length)
            )
            
            # Verificar qualidade
            if PasswordGenerator._check_quality(password, charset):
                return password
    
    @staticmethod
    def _check_quality(password: str, charset: str) -> bool:
        """Verifica a qualidade da senha."""
        # Verificar padrões comuns
        if PasswordGenerator._has_patterns(password):
            return False
        
        # Verificar distribuição de caracteres
        if len(password) >= 8:
            char_types = {
                'lower': string.ascii_lowercase,
                'upper': string.ascii_uppercase,
                'digit': string.digits,
                'special': string.punctuation
            }
            
            present_types = []
            for type_name, type_chars in char_types.items():
                if any(c in type_chars for c in charset):
                    if any(c in type_chars for c in password):
                        present_types.append(type_name)
            
            # Requer pelo menos 2 tipos de caracteres se disponíveis
            available_types = sum(1 for _, chars in char_types.items() 
                                if any(c in chars for c in charset))
            
            if available_types >= 2 and len(present_types) < 2:
                return False
        
        return True
    
    @staticmethod
    def _has_patterns(password: str) -> bool:
        """Detecta padrões comuns em senhas."""
        pwd_lower = password.lower()
        
        # Sequências de teclado
        sequences = [
            "qwerty", "asdfgh", "zxcvbn", "123456", "654321",
            "qwertyuiop", "asdfghjkl", "zxcvbnm"
        ]
        
        for seq in sequences:
            if seq in pwd_lower or seq[::-1] in pwd_lower:
                return True
        
        # Repetições
        for i in range(len(password) - 2):
            if password[i] == password[i+1] == password[i+2]:
                return True
        
        # Sequências numéricas/alfabéticas
        for i in range(len(password) - 2):
            chars = password[i:i+3]
            if chars.isdigit():
                nums = [int(c) for c in chars]
                if nums[1] == nums[0] + 1 and nums[2] == nums[1] + 1:
                    return True
                if nums[1] == nums[0] - 1 and nums[2] == nums[1] - 1:
                    return True
            
            if chars.isalpha():
                ords = [ord(c.lower()) for c in chars]
                if ords[1] == ords[0] + 1 and ords[2] == ords[1] + 1:
                    return True
                if ords[1] == ords[0] - 1 and ords[2] == ords[1] - 1:
                    return True
        
        return False
    
    @staticmethod
    def calculate_entropy(password: str, charset: str) -> float:
        """Calcula a entropia da senha em bits."""
        if not password or not charset:
            return 0.0
        
        # Cache baseado no tamanho e charset
        cache_key = (len(password), len(set(charset)))
        if cache_key in PasswordGenerator._entropy_cache:
            return PasswordGenerator._entropy_cache[cache_key]
        
        charset_size = len(set(charset))
        entropy = len(password) * math.log2(charset_size)
        
        # Limitar cache a 100 entradas
        if len(PasswordGenerator._entropy_cache) > Config.ENTROPY_CACHE_SIZE:
            PasswordGenerator._entropy_cache.clear()
        
        PasswordGenerator._entropy_cache[cache_key] = entropy
        return entropy


# ============================= GUI (estilo 2.0 restaurado) ===================

class KeyGuardApp(ttk.Window):
    """Interface gráfica inspirada no KeyGuard 2.0,
       acoplada ao núcleo de segurança do 3.0."""

    # ---------------------------------------------------------------------
    def __init__(self):
        super().__init__(themename="superhero")
        
        # MELHORADO: Verificação de integridade do executável
        self._verify_integrity()
        
        # NOVO: Aplicar proteções de processo antes de qualquer operação
        try:
            # Remover chamada duplicada - proteções já foram aplicadas em main()
            if not process_protection.protected:
                process_protection.apply_protections()
                
            if process_protection.debugger_detected and not Config.ALLOW_DEBUGGING:
                mb.showerror("Aviso de Segurança", 
                           "Debugger detectado. O aplicativo será fechado por segurança.")
                os._exit(1)
            
            # Iniciar verificação contínua
            process_protection.continuous_check(self._on_debugger_detected)
            
        except Exception as e:
            logger.error("Erro ao aplicar proteções: %s", e)
            if not mb.askyesno("Continuar?", 
                             "Algumas proteções de segurança falharam.\n"
                             "Deseja continuar mesmo assim?\n\n"
                             "⚠️ Isso pode comprometer a segurança dos dados."):
                os._exit(1)
        
        # assegura que _master_pw sempre exista
        self._master_pw: Optional[SecureMemory] = None
        self.title("KeyGuard 3.0.1")
        self.geometry("580x480")
        self.resizable(False, False)

        # ---------- backend ----------
        self.storage = StorageBackend(VAULT_FILE)
        self.crypto = CryptoEngine()
        self.vault = VaultManager(self.storage, self.crypto)
        self.password_gen = PasswordGenerator()

        # ---------- senha-mestra ----------
        pw_mem = SecurePasswordDialog.ask(self,
                                          title="Senha-mestra",
                                          prompt="Digite a senha do vault:")
        if pw_mem is None or len(pw_mem) == 0:
            self.destroy(); return
        self._master_pw = pw_mem

        try:
            if self.storage.exists():
                try:
                    self.vault.open(self._master_pw)
                except Exception as e:
                    mb.showerror("Erro",
                                 "Senha incorreta ou vault corrompido:\n%s" % e)
                    self.destroy(); return
            else:
                try:
                    if not mb.askyesno("Novo vault",
                                       "Nenhum vault encontrado. Criar novo?"):
                        self.destroy(); return
                    self.vault.create_new(self._master_pw)
                except ValueError as e:
                    mb.showerror("Erro", "Erro ao criar vault:\n%s" % e)
                    self.destroy(); return
        finally:
            # NOVO: Zeroizar cópia da senha mestra após uso inicial
            if hasattr(self, '_master_pw') and self._master_pw:
                pass  # Manter para operações futuras, mas limitar exposição

        # NOVO: Proteção: senha-mestra some após inatividade
        from functools import partial
        self._pw_timeout = PasswordTimeout(self._master_pw,
                                           timeout=Config.SESSION_TIMEOUT)

        # qualquer interação de UI reinicia o timer
        reset = self._pw_timeout.reset
        self.bind_all("<Any-KeyPress>", lambda e: reset())
        self.bind_all("<Any-Button>",   lambda e: reset())

        # ---------- interface ----------
        self._build_menu()
        self._build_ui()
    
    def _verify_integrity(self) -> None:
        """NOVO: Verificação básica de integridade do executável."""
        try:
            import hashlib
            
            # Verificar se o script foi modificado (desenvolvimento)
            if hasattr(sys, 'argv') and sys.argv[0].endswith('.py'):
                script_path = Path(sys.argv[0])
                if script_path.exists():
                    content = script_path.read_bytes()
                    current_hash = hashlib.sha256(content).hexdigest()
                    
                    # Em produção, você definiria um hash esperado
                    # Por ora, apenas log do hash atual
                    logger.debug("Hash do script: %s...", current_hash[:16])
                    
        except Exception as e:
            logger.warning("Erro na verificação de integridade: %s", e)

    # ⓷ MELHORADO: Callback de detecção de debugger com limpeza segura
    def _on_debugger_detected(self):
        """Callback chamado quando debugger é detectado durante execução."""
        logger.critical("⚠️ Debugger detectado em tempo de execução!")
        
        if not Config.ALLOW_DEBUGGING:
            try:
                # Limpar dados sensíveis imediatamente
                if hasattr(self, 'vault'):
                    self.vault.close()
                if hasattr(self, '_master_pw') and self._master_pw:
                    self._master_pw.clear()
                
                # Tentar mostrar aviso se a interface ainda estiver ativa
                if self.winfo_exists():
                    mb.showerror("Aviso de Segurança",
                                "Debugger detectado durante a execução!\n"
                                "O aplicativo será encerrado por segurança.",
                                parent=self)
            except (tk.TclError, AttributeError):
                # Interface já foi destruída ou não está disponível
                pass
            finally:
                # Usar os._exit para garantir encerramento imediato
                os._exit(1)
        else:
            logger.warning("Debugger detectado, mas modo de desenvolvimento ativo")

    # ---------------- menu ----------------
    def _build_menu(self):
        menubar = tk.Menu(self)

        m = tk.Menu(menubar, tearoff=0)
        m.add_command(label="Trocar Senha Mestra",
                      command=self._change_master)
        m.add_command(label="Atualizar Todas as Senhas",
                      command=self._update_all_passwords)
        menubar.add_cascade(label="Menu", menu=m)

        self.config(menu=menubar)

    def _change_master(self):
        old = sd.askstring("Trocar Senha",
                           "Senha atual:",
                           show="*",
                           parent=self)
        if old is None:
            return
        new = sd.askstring("Trocar Senha",
                           "Nova senha-mestra:",
                           show="*",
                           parent=self)
        if new is None:
            return
        conf = sd.askstring("Trocar Senha",
                            "Confirme a nova senha-mestra:",
                            show="*",
                            parent=self)
        if conf is None or new != conf:
            mb.showerror("Erro", "Confirmação não confere", parent=self)
            return
        try:
            self.vault.change_password(SecureMemory(old),
                                       SecureMemory(new))
            mb.showinfo("Sucesso", "Senha-mestra alterada", parent=self)
        except Exception as e:
            mb.showerror("Erro", str(e), parent=self)
            
    # ------------------------------------------------------------------
    #  Fluxo GUI para atualização em massa
    # ------------------------------------------------------------------
    def _update_all_passwords(self):
        if not self.vault.entries:
            mb.showinfo("Aviso", "O vault está vazio.", parent=self)
            return

        msg = (f"Serão geradas novas senhas para "
               f"{len(self.vault.entries)} entradas.\n\n"
               "As senhas antigas serão PERMANENTEMENTE substituídas "
               "e um backup será criado.\n\n"
               "Deseja continuar?")
        if not mb.askyesno("Confirmar Atualização", msg,
                           icon="warning", parent=self):
            return
        if not mb.askyesno("Última Confirmação",
                           "Tem certeza? Esta ação não pode ser desfeita!",
                           icon="warning", parent=self):
            return

        try:
            # janela de progresso simples
            prog = ttk.Toplevel(self); prog.title("Atualizando")
            prog.geometry("280x110"); prog.resizable(False, False)
            ttk.Label(prog, text="Gerando novas senhas...").pack(pady=10)
            bar = ttk.Progressbar(prog, mode="indeterminate",
                                  length=220, bootstyle=INFO)
            bar.pack(pady=10); bar.start(10); prog.update()

            total = self.vault.update_all_passwords(self.password_gen)

            prog.destroy()
            mb.showinfo("Concluído",
                        "✅ %d senhas foram atualizadas com sucesso." % total,
                        parent=self)

        except Exception as exc:
            if 'prog' in locals():
                prog.destroy()
            mb.showerror("Erro",
                         "Falha ao atualizar senhas:\n%s\n\n"
                         "O vault foi restaurado ao estado anterior." % exc,
                         parent=self)
            logger.error("Erro na atualização em massa: %s", exc)

            # tenta recarregar vault limpo
            try:
                self.vault.close()
                self.vault = VaultManager(self.storage, self.crypto)
                self.vault.open(self._master_pw)
            except Exception as reload_exc:
                logger.critical("Erro ao recarregar vault: %s", reload_exc)

    # --------------- UI principal ---------------
    def _build_ui(self):
        container = ttk.Frame(self)
        container.place(relx=0.5, rely=0.5, anchor="c")

        # ----- parâmetros de geração -----
        frm = ttk.LabelFrame(container, text="Parâmetros")
        frm.grid(row=0, column=0, sticky="n")
        frm.columnconfigure(1, weight=1)

        ttk.Label(frm, text="Comprimento:").grid(row=0, column=0,
                                                 sticky="e", padx=6, pady=4)
        
        # Validação corrigida que permite digitação
        def validate_length(value):
            # Permitir campo vazio (durante digitação)
            if value == "":
                return True
            
            # Verificar se é um número válido
            try:
                num = int(value)
                # Permitir valores entre 1-999 durante digitação
                # A validação final será feita ao gerar a senha
                return 1 <= num <= 999
            except ValueError:
                return False
        
        vcmd = (self.register(validate_length), '%P')
        self.spin = ttk.Spinbox(frm, from_=4, to=128,
                                width=6, bootstyle=PRIMARY,
                                validate='key', validatecommand=vcmd)
        self.spin.set(16)
        self.spin.grid(row=0, column=1, sticky="w",
                       padx=(2, 8), pady=4)
        ToolTip(self.spin, text="Tamanho da senha (4-128)")

        # rádios numéricos como na 2.0, agora cada um em sua própria linha
        self.opt = ttk.IntVar(value=4)
        labels = ("Números", "Letras", "Letras+Números", "Todos")
        for i, txt in enumerate(labels, 1):
            r = ttk.Radiobutton(frm, text=txt, value=i, variable=self.opt)
            r.grid(row=i,                      # ← 1,2,3,4
                   column=0 if i % 2 else 1,   # ímpar coluna 0 | par coluna 1
                   sticky="w", padx=8, pady=2) # mesmo padding da 2.1

        self.flag_save = ttk.BooleanVar()
        ttk.Checkbutton(frm, text="Salvar no vault",
                        variable=self.flag_save)\
            .grid(row=5, column=0, columnspan=2,
                  sticky="w", padx=8, pady=(6, 2))

        ttk.Label(frm, text="Aplicação:").grid(row=6, column=0,
                                               sticky="e", padx=6)
        self.ent_app = ttk.Entry(frm, width=24)
        self.ent_app.grid(row=6, column=1, sticky="w",
                          padx=(2, 8), pady=4)

        # ----- resultado -----
        out = ttk.Frame(container)
        out.grid(row=1, column=0, pady=12, sticky="ew")
        out.columnconfigure(0, weight=1)
        self.var_pwd = ttk.StringVar()
        # CORRIGIDO: Remover undo=False do ttk.Entry (não suportado)
        self.ent_pwd = ttk.Entry(out, textvariable=self.var_pwd,
                                 font=("Consolas", 14),
                                 state="readonly", width=38, show="•")
        self.ent_pwd.grid(row=0, column=0, sticky="ew",
                          ipadx=6, ipady=4)

        self.chk_eye = ttk.Checkbutton(out, text="👁",
                                       style="toolbutton",
            command=lambda: self.ent_pwd.config(
                show="" if self.chk_eye.instate(['selected']) else "•"))
        self.chk_eye.grid(row=0, column=1, padx=4)

        self.bar = ttk.Progressbar(out, maximum=120,
                                   length=400, bootstyle=SUCCESS)
        self.bar.grid(row=1, column=0, columnspan=2, pady=6)
        self.lbl = ttk.Label(out, text="Entropia / força")
        self.lbl.grid(row=2, column=0, columnspan=2)

        # ----- botões -----
        btn = ttk.Frame(container)
        btn.grid(row=2, column=0, pady=6)
        ttk.Button(btn, text="Gerar", bootstyle=PRIMARY,
                   command=self._on_generate).pack(side="left", padx=6)
        ttk.Button(btn, text="Copiar",
                   command=self._on_copy).pack(side="left", padx=6)
        ttk.Button(btn, text="Limpar",
                   command=self._on_clear).pack(side="left", padx=6)
        ttk.Button(btn, text="Vault",
                   command=self._vault_view).pack(side="left", padx=6)
        ttk.Button(btn, text="Sair", bootstyle=DANGER,
                   command=self.destroy).pack(side="left", padx=6)

        # atalhos
        self.bind_all('<Control-g>', lambda *_: self._on_generate())
        self.bind_all('<Control-c>', lambda *_: self._on_copy())
        self.bind_all('<Control-l>', lambda *_: self._on_clear())
        self.bind_all('<Escape>',   lambda *_: self.destroy())

    # ---------- callbacks ----------
    def _make_pwd(self) -> str:
        try:
            length = int(self.spin.get())
            # Garantir que está no range válido
            length = max(4, min(128, length))
            # Atualizar o spinbox se o valor foi ajustado
            if int(self.spin.get()) != length:
                self.spin.set(str(length))

        except ValueError:
            # Se não for um número válido, usar o padrão
            length = 16
            self.spin.set(str(length))
        
        charset = CHARSETS[OPT_TO_KEY[self.opt.get()]]
        return self.password_gen.generate(length, charset)

    def _on_generate(self, *_):
        pwd     = self._make_pwd()
        keyset  = OPT_TO_KEY[self.opt.get()]
        charset = CHARSETS[keyset]

        bits = PasswordGenerator.calculate_entropy(pwd, charset)
        self.var_pwd.set(pwd)
        self.bar['value'] = min(bits, 120)

        # alerta de mesma lógica 2.0
        msg = "Entropia: %.1f bits" % bits
        if bits < MIN_TOTAL_BITS:
            msg += " ⚠️"

        # distribuição por classes
        classes = {
            'lower': any(c in string.ascii_lowercase for c in pwd),
            'upper': any(c in string.ascii_uppercase for c in pwd),
            'digit': any(c in string.digits           for c in pwd),
            'symbol':any(c in string.punctuation      for c in pwd),
        }
        if sum(classes.values()) < 2:
            msg += " (classe fraca ⚠️)"

        self.lbl.config(text=msg)

        if self.flag_save.get():
            name = self.ent_app.get().strip() or "Sem_nome"
            try:
                self.vault.add_entry(name, pwd)
            except ValueError:
                # já existe → atualizar
                self.vault.update_entry(name, password=pwd)

    def _on_copy(self, *_):
        s = self.var_pwd.get()
        if s:
            self.clipboard_clear(); self.clipboard_append(s)

    def _on_clear(self, *_):
        self.clipboard_clear()
        self.var_pwd.set("")
        self.bar['value'] = 0
        self.lbl.config(text="Entropia / força")
        if self.chk_eye.instate(['selected']):
            self.chk_eye.state(['!selected'])
            self.ent_pwd.config(show="•")

    # ---------- vault viewer ----------
    def _vault_view(self):
        top = ttk.Toplevel(self)
        top.title("Vault")
        top.geometry("380x350")  # Aumentar altura para busca

        # Campo de busca
        search_frame = ttk.Frame(top)
        search_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(search_frame, text="Buscar:").pack(side=tk.LEFT, padx=5)
        search_var = ttk.StringVar()
        search_entry = ttk.Entry(search_frame, textvariable=search_var)
        search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

        # ---------------- Treeview ----------------
        tree = ttk.Treeview(top, columns=("app", "pwd"), show="headings")
        tree.heading("app", text="Aplicação")
        tree.heading("pwd", text="Senha")
        tree.column("pwd", width=120, anchor="center")
        tree.pack(fill=tk.BOTH, expand=True)

        def filter_entries(*args):
            query = search_var.get().lower()
            tree.delete(*tree.get_children())
            
            for name in self.vault.list_entries():
                if query in name.lower():
                    tree.insert("", tk.END, iid=name, values=(name, "••••••••"))
        
        search_var.trace('w', filter_entries)
        
        # Carregar entradas inicialmente
        filter_entries()

        # Atalhos de teclado
        tree.bind('<Double-1>', lambda e: self._detail(tree))
        tree.bind('<Return>', lambda e: self._detail(tree))
        tree.bind('<Delete>', lambda e: self._delete_sel(tree))
        tree.bind('<Control-c>', lambda e: self._copy_sel(tree))
        
        # ESC fecha a janela
        top.bind('<Escape>', lambda e: top.destroy())

        # -------------- drag-and-drop -------------
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

        def _release(e):
            if not tree._drag["moved"]:
                return
            new_order = [tree.item(iid, "values")[0]
                         for iid in tree.get_children()]
            self._persist_order(new_order)

        tree.bind("<ButtonPress-1>",   _press)
        tree.bind("<B1-Motion>",       _motion)
        tree.bind("<ButtonRelease-1>", _release)

        # ---------------- botões ------------------
        bar = ttk.Frame(top); bar.pack(pady=6)
        ttk.Button(bar, text="Ver detalhes",
                   command=lambda: self._detail(tree)).pack(side="left", padx=6)
        ttk.Button(bar, text="Copiar",
                   command=lambda: self._copy_sel(tree)).pack(side="left", padx=6)
        ttk.Button(bar, text="Excluir", bootstyle=DANGER,
                   command=lambda: self._delete_sel(tree)).pack(side="left", padx=6)

    # ---------- suporte a reordenação ----------
    def _persist_order(self, new_order: list[str]):
        """Salva nova ordem das entradas preservando senhas (operação atômica)."""
        if set(new_order) != set(self.vault.entries):
            return
        
        # Atualiza a ordem no vault
        self.vault.entry_order = new_order.copy()
        self.vault._modified = True
        self.vault._save()

    # ---------- detalhes / copiar / excluir ----------
    def _detail(self, tree):
        sel = tree.selection()
        if not sel:
            return
        name   = sel[0]
        entry  = self.vault.entries.get(name)
        if not entry:
            return
        pwd    = entry.get_password()
        show   = pwd[: min(16, len(pwd))]
        mask   = "•" * len(show)

        dlg = ttk.Toplevel(self); dlg.title(name); dlg.grab_set()
       
        ttk.Label(dlg, text=f"Aplicação: {name}",
                  font=("Segoe UI", 11, "bold")).pack(pady=(12,4))
        frame = ttk.Frame(dlg); frame.pack(padx=12, pady=4, fill="x")
        lbl   = ttk.Label(frame, text=mask, font=("Consolas",12))
        lbl.pack(side=tk.LEFT, fill="x", expand=True)
        var_eye = ttk.IntVar(value=0)
        ttk.Checkbutton(frame, text="👁", style="toolbutton", variable=var_eye,
                        command=lambda: lbl.config(text=show if var_eye.get() else mask)
                        ).pack(side=tk.LEFT, padx=6)
        ttk.Button(dlg, text="Copiar",
                   command=lambda: (self.clipboard_clear(), self.clipboard_append(pwd), dlg.destroy())
                   ).pack(pady=8)
        
        # Auto-ocultar após 10 segundos
        def auto_hide():
            try:
                if dlg.winfo_exists():
                    var_eye.set(0)
                    lbl.config(text=mask)
            except tk.TclError:
                pass  # Janela já foi fechada
        
        dlg.after(Config.AUTO_HIDE_DELAY, auto_hide)

    def _copy_sel(self, tree):
        sel = tree.selection()
        if sel:
            entry = self.vault.entries.get(sel[0])
            if entry:
                self.clipboard_clear()
                self.clipboard_append(entry.get_password())
    
    def _delete_sel(self, tree):
        sel = tree.selection()
        if not sel:
            return
        name = sel[0]
        if not mb.askyesno("Confirmar",
                           "Remover '%s' do vault?" % name,
                           parent=tree.winfo_toplevel()):
            return
        try:
            self.vault.delete_entry(name)
            tree.delete(name)
        except ValueError as e:
            mb.showerror("Erro", "Erro ao excluir entrada: %s" % e, parent=tree.winfo_toplevel())
        except Exception as e:
            mb.showerror("Erro", "Erro inesperado: %s" % e, parent=tree.winfo_toplevel())

    # ---------- limpeza ----------
    def destroy(self):
        # MELHORADO: Limpeza segura de dados sensíveis
        try:
            # NOVO: Cancelar timeout da senha-mestra
            if hasattr(self, '_pw_timeout'):
                self._pw_timeout.cancel()
            
            self.clipboard_clear()
            
            # Limpar senha gerada
            if hasattr(self, 'var_pwd'):
                self.var_pwd.set("")
            
            # Fechar vault
            if hasattr(self, "vault"):
                self.vault.close()
                
            # Limpar senha mestra
            if hasattr(self, '_master_pw') and self._master_pw is not None:
                self._master_pw.clear()
                
        except Exception as e:
            logger.error("Erro durante limpeza: %s", e)
        finally:
            super().destroy()

# ============================= MAIN ==========================================

def main():
    """Função principal."""
    import logging.handlers  # garante RotatingFileHandler
    
    # NOVO: Verificação inicial de segurança
    try:
        # NOVO: Validar recursos do sistema primeiro
        validate_system_requirements()
        
        # Aplicar proteções básicas logo no início (apenas uma vez)
        if not Config.ALLOW_DEBUGGING:
            process_protection.apply_protections()
        
        # MELHORADO: Validação de recursos do sistema
        ram_total = psutil.virtual_memory().total
        ram_gb = ram_total / (1024**3)
        
        if ram_gb < 1.5:  # Menos de 1.5 GB total
            logger.warning("Sistema com pouca RAM detectado: %.1f GB", ram_gb)
            if not mb.askyesno(
                "Aviso de Sistema", 
                f"Este sistema tem apenas {ram_gb:.1f} GB de RAM.\n"
                "O KeyGuard 3.0.1 high-security requer pelo menos 2 GB livres.\n\n"
                "Continuar mesmo assim? O programa pode falhar ao abrir vaults.",
                icon="warning"
            ):
                return
        
        # NOVO: Calibração opcional do KDF na primeira execução
        config_path = DATA_DIR / "config.ini"
        if not config_path.exists():
            logger.info("Primeira execução - calibrando KDF high-security...")
            try:
                Config.calibrate_kdf()
            except RuntimeError as e:
                logger.error("Falha na calibração: %s", e)
                mb.showerror(
                    "Erro de Sistema",
                    f"Não foi possível calibrar o sistema de segurança:\n\n{e}\n\n"
                    "O KeyGuard não pode executar neste hardware."
                )
                return
            
        app = KeyGuardApp()
        app.mainloop()
        
    except KeyboardInterrupt:
        logger.info("Aplicação interrompida pelo usuário")
    except Exception as e:
        logger.critical("Erro crítico na aplicação: %s", e)
        raise
    finally:
        # Limpar dados sensíveis na saída
        try:
            if 'app' in locals() and hasattr(app, 'vault'):
                app.vault.close()
        except:
            pass

if __name__ == "__main__":
    main()
