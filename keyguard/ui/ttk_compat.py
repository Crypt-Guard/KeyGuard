"""Compatibility layer for ttkbootstrap API differences across versions."""

from __future__ import annotations

import tkinter as tk
import warnings
from tkinter import ttk as tk_ttk

with warnings.catch_warnings():
    # Some ttkbootstrap releases emit internal deprecation warnings on import.
    warnings.filterwarnings("ignore", category=DeprecationWarning, module=r"ttkbootstrap(\.|$)")
    import ttkbootstrap as ttk

try:
    with warnings.catch_warnings():
        warnings.filterwarnings(
            "ignore", category=DeprecationWarning, module=r"ttkbootstrap(\.|$)"
        )
        from ttkbootstrap.constants import DANGER, INFO, PRIMARY, SUCCESS
except Exception:
    # Fallback strings match ttkbootstrap style names.
    DANGER = "danger"
    INFO = "info"
    PRIMARY = "primary"
    SUCCESS = "success"

try:
    # Preferred import path in newer ttkbootstrap versions.
    with warnings.catch_warnings():
        warnings.filterwarnings(
            "ignore", category=DeprecationWarning, module=r"ttkbootstrap(\.|$)"
        )
        from ttkbootstrap.widgets import ToolTip
except Exception:
    try:
        # Legacy import path kept for older versions.
        with warnings.catch_warnings():
            warnings.filterwarnings(
                "ignore", category=DeprecationWarning, module=r"ttkbootstrap(\.|$)"
            )
            from ttkbootstrap.tooltip import ToolTip
    except Exception:

        class ToolTip:  # type: ignore[no-redef]
            """No-op fallback when tooltip widget is unavailable."""

            def __init__(self, *_args, **_kwargs):
                pass


def _set_if_missing(name: str, value) -> None:
    if not hasattr(ttk, name):
        setattr(ttk, name, value)


# Variable classes are re-exported in most versions, but not all.
_set_if_missing("StringVar", tk.StringVar)
_set_if_missing("IntVar", tk.IntVar)
_set_if_missing("BooleanVar", tk.BooleanVar)

# Basic widgets.
_set_if_missing("Frame", tk_ttk.Frame)
_set_if_missing("Label", tk_ttk.Label)
_set_if_missing("Entry", tk_ttk.Entry)
_set_if_missing("Button", tk_ttk.Button)
_set_if_missing("Checkbutton", tk_ttk.Checkbutton)
_set_if_missing("Radiobutton", tk_ttk.Radiobutton)
_set_if_missing("Spinbox", tk_ttk.Spinbox)
_set_if_missing("Progressbar", tk_ttk.Progressbar)
_set_if_missing("Treeview", tk_ttk.Treeview)

# LabelFrame naming changed between versions.
if hasattr(ttk, "Labelframe"):
    _set_if_missing("LabelFrame", getattr(ttk, "Labelframe"))
elif hasattr(ttk, "LabelFrame"):
    _set_if_missing("Labelframe", getattr(ttk, "LabelFrame"))
else:
    _set_if_missing("Labelframe", tk_ttk.Labelframe)
    _set_if_missing("LabelFrame", tk_ttk.Labelframe)


# Window wrappers.
if not hasattr(ttk, "Window"):

    class _Window(tk.Tk):
        def __init__(self, *args, **kwargs):
            kwargs.pop("themename", None)
            super().__init__(*args, **kwargs)

    setattr(ttk, "Window", _Window)

_set_if_missing("Toplevel", tk.Toplevel)

__all__ = ["DANGER", "INFO", "PRIMARY", "SUCCESS", "ToolTip", "ttk"]
