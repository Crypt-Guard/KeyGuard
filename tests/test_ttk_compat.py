from __future__ import annotations

from keyguard.ui.ttk_compat import DANGER, INFO, PRIMARY, SUCCESS, ToolTip, ttk


def test_labelframe_aliases_exist():
    assert hasattr(ttk, "Labelframe")
    assert hasattr(ttk, "LabelFrame")


def test_required_ttk_symbols_exist():
    names = [
        "Window",
        "Toplevel",
        "Frame",
        "Label",
        "Entry",
        "Button",
        "Checkbutton",
        "Radiobutton",
        "Spinbox",
        "Progressbar",
        "Treeview",
        "StringVar",
        "IntVar",
        "BooleanVar",
    ]
    for name in names:
        assert hasattr(ttk, name), f"Missing ttk symbol: {name}"


def test_bootstyle_constants_available():
    for value in (DANGER, INFO, PRIMARY, SUCCESS):
        assert isinstance(value, str)
        assert value


def test_tooltip_symbol_available():
    assert callable(ToolTip)
