"""
aegis/gui/__init__.py
=====================
Aegis Studio Native Desktop GUI Launcher (pywebview + Edge WebView2).
"""

from pathlib import Path
from typing import Optional


def launch_studio(debug: bool = False) -> None:
    """
    Launch the native Windows 11 Liquid Glass GUI desktop application.
    """
    import sys
    import webview
    from aegis.bridge import AegisBridge

    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        html_file = Path(sys._MEIPASS) / "aegis" / "gui" / "index.html"
    else:
        html_file = Path(__file__).parent / "index.html"

    if not html_file.exists():
        html_file = Path(__file__).parent / "index.html"
    if not html_file.exists():
        raise FileNotFoundError(f"GUI markup file not found at {html_file}")

    bridge = AegisBridge()

    window = webview.create_window(
        title="Aegis 2.0 — Binary Security Analysis Studio",
        url=str(html_file.resolve()),
        js_api=bridge,
        width=1240,
        height=820,
        min_size=(980, 680),
        frameless=True,
        easy_drag=False,
        background_color="#06080d",
    )
    bridge.set_window(window)

    # Launch Edge WebView2 Chromium runtime
    webview.start(debug=debug)
