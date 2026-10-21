"""Light/dark palettes and the QSS built from them.

Caption button glyphs are vector-rendered in a concrete color, so a theme switch has
to hand the widgets a fresh palette - see MainWindow.apply_theme().
"""

from __future__ import annotations

from dataclasses import dataclass

from PySide6.QtGui import QPalette
from PySide6.QtWidgets import QApplication


@dataclass(frozen=True)
class Palette:
    name: str
    window: str
    surface: str
    text: str
    text_muted: str
    border: str
    hover: str
    pressed: str
    accent: str
    accent_text: str
    close_hover: str
    close_pressed: str
    menu_hover: str


LIGHT = Palette(
    name="light",
    window="#f7f8fa",
    surface="#ffffff",
    text="#1f2329",
    text_muted="#8a919b",
    border="#e5e7eb",
    hover="#e8eaed",
    pressed="#d9dce0",
    accent="#3b82f6",
    accent_text="#ffffff",
    close_hover="#f36b5f",
    close_pressed="#d94a3d",
    menu_hover="#eef2fb",
)

DARK = Palette(
    name="dark",
    window="#1c1f24",
    surface="#23272e",
    text="#e6e8eb",
    text_muted="#98a1ab",
    border="#31363d",
    hover="#2f343c",
    pressed="#3a4048",
    accent="#4f8cf7",
    accent_text="#ffffff",
    close_hover="#c8503f",
    close_pressed="#a53f31",
    menu_hover="#2b3038",
)

PALETTES = {p.name: p for p in (LIGHT, DARK)}


def system_prefers_dark() -> bool:
    """Windows: HKCU Themes\\Personalize\\AppsUseLightTheme == 0 means dark."""
    import sys

    if sys.platform != "win32":
        return False
    import winreg

    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"
        ) as key:
            value, _ = winreg.QueryValueEx(key, "AppsUseLightTheme")
        return int(value) == 0
    except OSError:
        return False


def resolve(preference: str) -> str:
    if preference == "dark" or preference == "light":
        return preference
    return "dark" if system_prefers_dark() else "light"


def palette_for(preference: str) -> Palette:
    return PALETTES[resolve(preference)]


def stylesheet(p: Palette) -> str:
    return f"""
QMainWindow, QWidget#Central {{
    background: {p.window};
    color: {p.text};
}}
QLabel {{ color: {p.text}; background: transparent; }}
QLabel#TitleLabel {{ font-size: 13px; font-weight: 600; }}
QLabel#Muted {{ color: {p.text_muted}; }}
QLabel#PairCode {{ font-size: 22px; font-weight: 700; letter-spacing: 3px; color: {p.accent}; }}
/* The QR keeps its own white quiet zone in either theme; the frame is drawn, not painted. */
QLabel#QrBox {{ background: #ffffff; border: 1px solid {p.border}; border-radius: 6px; }}
QLabel#SectionTitle {{ font-size: 15px; font-weight: 600; }}

QDialog {{ background: {p.window}; color: {p.text}; }}
QLineEdit, QComboBox {{
    background: {p.surface};
    border: 1px solid {p.border};
    border-radius: 6px;
    padding: 5px 8px;
    color: {p.text};
    selection-background-color: {p.accent};
}}
QLineEdit:focus, QComboBox:focus {{ border: 1px solid {p.accent}; }}
QRadioButton, QCheckBox {{ spacing: 6px; }}
/* The settings window's left-hand menu: no frame, the selection is the only chrome. */
QListWidget#SettingsMenu {{ background: transparent; border: none; outline: none; }}
QListWidget#SettingsMenu::item {{ padding: 8px 10px; border-radius: 6px; color: {p.text_muted}; }}
QListWidget#SettingsMenu::item:selected {{ background: {p.menu_hover}; color: {p.text}; font-weight: 600; }}

QWidget#TitleBar {{ background: {p.surface}; border-bottom: 1px solid {p.border}; }}

QGroupBox {{
    background: {p.surface};
    border: 1px solid {p.border};
    border-radius: 8px;
    margin-top: 10px;
    padding: 14px 12px 12px 12px;
}}
QGroupBox::title {{ subcontrol-origin: margin; left: 10px; padding: 0 4px; color: {p.text_muted}; }}

QListWidget {{ background: {p.window}; border: 1px solid {p.border}; border-radius: 6px; padding: 2px; }}
QListWidget::item {{ padding: 6px; border-radius: 4px; color: {p.text}; }}
QListWidget::item:selected {{ background: {p.menu_hover}; color: {p.text}; }}

QProgressBar {{
    background: {p.window};
    border: 1px solid {p.border};
    border-radius: 6px;
    text-align: center;
    color: {p.text};
}}
QProgressBar::chunk {{ background: {p.accent}; border-radius: 5px; }}

QToolButton#AppButton, QToolButton#LangButton, QToolButton#ThemeButton,
QToolButton#MinButton, QToolButton#MaxButton, QToolButton#CloseButton {{
    border: none;
    background: transparent;
    border-radius: 6px;
    padding: 0;
}}
QToolButton#AppButton:hover, QToolButton#LangButton:hover, QToolButton#ThemeButton:hover,
QToolButton#MinButton:hover, QToolButton#MaxButton:hover {{ background: {p.hover}; }}
QToolButton#AppButton:pressed, QToolButton#LangButton:pressed, QToolButton#ThemeButton:pressed,
QToolButton#MinButton:pressed, QToolButton#MaxButton:pressed {{ background: {p.pressed}; }}
QToolButton#CloseButton:hover {{ background: {p.close_hover}; }}
QToolButton#CloseButton:pressed {{ background: {p.close_pressed}; }}

QMenu {{ background: {p.surface}; border: 1px solid {p.border}; padding: 4px; }}
QMenu::item {{ padding: 5px 22px 5px 12px; border-radius: 5px; color: {p.text}; }}
QMenu::item:selected {{ background: {p.menu_hover}; }}
QMenu::separator {{ height: 1px; background: {p.border}; margin: 4px 6px; }}

QStatusBar {{ background: {p.surface}; color: {p.text_muted}; }}
QStatusBar::item {{ border: none; }}

QPushButton {{
    background: {p.accent};
    color: {p.accent_text};
    border: none;
    border-radius: 6px;
    padding: 7px 16px;
}}
QPushButton:hover {{ background: {p.accent}; }}
QPushButton:pressed {{ background: {p.pressed}; color: {p.text}; }}
QPushButton:disabled {{ background: {p.border}; color: {p.text_muted}; }}
/* A secondary action that sits next to the value it edits, not in a row under it.
   Every state needs its own rule: QPushButton:hover would otherwise win the paint. */
QPushButton#Inline {{
    background: transparent;
    color: {p.accent};
    border: none;
    border-radius: 4px;
    padding: 1px 6px;
}}
QPushButton#Inline:hover {{ background: {p.menu_hover}; color: {p.accent}; }}
QPushButton#Inline:pressed {{ background: {p.hover}; color: {p.text}; }}
QPushButton#Inline:disabled {{ background: transparent; color: {p.text_muted}; }}

QCheckBox {{ color: {p.text}; }}
QToolTip {{ background: {p.surface}; color: {p.text}; border: 1px solid {p.border}; }}
"""


def apply_theme(app: QApplication, p: Palette) -> None:
    """QSS drives our own widgets; QPalette keeps native dialogs coherent."""
    app.setStyleSheet(stylesheet(p))
    qt = QPalette()
    role = QPalette.ColorRole
    qt.setColor(role.Window, p.window)
    qt.setColor(role.Base, p.surface)
    qt.setColor(role.Text, p.text)
    qt.setColor(role.WindowText, p.text)
    qt.setColor(role.ButtonText, p.text)
    qt.setColor(role.Highlight, p.accent)
    qt.setColor(role.HighlightedText, p.accent_text)
    qt.setColor(role.PlaceholderText, p.text_muted)
    app.setPalette(qt)
