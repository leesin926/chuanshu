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
    #: The left-hand rail is dark in both themes: it is the one area that has to read as chrome
    #: rather than content, and a light rail against a light window loses the separation.
    #: Sampled off the mockups, where the rail is #1A293E with the accent worn by the one item
    #: that says "you are here".
    nav: str
    nav_text: str
    nav_sel: str
    nav_sel_text: str
    #: The rail's own quiet text - the brand line under the logo, which sits on navy.
    nav_muted: str
    #: The rail's hover, one step lighter than the rail. It cannot borrow the page's hover:
    #: a near-white chip flashing under the cursor on navy reads as a rendering fault.
    nav_hover: str
    #: Filter chips on the files page: unselected is a white pill with a hairline, selected
    #: wears the accent and loses the outline.
    chip: str
    chip_border: str
    chip_sel: str
    #: The rounded square behind a device glyph. The mockups tint it pale blue so the icon
    #: inside reads as belonging to the row's name rather than as decoration.
    tile: str
    #: The dashed outline of the drop zone, and the text inside it.
    drop_border: str
    drop_text: str
    #: A card sits on the page; a block sits inside a card. The mockups keep these two greys
    #: apart on purpose, so the nesting reads without a border.
    card: str
    inner: str
    hairline: str
    #: Online/offline dots and the green that means "it landed".
    ok: str
    ok_dot: str
    off_dot: str
    err: str


LIGHT = Palette(
    name="light",
    window="#eef1f8",
    surface="#ffffff",
    text="#121c26",
    text_muted="#686874",
    border="#ececec",
    hover="#e8eaed",
    pressed="#d9dce0",
    accent="#3b82f6",
    accent_text="#ffffff",
    close_hover="#f36b5f",
    close_pressed="#d94a3d",
    menu_hover="#eef2fb",
    nav="#1a293e",
    nav_text="#a9b6c8",
    nav_sel="#3b82f6",
    nav_sel_text="#ffffff",
    nav_muted="#6b7c93",
    nav_hover="#243650",
    chip="#ffffff",
    chip_border="#e0e0e0",
    chip_sel="#3b82f6",
    tile="#e8f0fe",
    drop_border="#c3ccd8",
    drop_text="#5f6b7a",
    card="#ffffff",
    inner="#f5f6fa",
    hairline="#ececec",
    ok="#1cab69",
    ok_dot="#33c388",
    off_dot="#9ca3af",
    err="#e5484d",
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
    nav="#13161a",
    nav_text="#98a1ab",
    nav_sel="#4f8cf7",
    nav_sel_text="#ffffff",
    nav_muted="#6c7480",
    nav_hover="#1f242b",
    chip="#2a2f36",
    chip_border="#3a4048",
    chip_sel="#4f8cf7",
    tile="#2b3542",
    drop_border="#3c434c",
    drop_text="#98a1ab",
    card="#23272e",
    inner="#1f232a",
    hairline="#31363d",
    ok="#3ecf8e",
    ok_dot="#3ecf8e",
    off_dot="#6c7480",
    err="#f0605f",
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
/* A path shown for reading, not typing: the recessed grey says so without a disabled look. */
QLineEdit#PathField {{
    background: {p.inner};
    border: 1px solid {p.hairline};
    border-radius: 8px;
    padding: 4px 8px;
    color: {p.text_muted};
}}
QRadioButton, QCheckBox {{ spacing: 6px; }}
/* The file page's search box is a pill on the page, not a field in a form: the mockups give it
   the same rounded ends as the chips below it so the two rows read as one filter group. */
QLineEdit#Search {{
    background: {p.surface};
    border: 1px solid {p.border};
    border-radius: 18px;
    min-height: 20px;
    padding: 9px 16px;
    color: {p.text};
}}
QLineEdit#Search:focus {{ border: 1px solid {p.accent}; }}
/* Both tables live inside a card, so they wear the card rather than their own frame: no border,
   no grey well, and the row separation is the hairline the mockups draw under each file. */
QTreeView#ReceivedTable, QTreeView#HistoryTable {{
    background: transparent;
    border: none;
    padding: 0;
}}
QTreeView#ReceivedTable::item, QTreeView#HistoryTable::item {{
    min-height: 34px;
    padding: 6px 4px;
    border-bottom: 1px solid {p.hairline};
    border-radius: 0;
}}
QTreeView#ReceivedTable::item:selected, QTreeView#HistoryTable::item:selected {{
    background: {p.menu_hover};
    color: {p.text};
}}
QTreeView#ReceivedTable QHeaderView {{ background: transparent; }}
/* The section's height is set rather than padded: a vertical padding pushes the words down and
   leaves the sort chevron at the top of the section, which reads as a mark on nothing. */
QTreeView#ReceivedTable QHeaderView::section {{
    background: transparent;
    border: none;
    border-bottom: 1px solid {p.hairline};
    height: 34px;
    padding: 0 4px;
    color: {p.text_muted};
    font-weight: 400;
}}
QWidget#TitleBar {{ background: {p.surface}; border-bottom: 1px solid {p.border}; }}

/* ---- left rail ---- */
QWidget#Nav {{ background: {p.nav}; }}
QWidget#Nav QLabel {{ color: {p.text}; }}
QLabel#Brand {{ font-size: 17px; font-weight: 700; color: #ffffff; background: transparent; }}
QLabel#BrandSub {{ font-size: 11px; color: {p.nav_muted}; background: transparent; }}
QLabel#BrandIcon {{ background: {p.nav_sel}; border-radius: 9px; }}
/* The rail's last row is the account, not a command: a face plus the machine's own name,
   with no button chrome around it until the pointer arrives. */
QPushButton#NavUser {{
    background: transparent;
    color: {p.nav_text};
    border: none;
    border-radius: 18px;
    padding: 7px 12px;
    text-align: left;
    font-size: 12px;
}}
QPushButton#NavUser:hover {{ background: {p.nav_hover}; color: {p.nav_sel_text}; }}
/* The rail's item is a pill, not a full-bleed bar: the mockups put 12px of navy on either
   side of it, which is what keeps five stacked rows from reading as a table. */
QPushButton#NavButton {{
    background: transparent;
    color: {p.nav_text};
    border: none;
    border-radius: 18px;
    padding: 10px 14px;
    text-align: left;
    font-size: 14px;
}}
QPushButton#NavButton:hover {{ background: {p.nav_hover}; color: {p.nav_sel_text}; }}
/* Checked is the page you are on, so it is the one item in the rail wearing the accent. */
QPushButton#NavButton:checked {{ background: {p.nav_sel}; color: {p.nav_sel_text}; font-weight: 600; }}

/* ---- pages ---- */
QLabel#PageTitle {{ font-size: 26px; font-weight: 700; color: {p.text}; }}
QLabel#PageSub {{ font-size: 12px; color: {p.text_muted}; }}
QScrollArea#Page {{ background: transparent; border: none; }}

/* A card is the white sheet on the page; a block is the recessed grey inside it. */
QFrame#Card {{ background: {p.card}; border: none; border-radius: 16px; }}
QFrame#Card QLabel {{ background: transparent; }}
QFrame#Block {{ background: {p.inner}; border: none; border-radius: 12px; }}
QFrame#Block QLabel {{ background: transparent; }}
QFrame#Hairline {{ background: {p.hairline}; border: none; }}

/* ---- the settings sheet (fig6) ---- */
/* A row is caption-left, control-right, and the sheet's own white has to show through it:
   without this the child QWidget repaints with the palette's window colour and the row reads
   as a grey bar inside a white card. */
QWidget#SettingRow {{ background: transparent; }}
QWidget#SettingRow QLabel {{ background: transparent; }}
QLabel#RowTitle {{ font-size: 15px; font-weight: 600; color: {p.text}; }}
QLabel#RowNote {{ font-size: 12px; color: {p.text_muted}; }}
QLabel#RowValue {{ font-size: 12px; color: {p.text_muted}; }}
/* The mockup draws the path and its 浏览 button inside one outline, so the field loses its own
   chrome and the frame around it takes over. */
QFrame#FieldGroup {{ background: {p.surface}; border: 1px solid {p.border}; border-radius: 10px; }}
QLineEdit#FieldBare {{ background: transparent; border: none; padding: 0; color: {p.text}; }}
/* The choice pills replace a radio group: the picked one is the only outlined thing on the row. */
QPushButton#Choice {{
    background: {p.inner};
    color: {p.text};
    border: 1px solid {p.hairline};
    border-radius: 8px;
    padding: 7px 18px;
}}
QPushButton#Choice:hover {{ background: {p.hover}; }}
/* No font-weight here on purpose. The mockup marks the picked pill with its accent outline and
   coloured text at the same weight as its neighbours, and a heavier face would not fit the width
   Qt reserved from the normal-weight metrics - which is how "Follow system" came to be drawn with
   its first letter cut off. */
QPushButton#Choice:checked {{
    background: {p.card};
    color: {p.accent};
    border: 1px solid {p.accent};
}}
QListWidget#PinList {{
    background: {p.inner};
    border: 1px solid {p.hairline};
    border-radius: 12px;
    padding: 4px;
    outline: none;
}}
QListWidget#PinList::item {{ padding: 7px 10px; border-radius: 8px; color: {p.text}; }}
QListWidget#PinList::item:selected {{ background: {p.menu_hover}; color: {p.text}; }}
/* The speed limit is a number you type as much as one you step, so it wears the same field as
   the rest; Qt's default spin box brings its own bevel with it. */
QSpinBox {{
    background: {p.surface};
    border: 1px solid {p.border};
    border-radius: 8px;
    padding: 5px 8px;
    color: {p.text};
}}
QSpinBox:disabled {{ background: {p.inner}; color: {p.text_muted}; }}
QSpinBox::up-button, QSpinBox::down-button {{ width: 16px; border: none; background: transparent; }}

/* ---- the incoming-offer card (fig5) ---- */
/* The dialog itself is translucent; this sheet is the whole visible window, so it carries the
   radius the mockup draws and the shadow that separates it from the page behind. */
QFrame#OfferCard {{ background: {p.card}; border: 1px solid {p.hairline}; border-radius: 24px; }}
QFrame#OfferCard QLabel {{ background: transparent; }}
QLabel#OfferTitle {{ font-size: 20px; font-weight: 700; color: {p.text}; }}
/* The file list is a sheet inside the sheet: the mockup keeps it the page's own white and lets a
   hairline do the separating, because a grey block behind three white rows reads as a table. */
QFrame#OfferFiles {{ background: {p.card}; border: 1px solid {p.hairline}; border-radius: 14px; }}
QFrame#OfferFiles QLabel {{ background: transparent; }}
/* "保存到" is a tag, not a field label: the mockup gives it the recessed chip the settings page
   uses for a value that is shown rather than typed. */
QLabel#Tag {{
    background: {p.inner};
    border: 1px solid {p.hairline};
    border-radius: 6px;
    padding: 3px 8px;
    color: {p.text_muted};
}}
/* 拒绝 is the answer that costs nothing, so it is a grey pill: filled enough to be a button,
   quiet enough that the one blue button on the card stays the thing you look at. */
QPushButton#Secondary {{
    background: {p.inner};
    color: {p.text};
    border: 1px solid {p.hairline};
    border-radius: 8px;
    padding: 7px 22px;
}}
QPushButton#Secondary:hover {{ background: {p.hover}; color: {p.text}; }}
QPushButton#Secondary:pressed {{ background: {p.pressed}; color: {p.text}; }}
QPushButton#Secondary:disabled {{ background: {p.inner}; color: {p.text_muted}; border: 1px solid {p.hairline}; }}

/* A device row is the mockup's own shape: a tinted tile holding the glyph, the name the peer
   chose for itself, and a dot on the right that says whether it is answering. The row is the
   card, so the list that holds the rows must not draw a box around them as well. */
QFrame#DeviceRow {{ background: {p.inner}; border: 1px solid transparent; border-radius: 12px; }}
QFrame#DeviceRow:hover {{ background: {p.hover}; }}
QFrame#DeviceRow[chosen="true"] {{ background: {p.menu_hover}; border: 1px solid {p.accent}; }}
QLabel#DeviceTile {{ background: {p.tile}; border-radius: 10px; }}
/* The 附近设备 cards draw their tile as a disc; the device rows on the other pages keep the
   rounded square. Two shapes because the mockups show two shapes. */
QLabel#DeviceTileRound {{ background: {p.tile}; border-radius: 20px; }}
QLabel#DeviceName {{ font-size: 14px; font-weight: 600; color: {p.text}; }}
/* The 附近设备 cards are buttons wearing a sheet: the mockup gives them the card's own radius
   and holds the accent outline back until one is picked. */
QPushButton#DeviceCard {{
    background: {p.card};
    border: 1px solid transparent;
    border-radius: 16px;
    padding: 0;
    text-align: left;
}}
QPushButton#DeviceCard:hover {{ background: {p.hover}; }}
QPushButton#DeviceCard:checked {{ border: 1px solid {p.accent}; background: {p.menu_hover}; }}
QPushButton#DeviceCard QLabel {{ background: transparent; }}
/* The blanket rule above outranks QLabel#DeviceTileRound on selector weight, so the disc has to
   name its button to keep a fill of its own. */
QPushButton#DeviceCard QLabel#DeviceTileRound {{ background: {p.tile}; border-radius: 20px; }}
QListWidget#DeviceList, QListWidget#TaskList, QListWidget#RecordList {{
    background: transparent;
    border: none;
    padding: 0;
}}
QListWidget#DeviceList::item, QListWidget#TaskList::item, QListWidget#RecordList::item {{
    background: transparent;
    padding: 0;
    margin: 0;
}}
QListWidget#DeviceList::item:selected, QListWidget#TaskList::item:selected,
QListWidget#RecordList::item:selected {{
    background: transparent;
    color: {p.text};
}}
/* The record list: the day is a caption, the row is a hairline away from the next one. */
QLabel#DayHeading {{
    background: transparent;
    color: {p.text_muted};
    font-size: 13px;
    padding: 10px 2px 2px 2px;
}}
QFrame#RecordRow {{
    background: transparent;
    border: none;
    border-bottom: 1px solid {p.hairline};
    border-radius: 0;
}}
QLabel#RecordName {{ background: transparent; font-size: 14px; font-weight: 600; color: {p.text}; }}
QLabel#Running {{ background: transparent; color: {p.accent}; }}
/* A live send shares the record card with the arrivals under it, so it is drawn the same way:
   a hairline between rows, not a box around each one. Two shapes in one list reads as two lists. */
QWidget#TaskRow {{
    background: transparent;
    border: none;
    border-bottom: 1px solid {p.hairline};
    border-radius: 0;
}}
QWidget#TaskRow QLabel {{ background: transparent; }}

/* ---- filter chips ---- */
/* The mockups' chips are pills. Qt silently draws a square corner when the requested radius is
   more than half the widget's height, so the height is pinned here and the radius kept under it
   - otherwise the pill reads as five rectangles, which is what 19px on a 32px button did. */
QPushButton#Chip {{
    background: {p.chip};
    color: {p.text};
    border: 1px solid {p.chip_border};
    border-radius: 18px;
    min-height: 20px;
    padding: 9px 20px;
    font-size: 14px;
}}
QPushButton#Chip:hover {{ background: {p.hover}; color: {p.text}; }}
QPushButton#Chip:checked {{ background: {p.chip_sel}; color: {p.accent_text}; border: 1px solid {p.chip_sel}; }}

/* The mockups' secondary action: an accent outline holding accent text, never a filled block,
   because a filled one would compete with the single primary button on the page. */
QPushButton#Ghost {{
    background: transparent;
    color: {p.accent};
    border: 1px solid {p.accent};
    border-radius: 8px;
    padding: 5px 14px;
}}
QPushButton#Ghost:hover {{ background: {p.menu_hover}; color: {p.accent}; }}
QPushButton#Ghost:pressed {{ background: {p.hover}; color: {p.text}; }}
QPushButton#Ghost:disabled {{ background: transparent; color: {p.text_muted}; border: 1px solid {p.border}; }}

/* 扫码连接 is the one thing on its card worth pressing, and the mockups draw it as a pill
   spanning the card - the round ends are what separate a full-width primary action from a bar
   of text the user reads past. */
QPushButton#Pill {{ border-radius: 20px; min-height: 22px; padding: 10px 18px; font-size: 14px; font-weight: 600; }}

/* A status line is a dot plus a word; the dot carries the colour so the word can stay in the
   reader's own palette and the pair still reads at a glance. */
QLabel#Ok {{ color: {p.ok}; }}
QLabel#Err {{ color: {p.err}; }}
QLabel#MutedOnCard {{ color: {p.text_muted}; background: transparent; }}

/* The drop target is an outline with nothing in it, so it is drawn rather than painted. */
QFrame#DropZone {{
    background: {p.surface};
    border: 2px dashed {p.drop_border};
    border-radius: 10px;
}}
QLabel#DropHint {{ color: {p.drop_text}; background: transparent; }}
QLabel#DropIcon {{ background: {p.tile}; border-radius: 36px; }}
QLabel#DropBig {{ font-size: 15px; font-weight: 600; color: {p.drop_text}; background: transparent; }}
/* While a drag is over the window the outline says "here", in the accent rather than the
   border grey, because a dashed line that never changes is a line nobody reads. */
QFrame#DropZone[dragging="true"] {{ border: 2px solid {p.accent}; background: {p.hover}; }}

/* A transfer in flight is one row: mark, name, bar, how far, cancel. */
QWidget#TaskRow QProgressBar {{ height: 6px; }}

QGroupBox {{
    background: {p.card};
    border: 1px solid {p.border};
    border-radius: 16px;
    margin-top: 10px;
    padding: 14px 12px 12px 12px;
}}
QGroupBox::title {{ subcontrol-origin: margin; left: 10px; padding: 0 4px; color: {p.text_muted}; }}

QListWidget {{ background: {p.window}; border: 1px solid {p.border}; border-radius: 6px; padding: 2px; }}
QListWidget::item {{ padding: 6px; border-radius: 4px; color: {p.text}; }}
QListWidget::item:selected {{ background: {p.menu_hover}; color: {p.text}; }}

QTreeView {{ background: {p.window}; alternate-background-color: {p.surface}; border: 1px solid {p.border}; border-radius: 6px; padding: 2px; color: {p.text}; }}
QTreeView::item {{ padding: 6px; border-radius: 4px; }}
QTreeView::item:selected {{ background: {p.menu_hover}; color: {p.text}; }}
QHeaderView::section {{ background: {p.surface}; color: {p.text_muted}; border: none; border-bottom: 1px solid {p.border}; padding: 6px 8px; }}

QProgressBar {{
    background: {p.window};
    border: 1px solid {p.border};
    border-radius: 6px;
    text-align: center;
    color: {p.text};
}}
QProgressBar::chunk {{ background: {p.accent}; border-radius: 5px; }}
/* The mockups' transfer bar is a 6px rail with the number written beside it, not inside it:
   a percentage in a 6px groove is unreadable, and the row already has a column for it. */
QProgressBar#Slim {{
    background: {p.inner};
    border: none;
    border-radius: 3px;
    max-height: 6px;
    min-height: 6px;
    text-align: none;
}}
QProgressBar#Slim::chunk {{ background: {p.accent}; border-radius: 3px; }}

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
/* A closed row's verdict is an answer, not a control that happens to be greyed out, so it takes
   the same green and red the record rows use. */
QPushButton#Inline[state="ok"] {{ color: {p.ok}; }}
QPushButton#Inline[state="err"] {{ color: {p.err}; }}

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
