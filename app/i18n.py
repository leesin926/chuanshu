"""gettext-based internationalization.

Message ids are the Chinese source strings, so an untranslated build still reads
correctly in Chinese and each locale only carries its own translations.

This module stays free of Qt: the network core (app/net/errors.py) builds its text
through ``_()`` and a command-line run has to localize it without a QApplication.
Everything that needs a running Qt - the ``changed`` signal widgets retranslate on
and the qtbase catalogues for Qt's own button labels - lives in
app/ui/language_manager.py, which delegates to the functions here.
"""

from __future__ import annotations

import gettext
import logging
import os
from pathlib import Path

from app.meta import TRANSLATION_DOMAIN
from app.paths import locale_dir

log = logging.getLogger(__name__)

#: Display names for the language menu, each written in its own language (an endonym),
#: so the list reads the same whichever language is on screen and needs no translation.
#: A locale becomes selectable as soon as its .mo exists, so this table only needs
#: entries for languages you add.
LANGUAGE_NAMES: dict[str, str] = {
    "zh_CN": "简体中文",
    "en": "English",
    "ja": "日本語",
    "ko": "한국어",
    "de": "Deutsch",
    "fr": "Français",
    "es": "Español",
    "ru": "Русский",
}

_catalog: gettext.NullTranslations = gettext.NullTranslations()
_current = "zh_CN"


def _(msgid: str) -> str:
    """Translate a single string."""
    return _catalog.gettext(msgid)


def N(msgid: str) -> str:
    """Name a string as translatable without translating it now.

    Widgets that are re-labelled on a language switch have to store the *message id*, not a
    string already translated in some other language, so the literals handed to those helpers
    are invisible to a plain ``_()`` call. Wrapping them in ``N()`` shows Babel the string and
    hands the caller back the same text; ``retranslate()`` does the translating later.
    """
    return msgid


def _n(singular: str, plural: str, n: int) -> str:
    """Translate a countable string. Python gettext has no %n, so format the number yourself."""
    return _catalog.ngettext(singular, plural, n)


def current() -> str:
    """The locale code ``use()`` last loaded, or the default before anything is loaded."""
    return _current


def available(localedir: Path | None = None) -> list[str]:
    """Locale codes with a compiled catalogue, in LANGUAGE_NAMES order."""
    root = localedir or locale_dir()
    found = set()
    if root.is_dir():
        for entry in sorted(root.iterdir()):
            if (entry / "LC_MESSAGES" / f"{TRANSLATION_DOMAIN}.mo").is_file():
                found.add(entry.name)
    ordered = [code for code in LANGUAGE_NAMES if code in found]
    return ordered + sorted(found - set(ordered))


def system_locale() -> str:
    """The OS language as far as the environment tells us, without Qt.

    A headless run has no QLocale, and LANG/LC_ALL carry the same choice the user made
    when the shell started. ``""`` when nothing is set, which ``resolve()`` treats as
    "no idea".
    """
    for name in ("LC_ALL", "LC_MESSAGES", "LANGUAGE", "LANG"):
        value = os.environ.get(name)
        if value:
            return value.split(".")[0]  # zh_CN.UTF-8 -> zh_CN
    return ""


def resolve(preference: str, system: str | None = None) -> str:
    """Map a saved preference ("auto" or a locale code) onto an available locale.

    ``system`` is the OS locale to fall back on; left out here so a GUI caller can hand
    over QLocale's answer instead of this module having to reach for Qt.
    """
    options = available()
    if preference and preference != "auto":
        if preference in options:
            return preference
        prefix = preference.split("_")[0]
        for code in options:
            if code.split("_")[0] == prefix:
                return code
    if not options:
        return "zh_CN"
    name = system_locale() if system is None else system
    if name in options:
        return name
    prefix = name.split("_")[0]
    for code in options:
        if code.split("_")[0] == prefix:
            return code
    return "en" if "en" in options else options[0]


def use(code: str) -> None:
    """Point ``_()`` and ``_n()`` at one locale's compiled catalogue."""
    global _catalog, _current
    try:
        _catalog = gettext.translation(
            TRANSLATION_DOMAIN,
            str(locale_dir()),
            languages=[code],
            fallback=True,
        )
    except OSError:
        log.exception("failed to load catalogue for %s", code)
        _catalog = gettext.NullTranslations()
    _current = code
    log.info("language set to %s", code)


def display_name(code: str) -> str:
    return LANGUAGE_NAMES.get(code, code)
