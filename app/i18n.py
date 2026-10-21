"""gettext-based internationalization.

Message ids are the Chinese source strings, so an untranslated build still reads
correctly in Chinese and each locale only carries its own translations.

Switching language re-reads the .mo catalogue and emits LanguageManager.changed;
widgets re-apply their texts in a retranslate() slot.
"""

from __future__ import annotations

import gettext
import logging
from pathlib import Path

from PySide6.QtCore import QCoreApplication, QObject, QLocale, QTranslator, Signal

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


class LanguageManager(QObject):
    changed = Signal(str)

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._localedir: Path = locale_dir()
        self._current = "zh_CN"
        self._qt_translator: QTranslator | None = None

    @property
    def current(self) -> str:
        return self._current

    def display_name(self, code: str) -> str:
        return LANGUAGE_NAMES.get(code, code)

    def available(self) -> list[str]:
        """Locale codes with a compiled catalogue, in LANGUAGE_NAMES order."""
        found = set()
        if self._localedir.is_dir():
            for entry in sorted(self._localedir.iterdir()):
                if (entry / "LC_MESSAGES" / f"{TRANSLATION_DOMAIN}.mo").is_file():
                    found.add(entry.name)
        ordered = [code for code in LANGUAGE_NAMES if code in found]
        return ordered + sorted(found - set(ordered))

    def detect_system(self) -> str:
        """Best match between the OS locale and the compiled catalogues."""
        options = self.available()
        if not options:
            return "zh_CN"
        name = QLocale.system().name()
        if name in options:
            return name
        prefix = name.split("_")[0]
        for code in options:
            if code.split("_")[0] == prefix:
                return code
        return "en" if "en" in options else options[0]

    def resolve(self, preference: str) -> str:
        """Map a saved preference ("auto" or a locale code) onto an available locale."""
        options = self.available()
        if preference and preference != "auto":
            if preference in options:
                return preference
            prefix = preference.split("_")[0]
            for code in options:
                if code.split("_")[0] == prefix:
                    return code
        return self.detect_system()

    def set_language(self, code: str) -> None:
        global _catalog
        try:
            _catalog = gettext.translation(
                TRANSLATION_DOMAIN,
                str(self._localedir),
                languages=[code],
                fallback=True,
            )
        except OSError:
            log.exception("failed to load catalogue for %s", code)
            _catalog = gettext.NullTranslations()
        self._current = code
        self._load_qt_translator(code)
        log.info("language set to %s", code)
        self.changed.emit(code)

    def _load_qt_translator(self, code: str) -> None:
        """Localize Qt's built-in strings (dialog buttons, standard headers)."""
        if self._qt_translator is not None:
            QCoreApplication.removeTranslator(self._qt_translator)
            self._qt_translator = None

        import PySide6

        qt_dir = Path(PySide6.__file__).resolve().parent / "translations"
        for variant in (code, code.replace("_", "-"), code.replace("_", "-").lower()):
            candidate = qt_dir / f"qtbase_{variant}.qm"
            if candidate.is_file():
                translator = QTranslator()
                if translator.load(str(candidate)):
                    self._qt_translator = translator
                    QCoreApplication.installTranslator(translator)
                    return
                log.warning("found %s but QTranslator failed to load it", candidate)
                return
        log.debug("no qtbase catalogue for %s under %s", code, qt_dir)
