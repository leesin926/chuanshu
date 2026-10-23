"""The Qt half of language handling: a signal to retranslate on and Qt's own strings.

app/i18n.py owns catalogue loading and locale choice so a headless run can localize itself;
this subclass adds what only makes sense inside a QApplication - notifying widgets that the
language changed and installing the qtbase .qm that translates Qt's built-in labels.
"""

from __future__ import annotations

import logging
from pathlib import Path

from PySide6.QtCore import QCoreApplication, QObject, QLocale, QTranslator, Signal

from app import i18n

log = logging.getLogger(__name__)


class LanguageManager(QObject):
    changed = Signal(str)

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._qt_translator: QTranslator | None = None

    @property
    def current(self) -> str:
        return i18n.current()

    def display_name(self, code: str) -> str:
        return i18n.display_name(code)

    def available(self) -> list[str]:
        """Locale codes with a compiled catalogue, in LANGUAGE_NAMES order."""
        return i18n.available()

    def detect_system(self) -> str:
        """Best match between the OS locale and the compiled catalogues."""
        return i18n.resolve("auto", QLocale.system().name())

    def resolve(self, preference: str) -> str:
        """Map a saved preference ("auto" or a locale code) onto an available locale."""
        return i18n.resolve(preference, QLocale.system().name())

    def set_language(self, code: str) -> None:
        i18n.use(code)
        self._load_qt_translator(code)
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
