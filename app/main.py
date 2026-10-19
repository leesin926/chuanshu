"""Process entry point: logging -> crash handlers -> Qt app -> language -> window."""

from __future__ import annotations

import logging
import sys

from app import icons
from app.config import Settings
from app.crash import SafeApplication, install_crash_handlers
from app.i18n import LanguageManager
from app.logging_setup import setup_logging
from app.meta import APP_NAME, ORG_NAME
from app.paths import locale_dir
from app.ui import theme
from app.ui.main_window import MainWindow

log = logging.getLogger(__name__)


def main() -> int:
    setup_logging()
    install_crash_handlers()

    app = SafeApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setOrganizationName(ORG_NAME)
    # Closing the window may only hide it to the tray, so quitting has to be explicit.
    app.setQuitOnLastWindowClosed(False)

    settings = Settings()
    languages = LanguageManager()
    if not languages.available():
        log.warning("no compiled catalogues under %s - run: powershell -File build.ps1 -Task i18n", locale_dir())
    languages.set_language(languages.resolve(settings.get("language", "auto")))
    palette = theme.palette_for(settings.get("theme", "auto"))
    theme.apply_theme(app, palette)
    # One logo for the whole app: every window and dialog inherits QApplication's icon,
    # and QMessageBox.about() paints it inside the box.
    app.setWindowIcon(icons.window_icon(palette.text))

    window = MainWindow(settings, languages)
    window.show()
    log.info("%s started", APP_NAME)
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
