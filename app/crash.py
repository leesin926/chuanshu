"""Global exception capture: log every uncaught error, tell the user when possible.

Two paths need different handling:
- Qt slots raise inside QApplication.notify, so SafeApplication catches them and the
  window survives.
- Worker threads report through threading.excepthook, which runs on that worker thread;
  Qt dialogs may only be built on the main thread, so the notification is marshalled
  back through a queued signal.
"""

from __future__ import annotations

import logging
import sys
import threading
import traceback

from PySide6.QtCore import QCoreApplication, QObject, QEvent, Signal
from PySide6.QtWidgets import QApplication, QMessageBox

from app.i18n import _
from app.logging_setup import log_file

log = logging.getLogger("app.crash")


class _Notifier(QObject):
    #: (window title, traceback text) - delivered on whichever thread owns this object.
    report = Signal(str, str)


_notifier: _Notifier | None = None


def _show_dialog(title: str, detail: str) -> None:
    app = QCoreApplication.instance()
    if not isinstance(app, QApplication):
        sys.stderr.write(f"{title}\n{detail}\n")
        return
    box = QMessageBox(app.activeModalWidget() or app.activeWindow())
    box.setIcon(QMessageBox.Critical)
    box.setWindowTitle(title)
    box.setText(_("程序遇到未处理的错误。操作可以继续，但请查看日志。"))
    box.setInformativeText(f"{_('日志文件')}: {log_file()}")
    box.setDetailedText(detail)
    box.exec()


def _report(context: str, exc_type, exc_value, exc_traceback) -> str:
    detail = "".join(traceback.format_exception(exc_type, exc_value, exc_traceback))
    log.error("uncaught exception (%s):\n%s", context, detail)
    return detail


def _excepthook(exc_type, exc_value, exc_traceback) -> None:
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return
    _deliver(_("未处理的异常"), _report("main", exc_type, exc_value, exc_traceback))


def _thread_excepthook(args: threading.ExceptHookArgs) -> None:
    thread = args.thread.name if args.thread else "?"
    detail = _report(
        f"thread:{thread}", args.exc_type, args.exc_value, args.exc_traceback
    )
    _deliver(_("后台线程异常"), detail)


def _deliver(title: str, detail: str) -> None:
    if _notifier is not None:
        _notifier.report.emit(title, detail)
    else:
        _show_dialog(title, detail)


def install_crash_handlers() -> None:
    global _notifier
    _notifier = _Notifier()
    _notifier.report.connect(_show_dialog)
    sys.excepthook = _excepthook
    threading.excepthook = _thread_excepthook


class SafeApplication(QApplication):
    """QApplication that logs exceptions raised in event handlers instead of aborting."""

    def notify(self, receiver, event: QEvent) -> bool:
        try:
            return super().notify(receiver, event)
        except Exception:
            detail = traceback.format_exc()
            log.error("exception while handling %s:\n%s", event.type(), detail)
            if event.type() not in (QEvent.MouseMove, QEvent.Paint):
                _deliver(_("界面处理异常"), detail)
            return False
