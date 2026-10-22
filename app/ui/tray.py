"""System tray presence for run-in-background mode."""

from __future__ import annotations

import logging

from PySide6.QtWidgets import QMenu, QSystemTrayIcon
from PySide6.QtCore import QObject, Signal

from app import icons
from app.autostart import is_supported, launch_command
from app.i18n import _

log = logging.getLogger(__name__)


class TrayIcon(QSystemTrayIcon):
    restore_requested = Signal()
    quit_requested = Signal()
    autostart_toggled = Signal(bool)

    def __init__(self, parent: QObject, color: str, app_name: str) -> None:
        super().__init__(parent)
        self.setIcon(icons.button_icon("tray", color))
        # Not `self.menu`: that would shadow QSystemTrayIcon.menu().
        self.context_menu = QMenu(parent)
        self.action_open = self.context_menu.addAction(_("打开主界面"))
        self.action_autostart = self.context_menu.addAction(_("开机自动启动"))
        self.action_autostart.setCheckable(True)
        self.action_quit = self.context_menu.addAction(_("退出{app}").format(app=app_name))
        self.setContextMenu(self.context_menu)

        self.action_open.triggered.connect(self.restore_requested)
        self.action_autostart.triggered.connect(self._on_autostart)
        self.action_quit.triggered.connect(self.quit_requested)
        self.activated.connect(self._on_activated)

    def _on_activated(self, reason: QSystemTrayIcon.ActivationReason) -> None:
        # Left double-click restores, matching the shell convention for tray apps.
        if reason in (QSystemTrayIcon.DoubleClick, QSystemTrayIcon.Trigger):
            self.restore_requested.emit()

    def _on_autostart(self, checked: bool) -> None:
        self.autostart_toggled.emit(checked)

    def sync_autostart(self, enabled: bool, checked: bool) -> None:
        """Reflect the real registry state; a rejected change must not stay ticked."""
        self.action_autostart.setChecked(enabled)
        if enabled != checked and not is_supported():
            self.showMessage(
                _("无法开启开机自动启动"),
                _("仅打包后的 Windows 版本可以注册开机自启。\n当前命令：{cmd}").format(cmd=launch_command()),
                QSystemTrayIcon.Warning,
                6000,
            )

    def retranslate(self, app_name: str) -> None:
        self.setToolTip(app_name)
        self.action_open.setText(_("打开主界面"))
        self.action_autostart.setText(_("开机自动启动"))
        self.action_quit.setText(_("退出{app}").format(app=app_name))

    def restyle(self, color: str) -> None:
        self.setIcon(icons.button_icon("tray", color))

    def notify_background(self, app_name: str) -> None:
        self.showMessage(
            app_name,
            _("已最小化到托盘，仍在后台运行。\n双击托盘图标可重新打开。"),
            self.icon(),
            4000,
        )

    def notify_arrival(self, app_name: str, who: str, count: int, size: str) -> None:
        """One message per finished transfer, so a window nobody is looking at still says it landed."""
        self.showMessage(
            app_name,
            _("收到 {who} 发来的 {n} 个文件（{size}）").format(who=who, n=count, size=size),
            self.icon(),
            5000,
        )
