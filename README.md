# 传书 ChuanShu — PC 端（PySide6 桌面客户端）

局域网文件互传的桌面端：对等协议（既能发也能收）、Ed25519 自签证书 + SPKI 指纹固定、
断点续传。同时保留国际化（gettext）、日志与异常捕获、PyInstaller 打包、Inno Setup 安装包
这条脚手架链路。

## 仓库与分支

| | 位置 | 内容 |
|---|---|---|
| PC 端 | 本仓库（远端名 `chuanshu-pc`） | PySide6 桌面端，Linux/Windows/macOS |
| 手机端 | `chuanshu-mobile` | uni-app x，一套代码出 Android / iOS / 鸿蒙 |
| 协议契约 | 两边各存一份 `protocol/` | `protocol.json` 是唯一真相源，手机端放在 `shared/protocol/` 并带来源摘要戳 |

分支按打包方式分开，不要让一个安装包背另一套方案的依赖：

- `main` = 局域网直连（mDNS + UDP 广播 + 扫码），当前唯一有实现的路线。
- `cloud-relay` = 云中转。它**不复制协议**，只替换寻址（见 `protocol/spec.md` §8）；中继服务
  还没有，所以这条分支暂时与 `main` 同树，等中转服务端落地后只改寻址和账号鉴权。

两端各自跑同一份 `protocol/protocol.json` 校验自己那端；契约改动先改文件、再改代码。

## 目录结构

```
app/
  meta.py            应用名 / 版本 / 发布者（唯一改这里即可发新版）
  paths.py           源码运行 与 冻结(打包) 运行 的路径解析
  config.py          settings.json 读写，存放于 %APPDATA%\ChuanShu\ChuanShu
  i18n.py            gettext 目录 + LanguageManager，切语言发 changed 信号
  logging_setup.py   滚动日志，存放于 %APPDATA%\ChuanShu\ChuanShu\logs\app.log
  crash.py           全局异常捕获 + SafeApplication（Qt 槽函数异常不退出）
  autostart.py       开机自启（HKCU ...\CurrentVersion\Run，仅打包后可用）
  icons.py           读取 assets/icons/icons.json → QIcon/QPixmap（按角色取字形与尺寸，带缓存）
  main.py            入口
  ui/main_window.py  主窗口：无边框外壳、托盘、关闭询问、主题切换、retranslate()
  ui/title_bar.py    自绘标题栏：六个图标按钮 + popup_below()、拖动/缩放/最大化、边缘缩放 eventFilter
  ui/theme.py        深浅两套 Palette 与由它生成的 QSS
  ui/tray.py         系统托盘菜单（打开主界面 / 开机自启 / 退出）
app/net/
  spec.py            读取 protocol/protocol.json：端点、错误码→HTTP、二维码字段顺序
  identity.py        Ed25519 自签证书、SPKI 指纹固定、已配对设备表（identity/ 目录）
  receive.py         接收端 HTTPS 服务：配对、offer、分块落盘、路径清洗、崩溃后认领未完成 offer
  send.py            发送端：plan→offer→分块→finalize，token 失效时用已信任的 key 静默重配对
  errors.py          错误码的中文 msgid 字面量（给 pybabel 抽取用），与 protocol.json 必须一致
protocol/
  protocol.json      机器可读契约：端口、chunk_size、端点清单、错误码表、限制值
  spec.md            语义与理由：为什么这么定，两端必须一致实现什么
scripts/
  protocol_selftest.py  M0 验收：配对→多文件含目录→杀进程重启→续传→finalize，40 条断言
  receiver_host.py      给自测用的独立接收进程
assets/icons/
  icons.json         图标配置：`window_icon` 指定全应用 logo，`glyphs` 字形表，`buttons` 角色→字形
                     （含主题/最大化变体），`pixmap_sizes` 每个 QIcon 的尺寸，`icon_sizes` 每按钮尺寸
  *.svg              一个字形一个文件，颜色写 `currentColor`，加载时替换成当前 Palette 的色值
locale/
  zh_CN/LC_MESSAGES/app.po(.mo)
  en/LC_MESSAGES/app.po(.mo)
  app.pot            模板，由 pybabel extract 生成
installer/setup.iss  Inno Setup 脚本（分区注释说明每个指令为什么这么写）
installer/licenses/  免责声明文本（zh_CN / en，UTF-8 BOM）
installer/languages/ 可选：项目自带的 ChineseSimplified.isl，优先于编译器版本
app.spec             PyInstaller 配置（one-folder，捆绑 locale）
build.ps1            i18n / exe / installer 流水线
babel.cfg            pybabel 抽取映射
```

## 环境

- Python 3.10–3.15（本机 3.14 已验证 PySide6 6.12 有 cp310-abi3 wheel）
- Windows；`py` 启动器可用

```powershell
py -m pip install -r requirements.txt -r requirements-dev.txt
py -m app                     # 源码运行
```

首次运行前需要编译翻译目录，否则界面走 msgid 回退（中文原文仍正确）：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File build.ps1 -Task i18n
```

## 国际化约定

- **msgid 就是中文原文**。`_()` / `_n()` 定义在 `app/i18n.py`，各模块 `from app.i18n import _, _n`。
- 未翻译的条目回退成中文，因此新增文案不会让英文界面崩溃。
- 语言优先级：`settings.json` 里的 `language` → 系统 locale → `en`。
  标题栏的语言菜单只列已编译的 locale，没有「跟随系统」项：`language` 保持 `auto` 就是跟随系统，
  一旦从菜单选了具体语言就固定下来（要恢复跟随，删掉 `settings.json` 里那个键）。
- 切语言时 `LanguageManager.set_language()` 会重新加载 `.mo`、装上 Qt 自带的
  `qtbase_*.qm`（负责对话框按钮等 Qt 内置文案），然后发 `changed` 信号；控件在
  `retranslate()` 里重设文本。新增界面时把文本设置都放进 `retranslate()`。
- 新增语言：`pybabel init -i locale/app.pot -d locale -D app -l ja`，翻译后
  `build.ps1 -Task i18n`，`app/i18n.py` 的 `LANGUAGE_NAMES` 加一项 `ja: 日本語`。

## 窗口外观（无边框 + 托盘）

`settings.json` 里与外观相关的键（全部持久化，`theme` 取 `auto|light|dark`）：

| 键 | 取值 | 作用 |
| --- | --- | --- |
| `theme` | `auto` / `light` / `dark` | `auto` 跟随 Windows `AppsUseLightTheme` |
| `on_close` | `ask` / `tray` / `quit` | 点关闭时问什么；`ask` 每次弹框，勾选"记住我的选择"后写成 `tray`/`quit` |
| `autostart` | bool | 仅记录意图，真实状态以注册表为准 |
| `window` | `{width,height}` | 上次退出的尺寸 |

几个实现上的取舍，改动前先看这里：

- **标题栏上没有菜单栏**：六个 `QToolButton` —— `AppButton`(logo)、`LangButton`(globe)、
  `ThemeButton`(sun/moon)、`MinButton`、`MaxButton`、`CloseButton`。前三个各带一个 `QMenu`，
  由 `TitleBar.popup_below()` 在按钮左下角（`button.rect().bottomLeft()` 映射到全局）弹出；
  别改成跟随鼠标位置弹，菜单会漂离按钮。`ThemeButton` 的字形随深浅色翻转，
  所以 `restyle(color, dark)` 需要同时拿到颜色和明暗标志。
- **快捷键挂在窗口上**：`Ctrl+H` 隐藏到托盘、`Ctrl+Q` 退出，用 `self.addAction()` 注册。
  没有 `QMenuBar` 就没有地方隐式持有它们，只 `setShortcut()` 到 `QAction` 上是无效的。
- **拖动/缩放交给系统**：标题栏 `mousePressEvent` 调 `QWindow.startSystemMove()`，
  边缘 6px 带内调 `startSystemResize(edges)`。自己按鼠标位移挪窗口会丢掉 Win11 的
  Aero Snap 和吸附动画，别改成手写 move()。
- **最大化用系统状态**：`showMaximized()` + `isMaximized()`，实测最大化后窗口底边
  1031 ≤ 工作区底边 1031，不会盖住任务栏，所以不需要手动按 `availableGeometry` 摆位置。
  `is_maximized` 是 `changeEvent` 里同步的普通属性，标题栏图标和边缘滤镜都读它。
- **圆角只在 Win11 生效**：`DwmSetWindowAttribute(DWMWA_WINDOW_CORNER_PREFERENCE=33,
  DWMWCP_ROUND=2)`，build < 22000 直接 no-op（无边框窗口在 Win10 上是直角）。
- **图标全部由配置驱动**：字形是 `assets/icons/*.svg` 里的独立文件（写 `currentColor`，
  单独打开也是合法 SVG），`assets/icons/icons.json` 决定"哪个按钮用哪个字形、多大"，
  带变体：`"theme": {"default":"sun","dark":"moon"}`、`"max": {"default":"maximize","maximized":"restore"}`。
  读取和光栅化都在 `app/icons.py`，任何模块 `from app import icons` 就能用
  `icons.button_icon("tray", color)` / `icons.icon("logo", color)`。颜色是参数不是常量，
  因为切主题要按当前 Palette 重画，所以 `TitleBar.restyle()` 仍然必须被调用。
  `PySide6-Essentials` 自带 `QtSvg`，打包后 `_internal\PySide6\` 里有 `Qt6Svg.dll` + `QtSvg.pyd`；
  `assets\icons\`（含 `icons.json`）由 `app.spec` 一起收进 `_internal`，Inno 的递归复制自动带上。
- **logo 全应用共用一个**：`icons.json` 的 `window_icon` 是唯一来源，`main.py` 启动时
  `app.setWindowIcon(icons.window_icon(palette.text))`，之后新建的窗口/对话框不用写任何
  图标代码就继承过去（`QMessageBox.about()` 还会把它画进弹框里）；切主题时
  `MainWindow.apply_theme()` 重新按 Palette 上色。要单独给某个窗口换图标，就在那个窗口上
  `setWindowIcon()` 覆盖。
- **无边框窗口仍要 `setWindowTitle()`**：任务栏、Alt+Tab 和无障碍名称都用它，
  自绘标题栏只是把系统那条标题栏画成了自己的。
- **开机自启只在打包版可用**：源码运行没有单一 exe 可注册，`is_supported()` 会返回
  False，托盘复选框自动回弹并弹通知说明原因。

## 打包

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File build.ps1 -Task all
```

1. `pybabel extract/update/compile` → `locale/**.mo`
2. `pyinstaller app.spec` → `dist\ChuanShu\ChuanShu.exe`（one-folder，启动快、好排查）
3. `ISCC installer\setup.iss` → `dist\installer\ChuanShu-Setup-0.1.0-x64.exe`

Inno Setup 的定位顺序：`$env:ISCC` → 卸载注册表里的 `InstallLocation`（本机 7.1.0 装在 D 盘且不在
PATH）→ 常见安装目录 → PATH。

安装向导语言：英文用 `compiler:Default.isl`（6/7 都有；Inno 7 删掉了 `Languages\English.isl`，
别写死那条路径）。简体中文优先用项目内 `installer\languages\ChineseSimplified.isl`，
没有就回退到编译器自带的（7.0 起官方内置，6.x 需要 unofficial 语言包），两者都没有则只提供英文。

安装前必须同意的免责声明页：文本在 `installer\licenses\disclaimer-{lang}.txt`，
通过 `[Languages]` 各条目的 `LicenseFile` 与向导语言联动。两个约束要记住：
文件必须是 **UTF-8 带 BOM**（否则 Inno 按 ANSI 解析，中文变乱码）；未选"我同意此协议"时
"下一步"按钮保持禁用，这是 Inno 内置行为，不需要 `[Code]` 额外校验。
现有文本只是骨架模板，正式发布前按你的产品与适用法律重写。

> 本机网络注意：Inno Setup 自 2026-03 起二进制只在 GitHub releases 分发
> （`files.jrsoftware.org` 只剩 `.issig` 签名文件），`winget install JRSoftware.InnoSetup`
> 会因直连 GitHub 失败而报 `0x80072efd`。请在能访问 GitHub 的环境安装；
> 若从镜像下载，先用 `Get-AuthenticodeSignature` 看 `Status`，并核对 SHA-256 与
> GitHub release 页面一致——签名 `Valid` 只说明未被改动，不代表来自官方。

已在本机验证（Inno Setup 7.1.0）：`-Task installer` 编译通过，产出 35MB 安装包，
`/PORTABLE=1 /SILENT /DIR=...` 便携安装后 exe 正常启动、翻译与日志路径均正确。

界面这层的验证分两条路，各自能证明的东西不同：

- **进程内驱动真实窗口**（`windows` 平台 + `QTimer` 依次点按钮）：无边框标志、
  六个图标按钮都有非空 `QIcon` 且各 4 个尺寸、`popup_below()` 弹出的菜单位置与按钮
  左下角逐像素一致（中英文下三个菜单的条目文本都对）、sun/moon 字形翻转、
  最大化不压任务栏、关闭弹框的 3 个按钮 + "记住我的选择"、选"最小化到托盘"后窗口隐藏且进程存活、
  `on_close`/`theme` 落盘、深浅主题切换。`tray.py` 的 `show_message` → `showMessage`
  这类拼写错误只有这条路能抓到（Qt 方法是驼峰，写成蛇形会在运行时抛 AttributeError，
  被 SafeApplication 兜住）。
- **外部校验打包后的 exe**：`GetWindowLong(hwnd, GWL_STYLE)` 的样式位 `WS_CAPTION=False`
  证明确实无边框（`WS_THICKFRAME=False`、`WS_SYSMENU=True`）、窗口标题非空、日志里有
  `ChuanShu started` 且 0 条 ERROR、`_internal\PySide6\Qt6Svg.dll` + `QtSvg.pyd` 与两个 `.mo`
  都在包里、`.mo` 比 `.po` 新。UIA 只能走到 Qt 的中央 `QWidget`，再往下的 `QToolButton`
  枚举不到（`descendant_buttons_total=0`），所以按钮的存在与行为以进程内那条为准，
  外部只补了原生外壳和打包完整性的结论。
  脚本里两个坑：`Process.Refresh()` 在 PowerShell 里返回 void，写成
  `-not $proc.Refresh()` 会恒真、把整段窗口检查跳过；GUI 子进程继承了脚本的 stdout 句柄，
  不在 `finally` 里 Kill 掉，管道就一直不结束。

## 需要改的地方

- `app/meta.py`：应用名、版本、发布者（安装包名、开始菜单、卸载项都跟着变）
- `app/ui/main_window.py`：换成你的真实界面
- `app/ui/theme.py` 的 `LIGHT` / `DARK`：换配色只改这两处，QSS 与图标颜色自动跟着变
- 换/加图标：把 SVG 丢进 `assets/icons/`，在 `icons.json` 的 `glyphs` 里起个名字，再改
  `buttons` 里对应角色的映射（要按主题或最大化状态换字形就用 `{"default":..,"dark":..}` 变体写法）；
  `icon_sizes` 覆盖某个按钮的图标尺寸，`pixmap_sizes` 是每个 QIcon 打包的尺寸
- 打包时 `assets/icons/` 必须进 `_internal`：`app.spec` 用 `paths.icons_dir()` 同一套相对路径收集，
  漏了的话窗口在启动构造标题栏时就抛 `IconConfigError`（这是故意的：配置缺失不该静默降级）
- `app/ui/tray.py` 的 `context_menu`：别改名回 `menu`，那会盖掉 `QSystemTrayIcon.menu()`
- 若要便携单文件 exe：把 `app.spec` 的 `EXE(...)` 改成 onefile（去掉 `COLLECT`，
  把 `a.binaries, a.datas` 直接传给 `EXE`）
