# 传书 ChuanShu — PC 端（PySide6 桌面客户端）

局域网文件互传的桌面端：对等协议（既能发也能收）、Ed25519 自签证书 + SPKI 指纹固定、
断点续传。主窗口就是传输面板（我的设备 + 配对码/二维码 + 附近设备 + 发送进度），
外面套国际化（gettext）、日志与异常捕获、PyInstaller 打包、Inno Setup 安装包这条链路。

## 仓库与分支

| | 位置 | 内容 |
|---|---|---|
| PC 端 | 本仓库（远端名 `chuanshu-pc`） | PySide6 桌面端，Linux/Windows/macOS |
| 手机端 | `chuanshu-mobile` | uni-app x，一套代码出 Android / iOS / 鸿蒙 |
| 协议契约 | 两边各存一份 `protocol/` | `protocol.json` 是唯一真相源，手机端放在 `shared/protocol/` 并带来源摘要戳 |

分支按打包方式分开，不要让一个安装包背另一套方案的依赖：

- `main` = 局域网直连（mDNS + UDP 广播 + 手输地址/粘贴配对串兜底），当前唯一有实现的路线。
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
  ui/settings_dialog.py 设置窗口：左侧四个分区、右侧设置项，非模态，每个控件改完即生效
  ui/title_bar.py    自绘标题栏：七个图标按钮 + popup_below()、拖动/缩放/最大化、边缘缩放 eventFilter
  ui/theme.py        深浅两套 Palette 与由它生成的 QSS
  ui/transfer.py     传输面板：接收开关、配对码+二维码、设备名单（含手输地址）、暂存与发送、
                     来件确认弹框；所有线程回调都转成 Qt 信号再上 GUI
  ui/tray.py         系统托盘菜单（打开主界面 / 开机自启 / 退出）
app/net/
  spec.py            读取 protocol/protocol.json：端点、错误码→HTTP、二维码字段顺序
  identity.py        Ed25519 自签证书、SPKI 指纹固定、已配对设备表（identity/ 目录）
  receive.py         接收端 HTTPS 服务：配对、offer、分块落盘、路径清洗、崩溃后认领未完成 offer
  send.py            发送端：plan→offer→分块→finalize，token 失效时用已信任的 key 静默重配对
  discovery.py       局域网发现：mDNS 注册/浏览 + UDP 广播 43721；广播只带指纹前缀，
                     完整摘要必须经 verify() 从 /v1/hello 取回；每条通道可用与否单独上报
  errors.py          错误码的中文 msgid 字面量（给 pybabel 抽取用），与 protocol.json 必须一致
protocol/
  protocol.json      机器可读契约：端口、chunk_size、端点清单、错误码表、限制值
  spec.md            语义与理由：为什么这么定，两端必须一致实现什么
scripts/
  protocol_selftest.py  M0 验收：配对→多文件含目录→杀进程重启→续传→finalize→两条发现通道，
                        51 条断言（报告写在 .probe/protocol_report.txt）
  ui_selftest.py        M1 验收：驱动真实窗口，132 条断言（含设置窗口、8 种语言下缩到最小
                        尺寸不裁切）。见"界面这层的验证"
  freeze_smoke.py       起打包好的 exe：等窗口、截图、查日志有无 ERROR，然后只结束自己起的进程
  i18n_sync.py          翻译守卫：按 locale/ 目录扫描，zh_CN 空条目自动镜像 msgid；其余任何
                        语言只要还有空条目或 fuzzy 就直接构建失败（LANGUAGE_NAMES 承诺了却没
                        建目录的语言同样报错）
  receiver_host.py      给自测用的独立接收进程
assets/icons/
  icons.json         图标配置：`window_icon` 指定全应用 logo，`glyphs` 字形表，`buttons` 角色→字形
                     （含主题/最大化变体），`pixmap_sizes` 每个 QIcon 的尺寸，`icon_sizes` 每按钮尺寸
  *.svg              一个字形一个文件，颜色写 `currentColor`，加载时替换成当前 Palette 的色值
locale/
  zh_CN/ en/ ja/ ko/ de/ fr/ es/ ru/  各一份 LC_MESSAGES/app.po(.mo)
  app.pot            模板，由 pybabel extract 生成
installer/setup.iss  Inno Setup 脚本（分区注释说明每个指令为什么这么写）
installer/licenses/  免责声明文本（zh_CN / en，UTF-8 BOM）
installer/languages/ 可选：项目自带的 ChineseSimplified.isl，优先于编译器版本
app.spec             PyInstaller 配置（one-folder，捆绑 locale + assets/icons + protocol）
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

改过布局或翻译后跑界面自测，两个平台都要（offscreen 的字体度量是假的，见"界面这层的验证"）：

```powershell
$env:QT_QPA_PLATFORM = "offscreen"; py scripts/ui_selftest.py   # 报告尾部 RESULT ALL PASS
Remove-Item env:QT_QPA_PLATFORM; py scripts/ui_selftest.py      # 真字形 + 真布局最小值
```

## 国际化约定

- **msgid 就是中文原文**。`_()` / `_n()` 定义在 `app/i18n.py`，各模块 `from app.i18n import _, _n`。
- 界面语言共 8 种：`zh_CN en ja ko de fr es ru`，菜单里用各自的原语言名（Eigenname）显示。
- 未翻译的条目回退成中文，因此新增文案不会让英文界面崩溃。
- 语言优先级：`settings.json` 里的 `language` → 系统 locale → `en`。
  标题栏的语言菜单只列已编译的 locale，没有「跟随系统」项：`language` 保持 `auto` 就是跟随系统，
  一旦从菜单选了具体语言就固定下来（要恢复跟随，删掉 `settings.json` 里那个键）。
- 切语言时 `LanguageManager.set_language()` 会重新加载 `.mo`、装上 Qt 自带的
  `qtbase_*.qm`（负责对话框按钮等 Qt 内置文案），然后发 `changed` 信号；控件在
  `retranslate()` 里重设文本。新增界面时把文本设置都放进 `retranslate()`。
- 新增语言：`pybabel init -i locale/app.pot -d locale -D app -l ja`，翻译后
  `build.ps1 -Task i18n`，`app/i18n.py` 的 `LANGUAGE_NAMES` 加一项 `ja: 日本語`。
  守卫是扫目录的，所以"建了 .po 但没翻完"和"承诺了但没建目录"两种偷懒都会挡住。
- **哪些字面量会被抽走**由 `babel.cfg` 的 `keywords` 决定：`_ _n:1,2 N:1 _bind:2 _switch:1`。
  设置页的文案不是当场翻译，而是存下 msgid 等切语言时再翻（`retranslate()` 重放 `_bound`），
  所以它们藏在 `_bind(w, "打开日志目录")`、`_switch("开机自启", …)` 这类调用的参数里，
  还有 `_radios({"auto": N("跟随系统")})` 这种字典值里 —— 不加这几个关键字，Babel 一个都看不见，
  界面切过去就是空白。`N()` 只负责"让抽取器看见"，原样返回字符串。
- **`name:1,2` 的意思是"第 1 个参数是 msgid，第 2 个是它的复数形式"**，不是"这两个参数都要抽"。
  所以 `_row(title, note)` / `_block_row(title, note, …)` 不能按 `:1,2` 登记：那样 note 会变成
  `msgid_plural`，而 gettext 查普通消息时永远不看复数形式，note 就每种语言都显示中文。这两处的
  标题和说明当场用 `N()` 包起来。
- **中文 msgid 里，汉字与拉丁字母之间才加空格**：`这个程序跑在 Qt 上` 对，`关于 {app}` 错。
  msgid 就是中文文案，`{app}` 填进去是「传书」，两个汉字中间塞空格不符合中文排版；设计图写的
  也是 `关于传书`。英文要的那个空格写在 `en` 的 `msgstr` 里（`About {app}`），msgid 管不着，
  所以去掉空格不会影响其他语言。
- **`.probe/` 之类的点目录不进抽取范围**（`babel.cfg` 的 `[ignore: **/.*/**]`）：草稿脚本里也
  写着中文，漏进来就成了会发出去的假文案。
- **空 `msgstr` 是会漏进产物的 bug，不是回退**：Python 的 gettext 命中空翻译就返回空串，
  不会退回 msgid。所以 `build.ps1 -Task i18n` 在 compile 之前插了 `scripts/i18n_sync.py`：
  zh_CN 的空条目自动镜像 msgid（原文本来就是中文），其他任何语言只要还有空条目或 fuzzy 就
  退出非零，报出 `源文件:行号`。fuzzy 也当错误处理，因为 `pybabel update` 是按相似度猜的，
  Babel 编译时会把猜测当成正经翻译装进 `.mo`——实测它把 `正在发送：{name}` 猜成了
  `外观：{name}`，不加这道闸就发出去了。

## 传输面板（M1）

面板只有两条线程规矩，改之前先照镜子：

- **接收端的决定回调跑在服务线程里**，它等一个 `threading.Event`；GUI 侧把 offer 转成
  信号、弹框、把答案写回去再 set。反过来做（在服务线程里直接弹框）会死锁。
- **发送整个跑在自己的线程里**，逐块用 `QTimer`/信号排队回报进度。

几个坑是实测撞出来的：

- **发送端的 socket 超时必须大于对方的决定窗口**：`offer_wait_timeout_s + 15`。
  接收端会把 `POST /v1/offer` 挂住等用户点"接收/拒绝"，客户端先超时的话，keep-alive
  重试会把同一个 offer 发两遍，对面看到两次询问（`app/net/send.py:_connect`）。
- **广播只带 16 位指纹前缀**，所以 `verify()` 之前名单里的名字都是"未确认"。前缀只能
  挡住"地址填错撞到别人"，真正的信任来自两台屏幕同时显示的一次性配对码（`pair_code_digits`
  位，`pair_code_ttl_s` 秒换一个）；已固定过的 key
  再配对时静默通过，所以配对码只在第一次要。
- **手输地址的设备不进发现表**：发现表按 `peer_expiry_s`（15s）遗忘不再广播的邻居，而
  需要手输的机器本来就不广播。它存在面板自己的 `_manual` 里，加进来时立刻 `verify()`，
  状态栏要求用户核对指纹前缀——地址是你自己输的，只有指纹能证明连对了机器。
- **空文件的分块数是 0**，进度统计必须跳过它，否则进度条会跑到 100% 以上（和
  `PeerConnection._chunk_count` 同一套口径）。
- **`os.path.commonpath` 跨盘会抛 `ValueError`**：一次选中多个不同文件夹下的文件时
  relpath 没有共同基准，直接拒绝并提示分开发，不能压平文件名让两个文件抢同一条路径。
- **接收不是打开窗口就自动开始的**：端口、配对码、二维码都是用户点"开始接收"之后才存在的
  东西，所以按钮文案得在 `start_listening()` 里自己翻成"停止接收"——早先只写在
  `retranslate()` 里，结果只有切语言才对，看上去就是"按了没反应"。反过来，发送与手输地址
  走的是 `verify_peer()`（一次出向请求），本机没在听也照样能发出去。
- **窗口不设写死的最小尺寸**：`setMinimumSize()` 会盖掉布局自己的下限，窗口就能被缩到比某个
  控件还窄，Qt 不再拒绝这个尺寸，而是把控件裁了（西语下"发送给所选设备"要 440px，窗口下限
  写死 1000 时那一列只分到 431）。现在主窗口和设置窗口都不写下限，语言一变下限跟着变。
  三个动作按钮也从两列网格改成一列：最小宽度下每列只有 212px，而法语要 284/260/260。
  `ui_selftest.py` 会把两个窗口都缩到各自的最小尺寸，逐个控件比对 `minimumSizeHint`
  （会换行的标签比 `heightForWidth`），8 种语言各跑一遍。改完布局重跑它，别凭眼睛看一张大图就下结论。

## 窗口外观（无边框 + 托盘）

`settings.json` 里与外观相关的键（全部持久化，`theme` 取 `auto|light|dark`）：

| 键 | 取值 | 作用 |
| --- | --- | --- |
| `theme` | `auto` / `light` / `dark` | `auto` 跟随 Windows `AppsUseLightTheme` |
| `on_close` | `ask` / `tray` / `quit` | 点关闭时问什么；`ask` 每次弹框，勾选"记住我的选择"后写成 `tray`/`quit` |
| `autostart` | bool | 仅记录意图，真实状态以注册表为准 |
| `window` | `{width,height}` | 上次退出的尺寸；旧值比布局下限还小时按下限打开 |

几个实现上的取舍，改动前先看这里：

- **标题栏上没有菜单栏**：七个 `QToolButton` —— `AppButton`(logo)、`LangButton`(globe)、
  `SettingsButton`(gear)、`ThemeButton`(sun/moon)、`MinButton`、`MaxButton`、`CloseButton`。
  前三个各带一个 `QMenu`，
  由 `TitleBar.popup_below()` 在按钮左下角（`button.rect().bottomLeft()` 映射到全局）弹出；
  别改成跟随鼠标位置弹，菜单会漂离按钮。齿轮不带菜单，它发 `settings_requested`，
  由主窗口打开设置窗口（见下一节）。`ThemeButton` 的字形随深浅色翻转，
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

## 设置窗口（`ui/settings_dialog.py`）

标题栏齿轮打开它，第一次点才建、之后复用同一个实例，所以切走的分区还在。非模态：
它开着的时候接收照样能进来（自测里有这条断言）。左侧 `QListWidget` 四个分区，右侧
`QStackedWidget` 对应四页 `QFormLayout`：

| 分区 | 内容 |
| --- | --- |
| 常规 | 设备名、界面语言、外观、开机自启、关闭窗口时 |
| 传输 | 接收目录（浏览/恢复默认/打开）、端口、分块、配对码有效期 |
| 已配对设备 | 固定过 key 的设备名单 + 撤销 |
| 关于 | 版本、Qt/PySide6、契约版本、数据目录（可选中文本）、打开日志目录 |

- **没有"确定/取消"，只有"关闭"**：每个控件改完就写进 `settings.json` 并当场生效。
  一个能让你"取消"的对话框，在端口已经搬走之后就是在谎报两个状态里的某一个。
- **传输页那三个数字只读**：端口、块大小、并行数、配对码长度都来自 `protocol.json`，
  两端拿同一份契约互相校验，在这里改成别的只会配不上对。界面里因此只展示、不编辑，
  并注明"改了就配不上对"。
- **会换行的说明文字要自己报高度**：Qt 算布局最小值时把 `QWordWrap` 标签按一行算，
  整页提示语因此只要 211px 高，拿到 211px 后就把三句话的尾巴剪了，还顺手压扁旁边的单选组。
  解法是 `NOTE_WIDTH = 340` 给这些标签钉住宽度，`_remeasure()` 在每次 `reload()` 后按
  `heightForWidth()` 补上真实高度——宽度已知，高度才算得出来，窗口下限也才诚实。
- **左菜单宽度跟内容走**：`_fit_menu()` 用 `sizeHintForColumn(0)` 定宽，写死 150px 时西语
  "Dispositivos emparejados" 和俄语那行会被省略号吃掉；`QListWidget` 是截断而不是裁切，
  所以光看截图外不一定发现得了。`retranslate()` 里要重算。
- **窗口同样不写 `setMinimumSize()`**：理由和主窗口一样（见"传输面板"那节最后一条），
  实测最小尺寸随语言从 620x393（中文）变到 872x393（英文）。

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

> 防火墙：未签名的 exe 第一次监听时 Windows 一定弹授权框，而这个框点错一次就很难退回来：
> Windows 判定入站时**阻止优先于允许**，只要这个程序名下留着一条阻止规则，之后补多少条允许
> 规则都是废纸，设备在局域网里彻底隐身，比没装还难查。本机实测到的是弹窗点"允许"那一半——
> 系统按 exe 路径写下成对的 UDP+TCP 入站规则，规则名取 exe 文件名（`chuanshu`），配置文件只跟
> 弹窗时生效的那一个网络类别（本机 `Get-NetConnectionProfile` = WLAN/**Public**，所以四条全在
> "公用"）。点"取消"到底留下什么没在这台机器上复现过（要真的拒绝一次系统弹窗才看得到，那是写
> 系统的事），所以 `setup.iss` 不赌答案，装完先 `delete rule name=all dir=in program="<这个 exe>"`
> 把钉在这条路径上的入站规则清空，再 `add rule` 写自己的——阻止也好、系统自建也罢，结果都一样，
> 且过滤条件是求交集的，绝不碰用户给别的程序加的规则。三个配置文件全放（`profile=any`）而不再只放
> 专用+域，边界交给 `remoteip=LocalSubnet` 守：手机开热点时这张网卡就是"公用"，只放专用/域的规则
> 在传书最主要的使用场景里根本不生效。端口也不钉死在 43720，协议允许它在被占用时回退临时端口。
> 这条 `firewall` 任务现在**默认勾选**（不勾的后果是功能静默失效，勾上的代价只有一次 UAC，
> 拒掉也不影响安装成功），但只弹一次：两条命令用 `cmd.exe /c "netsh … & netsh …"` 合进同一次提权。
> 卸载按 `name=all dir=in program=<安装路径>` 删，连当初系统弹窗自建的那对也一并清掉，不留僵尸条目。
> `[Code]` 段里注释只能用 `//`：分号在 Pascal Script 里是语句分隔符，写 `;` 注释编译期就报
> `'BEGIN' expected`。

已在本机验证（Inno Setup 7.1.0）：`-Task installer` 编译通过，产出 35MB 安装包，
`/PORTABLE=1 /SILENT /DIR=...` 便携安装后 exe 正常启动、翻译与日志路径均正确。
上面两条 netsh 命令的**参数解析**过了：非提权状态下 netsh 是先解析参数再报"请求的操作需要提升"，
`cmd` 的 `&` 串联也确实发出两次调用，探针跑完 `name=chuanshu` 的规则数还是原来的 4 条，什么都没写进去。

`firewall` 任务已经真装过一次（用户手动双击，装到 `D:\Program Files\ChuanShu`），只读核对结果：
`name=ChuanShu` 的规则**只有 1 条**、方向入、配置文件"域,专用,公用"、远程 IP `LocalSubnet`、
程序路径就是安装的那个 exe，操作允许；全机也没有任何与它同路径的阻止规则。运行中的实例确实
owns 三个监听口（`netstat`：TCP 43720、UDP 43721、每个网卡各一个 UDP 5353），应用日志
`discovery started (channels: {'mdns': 'ok', 'udp': 'ok'})`。入站能不能真进来，用 WSL 的另一个网络
命名空间做过一次跨命名空间连接：从 `172.27.80.195` 连本机 `172.27.80.1:43720` 握手成功，
应用日志同一时刻记下 `connection from ('172.27.80.195', 52048) ended early`——连接穿过 WFP 落到了
安装版的 accept 上，不是本机回环。**仍未做**的两件事：同一次安装里"先删后加"那条分支没被触发过
（全新路径本来就没有旧规则可删，要第二次覆盖安装才算），以及真正的同网段实物对端。

界面这层的验证分三条路，各自能证明的东西不同：

- **`scripts/ui_selftest.py`：进程内跑完整传输 + 设置窗口**（`QT_QPA_PLATFORM=offscreen`，
  132 条断言，`windows` 平台同样 132 条全过）。
  它把 `APPDATA`/`XDG_DATA_HOME` 指到临时目录**再** import `app.*`，所以自测用的是自己的
  身份、自己的已配对表和自己的接收目录，碰不到真实那套。覆盖：打开时不监听（没端口、没二维码、
  按钮写着"开始接收"）→ 点一下才有端口/二维码/配对码且按钮翻成"停止接收"→ 再点回去三样都收走、
  真 `PeerConnection` 推进来的 offer 弹框（标题、文件名、保存路径、点的按钮）、拒绝路径拿到
  `DECLINED`、选中文件→点发送→输配对码→对面落盘逐字节一致、陌生设备要码而熟人不再问、
  手输地址连一个从不广播的机器（含地址填错要报错、不留半行）、切语言、退出释放端口。
  设置窗口那半段：齿轮点开出的是同一个实例、开着时接收服务没被关掉、四个菜单行各显示自己那页、
  传输页逐字引用契约里的数字、在这里改的名字传到面板上也跟着变、接收目录换了端口不重开、
  "恢复默认"指回应用目录、外观和关闭行为单选生效、撤销设备后 key 从名单里消失、
  切语言把设置窗口自己也翻了、重新打开还在原来那页。
  最后 `phase_settings_fit` 把主窗口和设置窗口都 `resize(minimumSize())`，逐个可见控件比对
  `minimumSizeHint()`（会换行的比 `heightForWidth()`），再检查左菜单没有一行被省略号截断，
  8 种语言各跑一轮，每页在最小尺寸下存一张截图。
  三条写死在代码里的规矩：模态 `exec()` 是在 GUI 线程上跑嵌套事件循环，测试自己就是那条线程，
  所以**只能在 `QTimer` 里跟弹框打交道**（`AutoDialog`）；截图要真字形就换
  `windows` 平台用 `QWidget.grab()`，offscreen 没有 CJK 回退，拍出来是一屏豆腐块；
  **offscreen 量出来的布局最小尺寸是假的**（字体度量不准，同一页它报 149x36，`windows` 下
  实际 534x307），所以布局结论必须用 `windows` 平台复核一遍，两个平台都跑才算数。
- **进程内驱动真实窗口**（`windows` 平台 + `QTimer` 依次点按钮）：无边框标志、
  七个图标按钮都有非空 `QIcon` 且各 4 个尺寸、`popup_below()` 弹出的菜单位置与按钮
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
- **`scripts/freeze_smoke.py`：起真正的打包产物**。上面两条都在源码进程里跑，证不了冻结环境
  才会坏的部分（`sys._MEIPASS` 下的资源查找、`cryptography` 的 `_rust.pyd`、QtSvg 插件、
  `protocol/` 与 `.mo` 有没有收进去）。它启动 exe、等窗口、截图、扫日志里的 ERROR，
  然后只结束自己起的那个进程。实测结论：`qrcode` 不用加 hiddenimport（`from qrcode.image.svg
  import SvgPathImage` 是显式导入，`warn-app.txt` 里 `missing module PIL/png/lxml` 那几条来自
  qrcode 自己的可选后端，我们这条路径不会 import），`_rust.pyd`、`protocol/protocol.json`、
  两个 `.mo`、`assets/icons/` 都在 `_internal` 里，冻结版能画二维码、能绑 43720、两条发现通道都 ok。

## 需要改的地方

- `app/meta.py`：应用名、版本、发布者（安装包名、开始菜单、卸载项都跟着变）
- `app/ui/transfer.py`：传输面板就是主窗口的正文（`main_window._build_body` 只放它）；
  界面上写出来的每一句承诺都要有对应的入口，别留"可以扫码"这种做不到的话
- `app/ui/theme.py` 的 `LIGHT` / `DARK`：换配色只改这两处，QSS 与图标颜色自动跟着变
- 换/加图标：把 SVG 丢进 `assets/icons/`，在 `icons.json` 的 `glyphs` 里起个名字，再改
  `buttons` 里对应角色的映射（要按主题或最大化状态换字形就用 `{"default":..,"dark":..}` 变体写法）；
  `icon_sizes` 覆盖某个按钮的图标尺寸，`pixmap_sizes` 是每个 QIcon 打包的尺寸
- 打包时 `assets/icons/` 必须进 `_internal`：`app.spec` 用 `paths.icons_dir()` 同一套相对路径收集，
  漏了的话窗口在启动构造标题栏时就抛 `IconConfigError`（这是故意的：配置缺失不该静默降级）
- `app/ui/tray.py` 的 `context_menu`：别改名回 `menu`，那会盖掉 `QSystemTrayIcon.menu()`
- 若要便携单文件 exe：把 `app.spec` 的 `EXE(...)` 改成 onefile（去掉 `COLLECT`，
  把 `a.binaries, a.datas` 直接传给 `EXE`）
