# 传书 ChuanShu — PC 端（PySide6 桌面客户端）

局域网文件互传的桌面端：对等协议（既能发也能收）、Ed25519 身份密钥签名 + RSA-2048 服务叶 + SPKI 指纹固定、
断点续传。主窗口就是传输面板（我的设备 + 配对码/二维码 + 附近设备 + 发送进度），
外面套国际化（gettext）、日志与异常捕获、PyInstaller 打包、Inno Setup 安装包这条链路。

各端（Windows/Linux × GUI/CLI、Android、鸿蒙、浏览器）能做到哪一步、每条结论是哪一档证据给的、
还欠什么，看 [docs/feature-matrix.md](docs/feature-matrix.md)。这份 README 讲实现与出包，那份讲范围与验收状态。

## 仓库与分支

| | 位置 | 内容 |
|---|---|---|
| PC 端 | 本仓库根目录（仓库名按 `chuanshu-pc` 起的，但**还没配任何 remote**，两个端都在这一个工作树里） | PySide6 桌面端，Windows 已出包；Linux 是第二个目标平台：headless 半边（路径、身份权限、自启、端口、双向传输）与冻结产物都在 WSL 实测过，GUI 那条也拉到 WSLg 真显示上拍过（见"Linux 侧"）；macOS 未排期 |
| 手机端 | `mobile/` | uni-app x，出 Android 与鸿蒙两个平台。iOS 2026-10-24 起终止：没有 Mac 就没法出可签名的包，`app-ios` 那两半边代码留在树里不再推进 |
| 协议契约 | `protocol/` 与 `mobile/shared/protocol/` | `protocol.json` 是唯一真相源，手机端那份是 vendored 副本，带来源摘要戳，由 `mobile/scripts/check_protocol.py` 守着 |

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
  config.py          settings.json 读写，目录由 paths.user_data_dir() 给（Windows %APPDATA%、Linux $XDG_DATA_HOME）
  i18n.py            Qt-free gettext 核心：_()/_n()/N()、current()/available()/resolve()/use()
  logging_setup.py   滚动日志，在数据目录下的 logs/app.log
  crash.py           全局异常捕获 + SafeApplication（Qt 槽函数异常不退出）
  autostart.py       开机自启：Windows 写 HKCU ...\CurrentVersion\Run，Linux 写 ~/.config/autostart/<名>.desktop，两边都只在打包后可用
  icons.py           读取 assets/icons/icons.json → QIcon/QPixmap（按角色取字形与尺寸，带缓存）
  main.py            GUI 入口
  cli.py             命令行入口（`python -m app.cli`）：self/receive/send/peers/pins/firewall/unpair/
                     pair-code，整条链路不 import PySide6，见"命令行（headless）"
  ui/main_window.py  主窗口：无边框外壳、托盘、关闭询问、主题切换、retranslate()
  ui/language_manager.py  切语言的 Qt 半边：QTranslator + changed 信号，翻译核心在 app/i18n.py
  ui/settings_dialog.py 设置窗口：左侧四个分区、右侧设置项，非模态，每个控件改完即生效
  ui/title_bar.py    自绘标题栏：七个图标按钮 + popup_below()、拖动/缩放/最大化、边缘缩放 eventFilter
  ui/theme.py        深浅两套 Palette 与由它生成的 QSS
  ui/transfer.py     传输面板：接收开关、配对码+二维码、设备名单（含手输地址）、暂存与发送、
                     来件确认弹框、本机卡的"入站"结论；所有线程回调都转成 Qt 信号再上 GUI
  ui/tray.py         系统托盘菜单（打开主界面 / 开机自启 / 退出）；`available()` 说这台桌面有没有托盘
app/net/
  spec.py            读取 protocol/protocol.json：端点、错误码→HTTP、二维码字段顺序
  identity.py        Ed25519 身份密钥（签配对）+ 首次运行签发的 RSA-2048 服务叶（TLS 递出去的就是它）；
                     两个摘要各管各的，SPKI 指纹固定、已配对设备表（identity/ 目录，POSIX 上这几个文件 0600）；
                     写盘前与文件做三方合并，窗口和命令行共用一个目录时不会互相抹掉固定
  receive.py         接收端 HTTPS 服务：配对、offer、分块落盘、路径清洗、崩溃后认领未完成 offer
  send.py            发送端：plan→offer→分块→finalize，token 失效时用已信任的 key 静默重配对
  discovery.py       局域网发现：mDNS 注册/浏览 + UDP 广播 43721；广播只带**服务叶**的指纹前缀，
                     完整摘要必须经 verify() 从 /v1/hello 取回（取 `served`，老对端只有 `fingerprint`）；
                     每条通道可用与否单独上报
  errors.py          错误码的中文 msgid 字面量（给 pybabel 抽取用），与 protocol.json 必须一致
  firewall.py        只读地问平台防火墙"这台机器放不放对端连进来"：Windows 按程序路径问 netsh，
                     Linux 按端口问 firewalld/ufw；结论只有 open/no_allow/blocked/unknown 四个。
                     窗口和终端都读它，所以两边不会把同一条规则叫成两个名字；它自己从不写规则
protocol/
  protocol.json      机器可读契约：端口、chunk_size、端点清单、错误码表、限制值
  spec.md            语义与理由：为什么这么定，两端必须一致实现什么
scripts/
  protocol_selftest.py  M0 验收：配对→多文件含目录→杀进程重启→续传→finalize→两条发现通道，
                        72 处断言、跑下来 78 条（报告写在 .probe/protocol_report.txt）
  ui_selftest.py        M1 验收：驱动真实窗口，203 处断言、跑下来 403 条（部分按 8 种语言重复；
                        含设置窗口、缩到最小尺寸不裁切、没有托盘的桌面不承诺托盘、入站那句防火墙结论）。见"界面这层的验证"
  cli_selftest.py       命令行验收（Windows 这台）：起几个 CLI 进程（各自一个身份目录）互配、双向传
                        3MB 并逐字节对 sha256；第四条腿专测**粘整串 chuanshu://**——串里本来就带着配对码
                        与密码，命令里不再输 --code 也该走得通，配套的还有"裸 host 不含任何秘密"那条反例；
                        顺带断言 import app.cli 不带进 Qt；再加一节 firewall：真跑一次 `firewall`
                        对得上退出码，并用备好的 netsh/firewalld/ufw 输出把四个结论、两个平台的放行命令
                        都验一遍，38 处
  linux_selftest.py     命令行验收（Linux 那台，WSL 里跑）：XDG 路径、身份文件 0600 与旧私钥回收、
                        XDG 自启写读删、端口被占改用临时端口、双向传、没装 zeroconf 时 mDNS 通道
                        自己报 unavailable、--lang、这台机器上 firewalld/ufw 都没有时 `firewall` 报
                        unknown（不是"没问题"），27 处。见"Linux 侧"
  freeze_smoke.py       起打包好的产物：先跑 `*-cli.exe` 那四条腿（读契约＋首跑铸码、--lang、真绑一个
                        端口并说出入站、`firewall` 的结论与退出码互相咬合），再起窗口 exe、等窗口、
                        向那个句柄要它自己的像素（`PrintWindow`，不是拍屏幕一块区域）、点一下导航栏
                        换到「接收」页、在像素里数二维码的定位图案，然后查日志有无 ERROR，
                        最后只结束自己起的进程（系统弹的防火墙框留给用户答）
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
app.spec             PyInstaller 配置（one-folder，一个 COLLECT 两个入口，捆绑 locale + assets/icons + protocol）
build.ps1            i18n / exe / installer 流水线（Windows）
build-linux.sh       同样三步的 Linux 版：i18n → PyInstaller → tar.gz
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
- 切语言时 `ui/language_manager.py` 的 `set_language()` 先调 `app.i18n.use()` 换掉 gettext 目录，
  再装上 Qt 自带的 `qtbase_*.qm`（负责对话框按钮等 Qt 内置文案），然后发 `changed` 信号；控件在
  `retranslate()` 里重设文本。新增界面时把文本设置都放进 `retranslate()`。
- **`app/i18n.py` 不 import PySide6**：语言核心（`_`、`_n`、`N`、`current`、`available`、`resolve`、
  `use`）是纯 gettext，QTranslator 与 `changed` 信号那一半单独住在 `ui/language_manager.py`。
  这样 `app/net/errors.py` 的错误码标签和命令行都能翻译，而不把 Qt 拖进 headless 路径。
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
- **一台设备两个指纹**：`served_fingerprint` 是套接字递出来的那张 RSA-2048 叶，`fingerprint` 是签配对
  请求的 Ed25519 身份密钥。凡是描述"这条连接"的数（二维码的 `f=`、广播前缀、TLS 钉子、hello 的 `served`）
  用前者，凡是描述"这台机器"的数（hello 与配对应答的 `fingerprint`、`trusted.json` 的键）用后者；
  `is_trusted()` 认这两个数中的任意一个，`unpair` 也按任意一个的前缀找。为什么非要分开：没有任何平台的
  TLS 栈愿意把 Ed25519 当叶证书使——鸿蒙签不出来（#47），Android 的 Conscrypt 压根不广告 ed25519、
  android.jar 34 的 `SSLParameters` 也没有 setter 能加上，同一个端口换张叶就握手成功（#106 实测）。
  代价是**换了服务叶的设备，对端旧钉子不再匹配**，已经配过对的得重新配一次。
- **广播只带 16 位指纹前缀**（前缀是服务叶的），所以 `verify()` 之前名单里的名字都是"未确认"。前缀只能
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

## 命令行（headless）

`py -m app.cli <子命令>`，走的是 GUI 底下同一套 `app/net/`，整条链路不 import PySide6：

```
self        我是谁（配对指纹=套接字那张叶，身份指纹=签配对那把钥匙）、固定过谁、身份/数据/接收目录在哪
receive     开接收（--yes 不问直接收，--root 换目录，--seconds 收一阵自己退，--port 换端口）
send        发文件（粘整串 chuanshu:// 就够了——配对码与密码本来就在串里；只给 host[:端口] 时第一次要 --code/--secret）
peers       广播自己并听邻居（mDNS + UDP 都听；--no-verify 只列前缀）
pins        列已固定的指纹
firewall    问这台机器的防火墙放不放对端连进来（只读；退出码就是结论，见下）
unpair      忘掉一台（前缀唯一即可）      pair-code  看/换（--rotate）配对码与密码
```

四个决定写在这里，改之前先读：

- **`receive` 的来件询问是问在终端里的，但它自己有闹钟**：`ReceiveService.handler` 同步跑在服务
  线程上、手里还捏着对方的 socket（见"传输面板"第一条）。GUI 把那一步转成信号 + 弹框；命令行没有
  事件循环，所以另起一条守护线程读 stdin、把每一行丢进队列，服务线程只等 `offer_wait_timeout_s - 5`
  秒。到点没人回答就把这单按拒绝回执并说出"55 秒内没有人回答，这单先拒了"——对方到 60 秒自己就断，
  再多占那条 socket 只是让我们的终端替对方等；#84 给弹框修的是同一件事，命令行不能只把秒数写在提示
  里。stdin 那头没人（重定向、脚本里跑）会立刻读到 EOF，同样按拒绝处理并提示改用 `--yes`，但那是另一
  句话：一个"没人打字"，一个"根本没人在打字"。键盘前坐着真人时，每次开问前先把队列里剩下的行丢掉，
  上一条慢了一拍的回车不能替下一条作答；管道里预先喂进来的那一行不算"慢了一拍"——`printf '\n' |` 就是
  打算回答下一单的，那是 `--yes` 之外唯一还能自动收的写法，所以只有 tty 才丢。丢的时候不能连"stdin 已经
  见底"那个哨兵一起丢：Windows 上重定向到 null 的 stdin 也自称 tty，哨兵被抹掉就把"立刻拒"拖成等满 55 秒。
- **命令行提示词不翻**：整个 `cli.py` 里没有 `_()`，所以 `pybabel extract` 抽不到它，7 份目录不必跟着
  长一遍。唯一走目录的是错误码标签——`send` 失败时打印的 `errors.describe(code)` 和 GUI 标红的是同一句
  话，但它只在 `--lang`（或窗口里固定过某个语言）时换，所以"自动"在命令行这边等于中文，不去跟系统 locale：
  跟着 locale 走就会出现一句德语错误夹在一串中文里。退出码分得开：`0` 发完了，`1` 传坏了，`2` 是没配对码
  ——脚本看见 `2` 知道这单要人来输码，看见 `1` 才需要去翻日志。`-q` 只留结果行（对端、发完了、每文件的
  校验与摘要前缀），进度行在非 tty 时本来就不打。
- **粘进来的整串里就带着配对码与密码，但只有命令行肯替你把它们用上**：`send` 拿到 `chuanshu://p?…&c=…&k=…`
  时，缺的 `--code`/`--secret` 从串里补（`spec.pairing_secrets`，显式给的两个 flag 永远赢）。窗口那边故意
  不这么做——`verify_address()` 只从串里取地址与 `f=` 前缀，六个数字仍然要人当场打，因为那张卡片就是
  spec §3 说的那次带外确认；终端前没有"同屏看一眼"这回事，脚本要么给 flag，要么给整串。两种 face 的差别
  写在这儿，别把它"统一"成一边。
- **Windows 查不出端口被占，只能问出来**：`ThreadingHTTPServer` 带 `SO_REUSEADDR`，而 Windows 允许
  第二个进程 bind 一个已经有人在听的端口——两边都打印 `监听：43720`，真正应答的只有先绑上那个，
  于是给"第二个接收端"的文件全发进了第一个。`_serve()` 因此在 bind 前往 127.0.0.1 打一发 `/v1/hello`
  （`listener_on()`），有人应答就改用临时端口并把占着的那台名字说出来。POSIX 上 bind 确实会直接
  `EADDRINUSE`，但 WSL 实测两个 CLI 进程、以及一个只 accept 不回话的野 socket，都在 bind 之前就被
  `listener_on()` 认出来了（后者报 `不是传书`），所以那个 except 分支守的是探测与 bind 之间的竞态，
  不是 Linux 的日常路径。

`firewall` 这条命令回答的是**这台机器**放不放人进来，不是传书自己在不在听——这两件事以前只有第 2 条
能说，第 1 条永远沉默，于是"我听得见但没人进得来"这种状态谁都不知道。事实只有一个来源
`app/net/firewall.py`，窗口和终端都读它（`WORDS`/`word()`/`on_off()`/`fix_commands()` 也在里面，所以
两个 face 不会把同一条规则叫成两个名字）：

- **按系统各自适配**：Windows 的规则钉在**程序路径**上，所以问的是"正在跑的这一个 exe"——本机实测
  `ChuanShu.exe` 是放行，而 `ChuanShu-cli.exe` 名下压两条"公用"阻止规则、判 blocked，这正是因为规则
  按路径而非按名字匹配；Linux 的规则按**端口**写，所以问的是协议端口，`firewall-cmd --query-port` 或
  `ufw status` 里那行 `ALLOW IN`。
- **四个结论，各给一个退出码**：`open`→0、`unknown`→1、`no_allow`→2、`blocked`→3。脚本按数字分支，
  不用去 parse 中文句子；"读不到"单独是一个码，不会被当成"没问题"。
- **只读**：写规则要提权，那是安装器或用户双击装的事（见"安装包"），传书不在跑着的时候改自己机器的
  防火墙。它给结论 + `fix_commands()` 那几条命令让你自己提权跑：Windows 是先清这个路径的入站规则、
  再写一条 `profile=any remoteip=LocalSubnet`（不钉端口，理由见安装器那段注释），Linux 是按端口加。
- **两个 face 都在开始监听那一刻自己说**：窗口那边是本机卡多一行"入站"（`chuanshu-firewall`
  线程 + 信号回 GUI，`netsh` 那几百毫秒不占服务线程），四种状态各有一句话，鼠标停在上面能读到全部原始
  事实和那几条命令；停止监听就把结论丢掉——它说的是一扇已经关上的门。配对码 5 秒刷新那次重绘不会把它抹掉。
  终端那边不用另跑一条命令：`receive` 的横幅里就多一行"入站：…"，因为"监听：43720"单独摆在那儿会被
  读成"连得进来"，而那恰恰是它证明不了的事。

`scripts/cli_selftest.py` 是这条链路的验收：两个 CLI 进程（各自一个 APPDATA 身份目录）互配、双向传
3MB、逐字节对 sha256、再查 `pins`/`self`/`peers`，并断言 `import app.cli` 不带进 Qt。第二条腿固定用
43912 而不是契约端口，因为第一条腿那个进程还在 43720 上听——这正是 `listener_on()` 要挡的那件事。
最后那节 `firewall_checks` 先真跑一次 `firewall`（这台机器的 netsh 答的，结论与退出码必须互相对得上），
再用备好的 netsh/firewalld/ufw 输出把四个结论和两个平台的 `fix_commands()` 都验一遍——一台机器配好了
证明不了另一台的配置，而"读的东西里没有任何一条在写规则"本身也是一条断言。第一条腿的横幅也断言了那行
"入站："。
Linux 那半边是 `scripts/linux_selftest.py`，在 WSL Ubuntu-24.04（Python 3.12，没装 PySide6）里跑，
scratch `HOME`/`XDG_*` 指到 `/tmp`，27 条全绿。

冻结产物里命令行是**第二个 exe**（`ChuanShu-cli.exe` / `ChuanShu-cli`），不是给窗口那条加开关：
`console=False` 的窗口进程根本没有 stdout 可写，`ChuanShu.exe self` 打不出任何东西。两条命令台共用
`app.spec` 里那一个 `COLLECT`，两份 `Analysis` 的 `binaries`/`datas` 按文件名合并（`_merge()`，先到先留），
所以 CLI 那份 Qt-free 的分析不会往包里再塞一套 Qt；`a_cli` 显式 `excludes=["PySide6"]`，将来谁在
`app/cli.py` 里不小心 import 了 Qt，出包当场就断，而不是悄悄带回 60MB。

冻结版有个源码没有的行为：Windows 上它**按控制台代码页输出**（本机 cp936），`PYTHONIOENCODING` 和
`PYTHONUTF8` 都不起作用——bootloader 自己配置解释器，PEP 587 那条读环境变量的路没走。管道进
PowerShell 5.1 反而是对的（它按同一套代码页解码），要给 UTF-8 的消费者就读 `chcp 65001` 之后的输出，
或者跑源码版加 `-X utf8`。自测脚本里那个 `decode()` 先 utf-8 再 gbk 就是这个原因。

另外 `_identity()` 现在替 `self`/`pair-code` 先把配对码铸出来：一台全新机器上只跑命令行、从没开过窗口，
之前会印出两行空的"配对码："，而窗口里有码——同一份承诺不能一个 face 兑现、另一个 face 落空。

两个 face 共用同一个身份目录，所以 `trusted.json` 会被两个进程各读一次各写一遍：以前谁后写就把对方刚
固定的对端从文件里抹掉（自己内存里还留着，下次再写又抹回来），撤销的那台也会被对方下一次无关的写入救活。
现在 `save_trusted()` 先重读文件、跟"上次看到的磁盘快照"做三方合并再写，读路径（`is_trusted`、
`pinned_fingerprints`、`same_peer`…）也先 `sync_trusted()`，所以窗口开着时命令行固定/撤销的设备能立刻看到。
`pairing.json` 同理：谁轮换谁写文件，另一边显示时重读，否则屏幕上会留一个已经配不上的码。

## 窗口外观（无边框 + 托盘）

`settings.json` 里与外观相关的键（全部持久化，`theme` 取 `auto|light|dark`）：

| 键 | 取值 | 作用 |
| --- | --- | --- |
| `theme` | `auto` / `light` / `dark` | `auto` 跟随系统：Windows 读 `AppsUseLightTheme`，其余平台读 Qt 的 `styleHints().colorScheme()` |
| `on_close` | `ask` / `tray` / `quit` | 点关闭时问什么；`ask` 每次弹框，勾选"记住我的选择"后写成 `tray`/`quit`。这台桌面没有托盘时 `tray` 这一项根本不出现在下拉里 |
| `autostart` | bool | 仅记录意图，真实状态以注册表值 / `~/.config/autostart` 那个文件为准 |
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
  DWMWCP_ROUND=2)`，build < 22000 直接 no-op（无边框窗口在 Win10 上是直角），Linux 上也是 no-op——
  窗口管理器给不给圆角不由这里决定。`ctypes.wintypes` 在 Linux 上 import 就炸，所以这个模块不 import
  它，`ctypes.windll` 也只在这个函数里出现。
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
  False，托盘复选框自动回弹并弹通知说明原因。Windows 写 HKCU 的 Run 值，Linux 按 XDG 写
  `~/.config/autostart/ChuanShu.desktop`——文件存在就是开启，所以"关闭"是删掉它，读回时还要
  比对 `Exec=` 是不是现在这个可执行文件，搬家后的旧条目不算已注册。
- **没有托盘的桌面不许承诺托盘**：`ui/tray.py::available()` 就是 `QSystemTrayIcon.isSystemTrayAvailable()`，
  在 `QT_QPA_PLATFORM=offscreen` 和没有 StatusNotifier 宿主的 GNOME 上都是 False。所有依赖它的东西
  一起降级——设置里"关闭窗口时"少了 `tray` 这一项（存过的 `tray` 会退回显示成"每次询问"，因为
  `findData` 找不到就取 0）、`Ctrl+H` 变灰、`hide_to_tray()` 直接不隐藏、关闭询问改成"关闭窗口就是退出
  程序"。把窗口藏进一个不存在的托盘，等于把一个还在收文件的面板弄丢。

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

## Linux 侧

PC 端现在是两个产物：Windows（已出包）与 Linux（目标）。命令行两边共用同一套 `app/net/`，
差异全在"贴系统的那一层"，一处一个分支，没有 `if linux` 散落各处：

| 差异 | Windows | Linux |
| --- | --- | --- |
| 数据目录 | `%APPDATA%\ORG\APP` | `$XDG_DATA_HOME`（缺则 `~/.local/share`）`/ORG/APP`，见 `paths.user_data_dir()` |
| 身份文件权限 | 跟随 ACL 继承 | `identity/` 下每个文件 0600：`_atomic()` 用 `os.open(...,0o600)` 建临时文件再 rename；`load_or_create()` 读到旧的 0644 私钥当场 `chmod` 回来并写日志 |
| 开机自启 | HKCU `...\CurrentVersion\Run` | `$XDG_CONFIG_HOME/autostart/ChuanShu.desktop` |
| 主题 `auto` | 读 `AppsUseLightTheme` | 读 `styleHints().colorScheme()`（`theme.system_prefers_dark()`） |
| 托盘 | 总是有 | `QSystemTrayIcon.isSystemTrayAvailable()` 可能为 False，界面整体降级（见上一节最后一条） |
| 窗口圆角 | Win11 DWM 属性 | no-op；`ctypes.wintypes` 不 import，`apply_rounded_corners()` 第一行就返回 |
| 端口被占 | bind 不报错，只能探测 | bind 报 `EADDRINUSE`，但实测同样是探测先认出来 |

**测到了什么层级**：`scripts/linux_selftest.py` 在 WSL Ubuntu-24.04（Python 3.12.3、
cryptography 41.0.7、**没有 PySide6、没有 zeroconf**）跑，scratch `HOME`/`XDG_*` 指到 `/tmp`，
27 条断言全绿。这一台恰好把两件事变成了实证而不是推理：`import app.cli` 不带 Qt 是因为这里
根本装不了 Qt；mDNS 通道报 `unavailable`、UDP 广播 `ok`，正是 `discovery.py` 那条"每条通道单独
上报"的分支；`firewall-cmd` 与 `ufw` 这里**两个都没装**（`command -v` 都是空），所以 `firewall`
落到 `unknown`/退出码 1，而不是替用户说一句"放行着"。GUI 那半边（主题自动、无边框外壳、无托盘降级）过了
`ui_selftest.py` 的 offscreen 路径——offscreen 在 Windows 上就是"没有托盘"，所以降级逻辑被真跑了一遍——
但字体度量与合成器行为在 offscreen 上证明不了（见"界面这层的验证"第一条），所以冻结产物又被拉到 WSLg 的
**真显示**上跑了一遍（下一段）：那才是导轨宽度这类几何结论的来源。

**真跑过 PyInstaller 的那半边**（#105）：`./build-linux.sh` 在 WSL Ubuntu-24.04 里出了六次产物，
最后一次（#139，#137 那一条之后）就是仓库里那个 `dist/ChuanShu-0.1.0-linux-x64.tar.gz`
（70,088,524 字节，一个目录两个可执行）。
在这之前还有一次纯脚本层的实跑（`.probe/linux_build_probe.sh`，一次性探针，不进仓库）：把 `-m PyInstaller`
与翻译三步换成桩，其余照原样，于是 `--exe-only` 那条分支（真构建没走它）与"解压回来还在 +x"是那次拿到的结论。
装的东西：`python3-venv`/`python3-pip`、PySide6 6.12.0 跑起来要的 Qt 运行库（`libxcb-*`、`libxkbcommon`
那一串）、`fonts-noto-cjk`（没有它截出来是一屏豆腐块）、`xdotool`+`maim`（拍窗口用）。PySide6 6.12.0
与 PyInstaller 6.22.3 装在 `~/.venvs/cs`，**构建目录在 ext4（`~/csbuild`）而不是 `/mnt/e`**：往 9p 挂载上
写 one-folder 会挂在收集那一步。产物怎么验的看 `.probe/linux_smoke.sh`——它是 `freeze_smoke.py` 的 Linux
对应物：解压到临时目录、`XDG_*` 指到 scratch（绝不碰真的身份），跑冻结 CLI 的四条腿（`self`、
`self --lang en`、`receive` 真起 43917 且横幅把端口和入站那半句都说出来了、`firewall` 的结论与退出码对得上），
然后**在 WSLg 的真显示上把冻结的窗口拉起来**，`xdotool` 按 pid 找到窗口、`maim` 拍下来、再读它自己的
`app.log`：10 条腿全绿，窗口 1080x761，日志无 ERROR/Traceback。导轨那一下点击要按两次才换页——第一次
按下被吞（鼠标移动到了、那一行亮起、页面还停在「传输」），换页发生在第二下；`windowfocus`、
`windowactivate --sync`、`mousedown`/`mouseup` 之间留 0.25 秒，四种办法都试过，都还吞第一下，所以那条腿
改成按两次并在日志里说清是哪一拍出的图，而不是假装一拍就够。真桌面证明掉的是 offscreen 永远证明不了的那类：
字体度量（同一个 12px，`advance("DESKTOP-58TSA70")` offscreen 180 / 真机 113，左导轨的宽度就是按它算的）、
四个页面各自真渲染一遍长什么样、以及 #87 那行入站结论在桌面降级下说的是人话（这台机器没 firewalld 也没 ufw，
所以窗口上那句是"读不到，所以不构成保证"）。**仍然没跑的**：Wayland 下 `startSystemMove()` 能不能拖动无边框窗口
（WSLg 给的是 X11 转发，这条要真 Wayland 会话）、X11 边缘缩放、托盘在桌面环境里到底有没有（AppIndicator），
以及 AppImage / deb 这个投递形式还没定——脚本只承诺 tar.gz。装着火墙的那台答出来什么，仍只对着备好的
`firewall-cmd`/`ufw` 文本验过，在 `cli_selftest.py` 的 `firewall_checks` 里。

## 打包

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File build.ps1 -Task all
```

1. `pybabel extract/update/compile` → `locale/**.mo`
2. `pyinstaller app.spec` → `dist\ChuanShu\ChuanShu.exe` **加** `ChuanShu-cli.exe`（one-folder，启动快、
   好排查；一个 `COLLECT` 里两个入口，Inno 的 `recursesubdirs` 自动把第二个一起收）
3. `ISCC installer\setup.iss` → `dist\installer\ChuanShu-Setup-0.1.0-x64.exe`

`dist\` 里现成那两套（Windows 的 `ChuanShu\` + 安装包、Linux 的 tar.gz）出在 #139，也就是「那一问也没人答时
一次都不重写」（#137）之后——出这一批时本机没有正在跑的实例，所以直接出在正式 `dist\` 上，`freeze_smoke.py`
与 `.probe/linux_smoke.sh` 各复验了一遍；再往前是 #131（「分块体落对了但回复没来，先问一次 `state`」那两条
#120 #130），上一次是 #117 #118。出包这件事历史上连着一个动作
要做：#106 #109 #115 把 TLS 叶换成独立签发的那张以后，**存量那枚钉子对不上**——老包把这台机器的*身份*摘要
当成了 TLS 叶记下来，新包递出来的是另一张叶，所以对端在握手那一步就停住了——`/v1/pair` 都到不了（#115 量过
这个形状：把串里的 `f=` 改掉一个字符，钉不住的那一侧在配对之前就拒）。修它的动作是**重新扫一次码或重粘一份
配对串**（串里带的就是现在的叶摘要），光输配对码不够。那一轮重来已经过去了：现在这两个包与现在这份串是同一
张叶，出包不再附带"已经配过对的那几台得重来一次"。

Linux 那一侧重复同样的三步，只是产物是 tar.gz：`./build-linux.sh`（`--exe-only` 只出可执行文件不打包，
`PY=python3.12` 换解释器）。它需要 `requirements.txt` + `requirements-dev.txt` 都装上。这条在 WSL 里真跑出过
产物，`.probe/linux_build_real.sh` 是那次的输入（先把仓库从 `/mnt/e` 拷到 ext4，再用带 PySide6+PyInstaller 的
venv 跑），跑法与产物见"Linux 侧"最后一段。

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
> 拒掉也不影响安装成功），但只弹一次：所有命令用 `cmd.exe /c "netsh … & netsh …"` 合进同一次提权。
> **两个 exe 各写一对**——规则按程序路径匹配，`ChuanShu.exe` 放行了不等于 `ChuanShu-cli.exe` 放行了，
> 而命令行是冻结产物里的第二个入口；实测过漏掉它的那台机器：窗口能收，`ChuanShu-cli.exe receive` 在听、
> 局域网对面零回应。卸载按 `name=all dir=in program=<安装路径>` 删两个路径，连当初系统弹窗自建的那对
> 也一并清掉，不留僵尸条目。
> `[Code]` 段里注释只能用 `//`：分号在 Pascal Script 里是语句分隔符，写 `;` 注释编译期就报
> `'BEGIN' expected`。

已在本机验证（Inno Setup 7.1.0）：`-Task installer` 编译通过，产出 41MB 安装包（`dist\ChuanShu\` 是
139MB 的 one-folder 目录，现在连 zeroconf 一起打进去），`/PORTABLE=1 /SILENT /DIR=...` 便携安装后
exe 正常启动、翻译与日志路径均正确。Inno 的 `[Code]` 是编译期做语法与类型检查的，所以"两个 exe 各写
一对"这版改动至少过了编译器这一道。
早先那两条 netsh 命令的**参数解析**探过：非提权状态下 netsh 是先解析参数再报"请求的操作需要提升"，
`cmd` 的 `&` 串联也确实发出两次调用，探针跑完 `name=chuanshu` 的规则数还是原来的 4 条，什么都没写进去。
给第二个 exe 加的那一对**没有再探一次**：参数形状与第一对逐字相同、只换路径，而重跑探针等于再朝这台
机器发一遍 `delete`/`add`（那是写系统的事，要点头）。它的真凭证在下一次双击安装之后——那时
`ChuanShu-cli.exe firewall` 应该从 `blocked` 变成 `open`，这条现在读得到的是：本机 `ChuanShu.exe`
放行、`ChuanShu-cli.exe` 名下压两条"公用"阻止规则（退出码 3）。

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
  203 处 `check(`，一轮跑完打印 403 行 PASS；`windows` 平台同样全过）。
  它把 `APPDATA`/`XDG_DATA_HOME` 指到临时目录**再** import `app.*`，所以自测用的是自己的
  身份、自己的已配对表和自己的接收目录，碰不到真实那套。覆盖：打开就已经在监听（端口、二维码、
  配对码三样都在，两条发现通道也一起起了；界面上没有"开始接收"这个开关，所以也没有点了没反应那一说）→
  真 `PeerConnection` 推进来的 offer 弹框（标题、文件名、保存路径、点的按钮）、拒绝路径拿到
  `DECLINED`、选中文件→点发送→输配对码→对面落盘逐字节一致、陌生设备要码而熟人不再问、
  手输地址连一个从不广播的机器（含地址填错要报错、不留半行）、切语言、退出释放端口。
  本机卡那行"入站"单独一节：没问过就不表态、放行/被阻止/没有规则/读不到四种状态各说各的话、
  被阻止时那句话里带上它挡在哪个端口上、提示词里给出`fix_commands()`那几条、5 秒重绘不丢掉结论、
  停止监听就把结论撤走。这里不读真机防火墙（那台机器的配置不是被测代码的事实），`firewall.inspect`
  被换成备好的状态；读真规则的那条门是 `cli_selftest.py`。
  导航栏收尾那颗账号章单独一节：栏宽按目录里最长的那条词条给，机器名另有一个上限——到顶就用
  省略号缩写，绝不硬裁掉尾巴（Linux 真桌面上"DESKTOP-58TSA70"少掉的那个 0 就是这么来的），
  整条名字留在提示词和无障碍名里；改名后栏上跟着变；"保存到"那格滚到的是路径的尾，整条路径挂在提示词里。
  这一段量的是真字形，offscreen 量不出来（同一台机器同一字号，offscreen 报 180px、真桌面 113px），
  所以三条结论都在真桌面上复看过。
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
  `protocol/` 与 `.mo` 有没有收进去）。它启动 exe、等窗口、扫日志里的 ERROR，
  然后只结束自己起的那个进程。窗口那条腿问的是**那个句柄自己的像素**（`PrintWindow` +
  `PW_RENDERFULLCONTENT`），不是拍屏幕上一块区域——之前它就在传书被压住的时候把**挡在前面的
  那个应用**存成了 `window.png`，还照自己窗口的尺寸印了一行、报了 PASS（#119）。所以现在有两道
  否定：图不能是单色（挡住又不肯重绘的窗口回给你的就是一张纯色），二维码不能只靠"看着像"——
  它先往导航栏第三行 Post 一个左键（**不动用户的光标**，且那一列里没有一个会弹对话框的按钮，
  点歪最多是换了页），再到「接收」页的像素里数 QR 定位图案那 1:1:3:1:1 的横条，
  并要求同一列竖着也成一次。实测这台机器：画出来的码 31～33 行命中，纯文字的首页 0 行，
  把码那块涂白也 0 行——**这条腿要的就是"QtSvg 没打进包"这种只在冻结版发生、又一声不响的坏，
  它得会说"不"**。实测结论：`qrcode` 不用加 hiddenimport（`from qrcode.image.svg
  import SvgPathImage` 是显式导入，`warn-app.txt` 里 `missing module PIL/png/lxml` 那几条来自
  qrcode 自己的可选后端，我们这条路径不会 import），`_rust.pyd`、`protocol/protocol.json`、
  两个 `.mo`、`assets/icons/` 都在 `_internal` 里，冻结版能画二维码、能绑 43720、两条发现通道都 ok。
  现在它还先跑 CLI 那四条腿，因为第二个入口是同一个 COLLECT 多带出来的，窗口那条腿证明不了它：
  冻结的 `ChuanShu-cli.exe self` 读得到 `_MEIPASS` 里的契约、首跑就印 6 位码、`--lang en` 拿到目录里的
  句子、`receive --no-discover` 真绑上 43915 并且把入站那半句一起说出来、`firewall` 印出的结论与它的退出码互相对得上（这台机器
  现在给的是 `open` → 0；同一行早些时候在这台机器上印的是 `blocked` → 3，那条路径名下当时有阻止规则。
  **这条腿要的不是某个固定答案，是它敢把自己那条路径的真实处境说出来**）。
  另外单独跑过一轮更狠的：三个 scratch 身份目录、1 MiB
  双向落到磁盘逐字节对 sha256、陌生端拿错码与熟人不再要码两条分支都对（`.probe` 里的一次性脚本，
  没进仓库；四条腿本身已经在上面那条里成了一遍门）。默认路径就指 `dist/ChuanShu/`——指回某个 scratch
  副本会拿着旧结构出新结论，第一次跑就是这么暴露出"CLI 不在旁边"的。
  `--no-discover` 挡不住 Windows 弹防火墙框：一个纯 TCP 监听就够弹了，所以跑完这一门桌上常留一个
  系统框——那个框归用户答，脚本从不点它（点"取消"留下的就是上面那两条阻止规则）。
- **冒烟证的是"跑得起来"，不是"这一步改动在里面"**。改过 `app/net/send.py` 重出包之后（#131），用
  `PyInstaller.archive.readers` 把产物里的 `PYZ` 掏出来、`marshal` 出 `app.net.send` 的 code object，
  在它的常量里找那三句新日志（Windows 侧读 `dist\ChuanShu\ChuanShu.exe`，Linux 侧在 WSL 里读解压出来的
  `ChuanShu/ChuanShu`）——两边都命中才算这次出包真的把 #130 带上了。这条不是例行步骤：只有"改了产品代码
  又重出包"那一轮值得做一次，因为那三句在包里是编译后的常量，grep 二进制搜不到。

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
- 平台差异只有四个落点：路径问 `paths.user_data_dir()` / `autostart_desktop_path()`，开机自启问
  `autostart.is_supported()`，有没有托盘问 `tray.available()`，深色跟随问 `theme.system_prefers_dark()`。
  别在 UI 里再写 `sys.platform`——加第三个系统时只该动这四处，`ui_selftest.py` 里那条
  "没有托盘就不承诺托盘"的断言也只在 `tray.available()` 上挂钩子
- `app.spec` 里是**两份 Analysis、两个 EXE、一个 COLLECT**：命令行必须是第二个 console 入口
  （`console=False` 的窗口进程没有 stdout），而两份的 `binaries`/`datas` 要经 `_merge()` 按文件名去重再
  交给 COLLECT，直接拼两份 TOC 会在同一个包里撞出同名条目。加第三个入口照这个形状加，别改成 onefile
- 若要便携单文件 exe：把 `app.spec` 的 `EXE(...)` 改成 onefile（去掉 `COLLECT`，
  把 `_merge(a.binaries, a_cli.binaries)`、`_merge(a.datas, a_cli.datas)` 传给每个 `EXE`），
  代价是每次启动先解包、而且两个入口会各自解一份
- 冻结版在 Windows 按控制台代码页写 stdout，`PYTHONIOENCODING` 不生效（见"命令行（headless）"）；
  要写解析它输出的脚本，先 `chcp 65001` 或者照 `freeze_smoke.decode()` 那样两种编码都试
