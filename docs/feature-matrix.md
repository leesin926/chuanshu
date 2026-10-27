# 传书 ChuanShu — 各端功能点与验证状态

这份文档回答三个问题：**每个端现在能做到什么**、**这条结论是哪一档证据给的**、**剩下的活儿按什么顺序做**。
它不复述协议语义（那在 [protocol/spec.md](../protocol/spec.md)），也不复述手机端工程结构（那在
[mobile/README.md](../mobile/README.md)）；这两处只留索引，见文末。

## 0. 证据分档（先认清口径）

产品口径只有一条判据：**接收方落盘后按同样的规则本地重算 sha256，逐字节比对**。
"两边都说了 ok" 不算结论，"发送方觉得自己发完了" 也不算。每个功能点后面挂的档位含义：

| 档 | 含义 | 覆盖到什么 |
|---|---|---|
| `真机` | 外部物理设备上跑过，判定读自设备自己的文件系统或界面 | 该条路径的平台行为 + 协议行为都算数 |
| `模拟器` | Android AVD / 鸿蒙模拟器上跑过，判定同上 | 平台行为算数；网络拓扑是 QEMU NAT，不代表局域网 |
| `浏览器` | H5 目标里跑过 | 只覆盖**平台无关**那一半（状态机、模型、UI 路由）；探针按钮的输出在浏览器里不是证据 |
| `门禁` | `scripts/*_selftest.py` 进程内自测跑绿 | 逻辑与契约，不含平台 chrome、字体、窗口管理 |
| `截图` | 真机/模拟器截图与设计图逐项比对 | 视觉与布局，不含传输行为 |
| `编译门` | HBuilderX CLI 编到 Kotlin/ArkTS 字节码，或 `py_compile` | 只说明那条路径**改得动**，没跑过 |
| `未验` | 代码在树里，一档证据都没有 | 写清楚，不当成已完成 |

`编译门` 与 `真机` 之间隔着的典型距离：Android 的 Conscrypt 不广告 Ed25519、鸿蒙的平台 TLS 签不出
Ed25519 叶、TLS 记录会乱序到达——这三条都是上机才知道的，编译过一点信息都给不了。

## 1. 产品范围（2026-10-24 由用户定口径）

- **手机 = Android + HarmonyOS Next**。iOS **终止**（不是搁置）：这台机器没有 Mac，出不了可签名的包；
  `app-ios/` 两半边代码留在树里当档案，不进任何验收。
- **PC = Windows + Linux**，每个系统**两个前端**：图形界面 + 命令行。"针对不同系统分别适配"落在
  数据目录、开机自启、托盘、防火墙、出包这几处分支上，不是重写。
- 平台差异按分支处理，不在协议层开洞：协议不看谁实现都得遵守同一份合同
  （[protocol/protocol.json](../protocol/protocol.json)）。

## 2. 协议 v1 要点（冻结口径，只列影响功能矩阵的那几条）

| 主题 | 口径 |
|---|---|
| 版本 | `protocol_version: 1`，`compatible_versions: [1]`。**§7 判的是两个集合的交集**，不是一个数：这个集合要出现在每一处"说自己"的场合——`hello`、`pair` 的应答，以及 `pair`/`offer` 的请求体。请求体也带它，是因为接收方不会回拨去读对方的 hello，对方的集合只可能从那两个体里拿到。哪一边没报集合，就按它印出的 `protocol_version` 那一个数当作整个集合——那是这个字段之前的一版，不是把它当陌生人的理由（与 §3 的 `served` 空值兜底同一条思路，#115）。**只有 UDP 公告和二维码不取交集**：那两处一个数都印不满一个集合，所以只筛数、把交集留给 hello（`app/net/discovery.py` 的 `_learn`、`app/net/spec.py` 的 `parse_qr`、手机的 `cs-discovery.uts`，三处都写着这条注释）。交集为空 → `400 UNSUPPORTED_PROTOCOL` |
| 端口 | 传输 43720（TCP）、发现 43721（UDP） |
| 发现 | 三条通道：mDNS 优先 → UDP 广播补充 → 扫码/手输兜底。**顺序不可颠倒，也不能只留 mDNS**；TXT 带 `ver/name/fp/ts`，announce 3 s，名单 15 s 过期；**Presence is not trust**（听见 ≠ 信任） |
| 身份 | 一台设备**两个摘要**：Ed25519 身份密钥只签配对码；套接字递出的是独立签发的 **RSA-2048 自签叶**（`CN=peer_id`，20 年）。信任锚是叶的 SPKI SHA-256；二维码 `f=`、广播前缀、TLS 钉子钉的都是这个叶摘要。两个都**不是** `peer_id` |
| 端点 | 七个：`GET /v1/hello`、`POST /v1/pair`、`POST /v1/offer`、`GET /v1/state`、`PUT /v1/offer/{id}/chunk/{idx}`、`POST /v1/finalize`、`DELETE /v1/offer/{id}`；鉴权走 `X-Chuanshu-Auth`，分块摘要 `X-Sha256`，声明长度 `X-File-Size` |
| 分块 | 4 MiB，同一 offer 最多 2 块并行；`hello` 里接收方声明 `chunk_pace_ms`，发送方按节奏写记录（手机侧阶梯 `[0, 15, 40]`）。阶梯到底以后体仍被管道吐掉时，先读一次 `state`：对方说没到，那是**中继打嗝**不是"还太快"（这一档无档可升），发送方用剩下的尝试次数重写那一块；问不到答案或次数用尽才把原错误抛出去。这条**不分端**，因为合同说的是"发送方"：PC 走 #120/#130/#137，手机走共用那半边 `cs-client.uts`（#132）——一块最多三次写，`state` 只在一写的回复没来时问一次。**「问到了答案」才允许重写**：对方说没到是管道打嗝，重写有戏；那一问自己也没人答，就是对面真没了，再写两次只是往一个拨不通的套接字上继续写。PC 在 #137 之前把后者读成了前者（`_chunk_landed` 只有真假两值，问不到就返回"没到"），手机那一半边从 #132 起就是三态的。 |
| 落盘 | 接收根目录**按单建目录**：`接收根目录/<offer_id>/<清洗后 relpath>`，两端同一个形状。平铺（`接收根目录/<relpath>`）时同一个名字被第二单送到，后一单 accept 里的预分配会把前一单**已经校验过**的字节截断重写（#128）。同一份清单里两个清洗后同名的条目也不许共用一个落点：**后拿到的那一个加 ` (2)`、` (3)`… 后缀（在扩展名之前），而不是覆盖**（#163——发送方按文件名取名是合法的，`ChuanShu-cli send C:\a\report.txt D:\b\report.txt` 就是把两个 id 报成同一个名字）。落点记在台账的 `land` 字段里（两端同一个键：手机 `cs-receive.uts`，PC 把它写在清单条目上、跟着状态文件一起持久化）；旧文档没有这个字段，读到空就按平铺/原 `relpath` 解释——那一单的字节确实躺在旧位置上 |
| 恢复 | 状态文件只是提示，**结论只来自 `finalize` 的整文件摘要**；offer id 就是续传柄，接收方的 `missing` 列表决定还缺什么。被摘要推翻的那本台账当场作废：`finalize` 一旦「台账说全有、磁盘说没有」，接收方就抹掉这个文件的分块记录并改口说全缺——否则发送方整单重发会被逐块「已经存过」挡回来，一个字节也写不回去（这一条 #127 在安卓与鸿蒙模拟器上各量到一次，原文 `.probe/a_127.txt`、`.probe/h_127.txt`） |
| 限额 | 一次 offer 2000 个文件、名字 255 字节、路径深度 16、offer 等待 60 s、会话闲置 900 s、offer 闲置 3600 s、配对码 120 s（6 位数字，口令 8 位大写+数字） |
| 错误码 | 11 个，中英双语文案；`CANCELLED` 是**传输层自己的**词，永不上线 |
| 中继 | 只在合同里留字段位，没有实现 |

## 3. 功能点 × 端 主矩阵

格子写证据档。`—` = 该端不做这件事（不是"没做完"）。

### 3.1 PC

| 功能点 | Windows GUI | Windows CLI | Linux GUI | Linux CLI |
|---|---|---|---|---|
| 收发双向（7 端点、断点续传、路径清洗、多文件带目录） | `门禁`+`模拟器`+`真机` | `门禁`+`真机` | `门禁` | `门禁`+`真机` |
| 收：一份清单里两个同名条目各落各的位置，后拿到的加 ` (2)` 后缀而不覆盖（#163，§5 第二句） | `门禁`（`protocol_selftest.py` 新 `phase_same_name` 那一趟 `RESULT ALL PASS`：`report.txt` 与 `report (2).txt` 两份字节各自对自己那一份源文件过整文件摘要。改之前同一趟是 `FILE_DIGEST_MISMATCH`，原文 `.probe/a_163_before.txt`、`.probe/a_163_before_run.txt`） | `门禁`（`cli_selftest.py` 全过；这一支的入口就在命令行上——GUI 会先拒掉跨根目录的选择，`send C:\a\report.txt D:\b\report.txt` 不会） | `门禁`（同一份 `app/net/receive.py`，Linux 没有第二套判据） | `门禁` |
| 协议 §7：版本按**两个集合的交集**判，本端的集合在 `hello`、`pair` 应答与 `pair`/`offer` 体里都说得出（#144） | `门禁`（`ui_selftest.py` 那一趟 403 条全过，证的是"处处公开集合"没把正常配对/清单/落盘碰坏；交集那四条腿打在 `protocol_selftest.py` 上，跑在源码里、不分端） | `门禁`（`cli_selftest.py` 全过）+ `模拟器`（**真手机发过来的那一趟**：`.probe/a_144_leg.py` 把 `Protocol.intersects` 包起来打印它读到的东西，两次——`pair` 与 `offer`——都是 `compatible_versions=[1] protocol_version=1 -> 交集非空=True`，随后 5 MB 落 `…/a_144_root/b537096fdc92f54c/chuanshu-probe-5mb.bin` 逐字节一致，屏上「完成：对方已收下 1 个文件 / 5.00 MB」（原文 `.probe/a_144.txt`）。判成功本来不吭声，所以这一行观察才是"PC 读到了手机那份集合"的证据，不是"两边都说 ok"） | `门禁` | `门禁`（`linux_selftest.py` 27 条在 WSL Ubuntu-24.04 的 Python 3.12 上全过：这条支是平台无关的那一份 `spec.py`/`send.py`/`receive.py`，Linux 没有第二套判据） |
| 发：节奏已在 40 ms 下限时体仍被管道吐掉 → 先问 `state`，对方说没到就重写那一块（#130，不判死整单） | `门禁`+`模拟器` | `门禁`+`模拟器` | `门禁` | `门禁` |
| 发：上面那一次 `state` 问不到答案时**一次都不重写**、当场抛原错误（#137，合同 §4 后半句的前一种；手机那半边同一支的模拟器腿见 §3.2/§3.3 的 `mute`） | `门禁` | `门禁` | `门禁` | `门禁`（这一支的证据是 `protocol_selftest.py` 那两条腿，跑在源码上；#139 那一批产物把它带进了两个包里，包内冒烟证的是"跑得起来、四条 CLI 腿还在"，不是这一支本身） |
| 接收确认（谁在拨、几个文件、60/65 s 内必须回答） | `门禁` | `门禁` | `门禁` | `门禁` |
| 收：同一个 `offer_id` 只问用户一次——已经答过的（拒绝／窗口到点／这一单已结束）按 id 复述那一答，不再弹第二次窗（#145，合同 §4） | `门禁`（`.probe/c145_ui.log`：`RESULT ALL PASS`，403 条。这一支的判据腿在 `protocol_selftest.py` 那一趟：`.probe/c145_proto2.log` `RESULT ALL PASS`，109 条，其中八条是 #145 新加的） | `门禁`（`.probe/c145_cli.log` 全过：CLI 的 `--yes`／超时不答都从同一个 `handle_offer` 出去，复用规则在 net 层，两个入口一起继承） | `门禁` | `门禁`（`.probe/c145_linux.log`：`linux_selftest.py` 27 条全过——改的是平台无关的那一份 `receive.py`，Linux 没有第二套回答） |
| 落盘记录持久化（`arrivals.json`，重启后仍按磁盘真相说话） | `门禁` | `门禁` | `门禁` | `门禁` |
| 固定对端管理 / 撤销（`unpair`） | `门禁` | `门禁` | — | `门禁` |
| 单会话名额 + 第三方连接拒 | `门禁` | `门禁` | `门禁` | `门禁` |
| 配对码 + 口令展示（同屏可核对） | `门禁` | `门禁` | `门禁` | `门禁` |
| 发：配对应答里那个身份摘要与**同一条连接**的 hello 不一致时，就地停住、不把它记进信任表（#162，合同 §1 那句"配对回复和 hello 的 `fingerprint` 字段是同一个数"；手机共用发送方 `cs-client.uts:218-222` 早就这么做，PC 这一端过去是把应答里说什么就照抄什么） | `门禁` | `门禁` | `门禁` | `门禁` |
| 发现：mDNS + UDP 广播（`_chuanshu._tcp`，名单 15 s 过期） | `门禁` | `门禁` | `门禁`(脚本读 stdout) | `门禁` |
| 防火墙状态读取与自述（被挡时界面自己说） | `门禁`+`真机`(WSLg 侧为 `模拟器`) | `门禁` | `门禁` | `门禁` |
| 防火墙规则写入 | 安装器（per-exe，`netsh`，先清后放；本机实测过装完的判定） | 同左 | 不代跑：`fix_commands()` 给出 `firewall-cmd`/`ufw` 那两条命令，界面与 CLI 只打印 | 同左 |
| 无边框自绘标题栏 / 深浅主题 / 托盘 / 开机自启 / 关闭询问 | `门禁`+`截图`+`真机`(窗口像素验收 #119) | — | `截图`(WSLg 实测)；托盘随桌面环境降级 | — |
| i18n 8 语言（zh_CN/en/ja/ko/de/fr/es/ru）+ 错误码双语文案 | `门禁` | `门禁` | `门禁` | `门禁` |
| 打包产物 | `exe` + Inno 安装包，`门禁`(freeze_smoke 复验)；#139 那一批出在 #137 之后 | 同一份 | `tar.gz`(0.1.0-linux-x64)，`.probe/linux_smoke.sh` 在 WSLg 真屏复验 | 同一份 |

CLI 的八个子命令（[app/cli.py](../app/cli.py)）：`self`（本机身份与配对串）、`receive`、`send`、
`peers`（发现的名单）、`pins`（固定的对端）、`firewall`（读平台判定）、`unpair`、`pair-code`。
`receive` 的 offer 提示带真计时器（#112）：不回答就到点，不再把对端无限期挂在一条连接上。

Linux 与 Windows 的三个真实分歧，都已落到代码分支：
1. 数据目录（`app/paths.py`：`%APPDATA%` vs XDG，`CS_ID_DIR` 可指走）；
2. 开机自启（`app/autostart.py`：HKCU `Run` 注册表值 vs XDG autostart 的 `.desktop`，且都只在打包态生效）；
3. 端口占用（`app/cli.py::listener_on` 先连上问一次 `/v1/hello` 才相信 bind 成功——**Windows 允许第二个进程
   bind 一个正在服务的端口**，POSIX 会 `EADDRINUSE`，这条是 coexistence 逻辑的地基）。

**Linux 那两列的证据边界要写清楚**：`linux_selftest.py` 的 27 条断言跑在 WSL Ubuntu-24.04 的 Python 3.12 上，
不带 Qt；GUI 半（主题自动检测、无边框、托盘降级）靠 WSLg 真屏截图看过两处渲染缺陷（#105 后续）。
真正的物理 Linux 桌面——需要 `pip install PySide6`、需要装桌面——**没跑过**，所以 Linux GUI 的传输行为
一格写 `门禁` 而不是 `真机`。

### 3.2 Android

| 功能点 | 状态 | 证据 |
|---|---|---|
| 身份：纯 BigInteger Ed25519 签名 + 手搓 236 字节 X.509 DER（RSA-2048 叶） | 完成 | `模拟器`（不引 BouncyCastle：三方依赖要云打包才拉得到，这台机器验不了那条路）。**§1 那两句这一端各欠过一半，#162 两处都补了并上了机**（见 §6 第 19 条）：一、叶的主题 `CN` 过去写 `Build.MANUFACTURER + Build.MODEL`，而 PC（`app/net/identity.py::ensure_leaf`）与鸿蒙（`app-harmony/index.uts::servedPair`）写的都是 `peer_id`——现在 `ServedLeaf.kt::commonName()` 读 `CsIdentity.peerId()`（这次新导出的取值口），读不到才回落硬件那句；二、`stored()` 里那道 `checkValidity()` 删掉了，日期**故意不读**：§1 说这张叶只铸一次、换了叶就要人工重新配对（钉子钉在证书上），问时钟就等于让一次倒退的时钟重铸出一把新钥匙、一个新 SPKI 摘要，把每一台钉过这手机的机器在下一次重启时静默地丢掉钉子。这一支在设备上发作过：`.probe/and_persist.txt` 152-155 那两行 `stored cert rejected by the clock: CertificateExpiredException`（#109 那回的年份编码把有效期写成了 1976，于是每次重启都被判死、叶重铸）。腿与读数在 `.probe/a_162_leaf.py`（`clock`/`cn`/`restore` 三段，改期是靠重写 TBS 里那两个 UTCTime 再重新签、逐字节拼回 718 字节的原 DER，`adb root` 推回私有目录后按 `stat -c %u:%g` 补属主再 `restorecon`）：`clock` 段 verdict PASS「一张被日期判死的叶留在架上也照样递出去，摘要三个地方都是同一个数，日志没开口」，`cn` 段 verdict PASS「首次运行铸的那张叶，主题就是 §1 说的 peer_id」（`CN=「e813141dd9020102047c620538899a20」 == peer_id`，notAfter 2046-10-27，架上/套接字/hello 三处 `885c8d70489c514e…` 相同）。编译门 `.probe/c162_android.log` |
| TLS 服务 + 指纹固定（拨入/拨出都钉得住） | 完成 | `模拟器`；`真机`（#106 手机发→PC 收就是这条路的真机证据） |
| 发：同一单多个文件 + 中文子目录（一块整 / 零头 / 带空格与括号） | 完成 | `模拟器`（#125 安卓腿：4 MiB + 1023 B + 1 MiB 三份一次发出，PC 侧逐字节比对三份全对、目录层级保住、单里三行都报完成） |
| 发：`pair/offer/chunk/finalize` + 4 MiB 分块 + 0x00 转义 | 完成 | `模拟器`（5 MB / 2 块，接收方逐字节比对） |
| 发：一写的回复没来时先问一次对方的 `state`，对方说齐了就算这块成了；说没到就用剩下的次数重写那一块（#132，与 PC 的 #120/#130 同一条） | 完成 | `模拟器`（#133：`.probe/a_133.py` 造四种喂法，同一台 AVD 四条腿全 YES。`held`＝体收下、回复不发、连接关掉 → 对端账本 `写块请求 2 次，真正收下 2 块，state 询问 1 次，吞回复 1 次，finalize 1 次`，落盘 `sha=6f25483fb457` 逐字节一致，屏上 `完成：对方已收下 1 个文件 / 5.00 MB`；`blind`＝体的一个字节都不收 → 同样问一次 `state`， 对方答"没到"，于是写第 3 次、仍逐字节一致；`dead`＝每块都收、每次都不答 → 写满 3 次、问满 3 次就判死，屏上 `失败：协议错误：CONN_RESET Broken pipe` + `推送失败 0/2 块`，没有挂住；`mute`＝体不收、连那一次 `state` 也不答 → 问不到答案就**一次都不重写**（`写块请求 1 次，state 询问 1 次（其中 1 次没答）`），报的是那一问自己的错（屏上 `失败：协议错误：PROTOCOL 对端没答话`），而不是原来那次 PUT 的错（对比 `dead` 那趟屏上是 `CONN_RESET Broken pipe`——那一趟问到了答案，所以抛的是写本身的错）。原文 `.probe/a_133_held.txt`、`a_133_blind.txt`、`a_133_dead.txt`、`a_133_mute.txt`）+ `浏览器`（H5 那 14 项同一支）+ `编译门`（`.probe/_and_gate_132b.log`） |
| 收：立即应答 + 轮询 `state` + 落盘后本地重算 | 完成 | `模拟器`（PC 发→手机收；中文子目录保留） |
| 收：§3 那句「同一来源 5 次失败锁 60s」的**来源**是地址，不是连接（#162，与鸿蒙那端同一轮对齐） | 完成 | `浏览器`（锁 60 s 那三条腿一直在共用状态机上——`接收自检 71 项全部通过`，`cs-receive.uts::failCount/pushFail` 按调用方交来的 `client` 字符串分桶，它自己不认地址）。安卓读的是 `CsServe.kt:233-236`：`sk.inetAddress?.hostAddress ?: "?"`，两条路都交得出一个"来源"而不是"这一条连接"——地址到手就按地址记，一时读不到就全落进 `'?'` 那一格，一个猜码的人因此最多只有 5 次（宁可和陌生人同桶，也不给它发新额度）。同一轮里鸿蒙那一端交的是连接序号，等于每条新连接一格新额度、这把锁永远填不满，已改掉（§3.3 同一行）；PC 按 `client_ip` 记，见 `app/net/receive.py:564`。三端现在各自有一份屏或一条腿说同一句话，细节见 §6 第 19 条 |
| 收：接收途中杀掉进程，重启后接管同一单只补缺的尾巴；台账被磁盘推翻时当场作废 | 完成 | `模拟器`（#127 两条腿：第一条 `接管以后的台账：received=1 missing=[1]` → 收尾 `sha=6f25483fb457…` 逐字节一致；第二条两块写完先不 finalize、杀掉、把文件删掉，手机自称 `received=2 missing=[]`，`finalize` 拦住并当场改口缺 `[0, 1]`，整单重发后 `verified_ok=True`。原文 `.probe/a_127.txt`） |
| 收：一单一个目录，同名两单不互相截断 | 完成 | `模拟器`（#128 三条腿：第一单落 `files/chuanshu-receive/858f6665df09342f/chuanshu-probe-5mb.bin`，逐字节一致；第二单送**同一个名字**、只写第一块，根目录里 `find` 出两份，第一单那份 sha 仍是 `6f25483fb457…`；第二单补完后两份都逐字节一致，卡片从「已验证 2 个（2 个已经不在了）」变成「已验证 4 个（2 个已经不在了）」——多出来的两行都还在。原文 `.probe/a_128.txt`） |
| 收：一份清单里两个同名条目各落各的位置，后拿到的加 ` (2)` 后缀而不覆盖（#163，§5 第二句；与 PC 同一条规则，代码只有一份） | 完成 | `编译门`（`.probe/c163_android.log`：`项目 chuanshu（模块 cs-transport）编译成功。`）+ `浏览器`（`接收自检 76 项全部通过`——5c 那五条新腿，原文 `.probe/c163_web_selftest.txt`。改之前同一趟是 `失败 3 项，通过 73 项`：把共用状态机里那句改名临时还原成 `return name`，两条 PUT 都照样回 200——它们落在同一个名字上，红的正是只有分开落点才说得出的那三个结论。安卓这一端没有第二份落盘代码：`land` 由 `cs-receive.uts::offerReply` 记进台账，宿主的写块、卡片与回收读的都是它） |
| 收：本机**拨出过**的对端不带配对码回拨时认成同一台（#141） | 完成 | `编译门`（`.probe/c141_android.log`：`项目 chuanshu 编译成功。`）+ `浏览器`（`接收自检 59 项全部通过`，其中新加的三条腿就是这一支：桥接交**身份摘要**时留空配对码能 `resumed=true`、只交**叶摘要**仍然 `BAD_PAIR_CODE`、验签后那条记录同时长出了密钥与叶）。修的是 `app-android/index.uts` 的入站桥：`CsIdentity.pinFor` 给的是拨出时钉住的**服务叶**，而 `cs-receive.uts::pairReply` 只按**身份摘要**认人——#47/#106 以后每一端都serve独立叶，这两个数再也不相等，所以旧桥把号递错了地址，回拨的一台落到陌生人分支被要一个它拿不到的码。现在 `pin()` 多存一个 `identity`（配对成功那一步从应答里拿 `fingerprint` 写进去），旧记录由 `healIdentity` 在**验签前**从那条 pair 里补：调用方把自家叶写在**签过名的字节里**（`pair|peer_id|nonce|tls_fingerprint`），声明与钉住的叶对上才认。设备腿跑过了（`模拟器`，`.probe/a_149.txt`：两台从零开始，手机先拨 `10.0.2.2:43720` 钉住那台，再由**出货的 PC 命令行**不带配对码回拨——线上 `code` 就是空串、`secret` 是 `null`，手机答 `resumed=true`，200 000 字节逐字节落在 `files/chuanshu-receive/<offer_id>/a149.bin`；同一份状态换成 `adb forward` 进来（手机上看起来是 `127.0.0.1`）就是另一句：`对方不认识这把钥匙…用 --code 传给我`，一个字节都没落。详见 §5 那两行与 §7「宿主机拨进 Android 模拟器有两条门」） |
| 发：点中的局域网候选**先按前缀核对，再进 §3 配对**（#142，核对的位置由 #150 搬到套接字上） | 完成 | `编译门`（`.probe/c142_android.log`，#150 重跑：`.probe/c150_android.log`）+ `浏览器`（`发送自检 24 项全部通过`，E 组那几条腿就是这一支：前缀对得上的候选照常配对传成、对不上的**连 hello 都没打到对方**、且那一单一次 pair 都没打到对方的固定名单上，另有一条 64 位整摘要的对照）。改的是 `store/session.uts::buildOptions`：过去只有扫过码才把值交给共用发送方的 `pinPrefix`，从名单点中的那一行只把前缀记在 `discPicked` 里，于是那句"先核对"根本拿不到东西，核对被推到 `markConnected`——那时配对已经写完、对方已经把这台机器落成固定、单会话名额也已经被占住，合同 §2 要的"排除地址撞错机器"变成事后的道歉。现在 `discPicked` 直接进 `pinPrefix`（`s.scannedFp` 仍优先，它是扫码读到的完整摘要），`markConnected` 里那一段只留名单记账：完整摘要取自 `pinnedFor()`，也就是传输在握手时自己记下并写进钉表的那个数，不再取对方在 hello 里自报的 `served`（那个字段已经删掉）。扫码读码时顺手清掉旧前缀，免得拿一条不再点的名单判今天扫的这台。**#142 当时比的是 `served`，PC 那端比的是套接字读回来的叶摘要**（`app/net/discovery.py:122` → `identity.py:500`）；**#150 把手机这一侧也搬到了套接字上**：判据收成一条 `cs-protocol.uts::pinAccepts`，Android 在 `CsWire.kt::checkServerTrusted` 里用它，前缀对不上就没有请求行。这条腿的形状两端都在模拟器上跑过：鸿蒙见 §3.3 末尾与 `.probe/h_150.txt`，**安卓这一边也跑过了**（`模拟器`，原文 `.probe/a_154.txt` 末段 + 截图 `.probe/a_154_card.png`：从名单点中一条假公告，屏上「对端证书与要核对的指纹不符，已中止 广播里报的是 0badc0ffee000000，收到 3ae1fc93c61c7b73…」，同一时间对端一条请求行都没有，只有 `SSLV3_ALERT_CERTIFICATE_UNKNOWN`；四条纹身的合账见 `.probe/a_153.txt`） |
| 机对机（两台 AVD 互传，双向） | 完成 | `模拟器`（宿主是唯一的路：接收方 `adb forward`，发送方拨 `10.0.2.2`） |
| 三份记忆：固定对端 / 未完成的单 / 已收下的文件 | 完成 | `模拟器`（重启后 `run-as` 读回文件，卡片逐个问文件系统） |
| 写入节奏 `chunk_pace_ms` + 阶梯 `[0,15,40]`、记录上限 4096 | 完成 | `模拟器`（4 MiB 块在 15 ms 档实测 ~37 s） |
| 取消两级：收回排队里的请求（A 级）+ 掐掉正在写的那一块（B 级） | 完成 | `模拟器`（#124 两条 leg 全 YES：半块断掉对端看得见、按下 2.2 s 停下、重发逐字节一致、取消不让节奏爬阶梯。**#136 在 #132 之后重跑过同一趟**，仍全 YES：按下取消 2.6 秒后屏上 `失败：本机取消了这次传输 用户按下了取消`，对端账本 `分块头 0→1 / 收完整块 0→0 / 断在半路 0→1`——**只上过线一次**，这就是这一趟真正要守的东西：#132 改的正是同一条 `putChunk`（`status == 0` 那一支现在会先问一次 `state`，问到"没到"还会重写那一块），而"本机自己收回"必须走不到那一支里去——它靠 `code != 'CANCELLED'` 把自己排除在外，对端因此只看见一个写块头。第二趟 2 块全落、`sha=6f25483fb457` 逐字节一致、逐块读体用时 `(0, 17.2) (1, 4.3)` 说明节奏还停在声明的那一档。原文 `.probe/a_124.txt`） |
| 失败原因的渲染：同一支 `detailOf`（A 级那句也从 `detail.reason` 读） | 完成 | `模拟器`（#134：把 A 级那一句在安卓上真按出来了一次。做法是让对端**只对清单表态说不**——本机对 `POST /v1/offer` 每次都回 `{"accepted": false}`，这正是手机端接收方自己还没决定时答的那一句，于是发送方按合同每秒重投一次清单、一直投到 60 秒，这一秒一秒之间屏幕上按下去的就是 A 级而不是正在写的那一块。对端账本：`清单进来 8 次（每次都不表态），写块请求 0 次，真正收下 0 块，finalize 0 次，落盘 {}`；按下取消 5.3 秒后传输页说 `失败：本机取消了这次传输 这一单还没发出去就被本机收回了`——整句、没有 `{"reason"`、没有 `detail`，也没等满对方的 60 秒窗口。六条判据全 YES，原文 `.probe/a_134.txt`，对端账本 `.probe/a_134_peer_pick.txt`；#126 那一趟的改动在共用渲染层 `cs-protocol.uts::detailOf`，这一趟证的就是它读出的那一句） |
| 发现：mDNS + UDP 广播 | 广播那一半在模拟器上**听到并用了**（`模拟器`），真 LAN 仍**卡在出包口径** | `编译门` + `浏览器`（模型共用）+ `模拟器`（`.probe/a_154.txt`：一条外来的 UDP 公告进了名单，点中它把前缀交给 TLS 那一关——所以"安卓模拟器上发现听不到东西"是 harness 的问题不是应用的问题：宿主打 `255.255.255.255`/`10.0.2.255` 进不去 guest，guest 本机 `nc -u` 打自己的 43721 也一个包都不到，能用的门是控制台 `redir add udp:43722:43721`；插件套接字是 `[::]:43721` 双栈，v4 包以 `Inet4Address` 原样到达，`is Inet4Address` 那道筛从来不是原因，细节 `.probe/a_153.txt` 末尾）。真机上要 `CHANGE_WIFI_MULTICAST_STATE`（mDNS 组播那一条），而它必须打进自定义基座——`pack --iscustom` 花的是用户的 DCloud 账号 |
| 协议 §7：版本按**两个集合的交集**判，本端的集合处处都说得出（#144，与 PC 同一条规则） | 完成 | `编译门`（`.probe/c144_android.log`：`项目 chuanshu 编译成功。`；鸿蒙那一道见 §3.3 同一行）+ `浏览器`（`发送自检 20 项全部通过`、`接收自检 61 项全部通过`、`发现自检 22 项全部通过`，`bad=0`——三条数都在共用状态机上，见 §3.4 那一节新写的 F 腿与 5b 腿）。**这一支只有一份代码**：判据落在 `utssdk/cs-protocol.uts`（新导出 `COMPATIBLE_VERSIONS`、`versionsOverlap`、`versionsText`），`cs-client.uts` 的 hello、`cs-receive.uts` 的 pair 与 offer 都改成问同一个问题；改之前是两条各拿一半腿——发送方只看对端在 hello 里印出的那一个 `protocol_version`（一台印 1、集合却是 `[2]` 的机器被放行了），接收方自带的那个 `supports()` 只看对方报的集合（一台在这个字段之前就发清单的机器被当成陌生人拒了），而且**谁都交集不了**，因为发送方从来没把集合送到接收方读得到的地方——接收方不回拨去读对方的 hello。所以集合现在跟着 `pairJson`/`offerJson` 的请求体走，`pair` 的应答把它在 hello 里说过的话重述一遍（§3 那条 `served` 兜底的同一思路）。没报集合＝那是这个字段之前的一版，按它印出的那一个数当作整个集合，不是把它当陌生人的理由。**设备腿两个方向都在安卓模拟器上跑过了**（`模拟器`）：手机发 → PC 收那一趟见 §3.1 那一行（`.probe/a_144.txt`——PC 那半边打印出自己读到的 `compatible_versions=[1]`，5 MB 逐字节一致）；PC 发 → 手机收那一趟就是 #141 那条回拨腿（`.probe/a_149.txt` 04:37 段：PC 那份 `pair` 体里的键列出来是 `code compatible_versions name nonce peer_id protocol_version public_key signature tls_fingerprint`，手机收下、`resumed=true`、200 000 字节逐字节落盘，屏上没有 `UNSUPPORTED_PROTOCOL`）。**手机读到自己那一侧的正证到这一轮补齐了，但补齐的那一台是鸿蒙**（`模拟器`，见 §3.3 那一行末：故意报一个只含 v2 的集合来判死，用的是**本机改报**的那台 PC 替身——`h_144_v2_recv.py` 把 `spec.load()` 交回来的那份声明换成只含 v2，所以量的是手机对一份陌生集合的判断，不需要第二个 v2 产品；安卓这两条腿跑在 `parsePairUrl` 改成问集合**之前**，而那一步改动在 `COMPATIBLE_VERSIONS == [1]` 时行为不变，`v=1` 的串照样通过，所以那两趟仍然算数——判据是同一份 `cs-protocol.uts`/`cs-client.uts`/`cs-receive.uts`，两端的编译门各自绿过：`.probe/c157_android.log`、`.probe/c157_harmony.log`。#157 那句"解析拒了要在本页说为什么"同样改在三端共用的 `store/session.uts`，**这一格也在安卓模拟器上对着屏重看过了**（`模拟器`，2026-10-27，三条腿各一趟：`.probe/a_157_android.txt`、`.probe/a_157_leg2.log`、`.probe/a_157_both.log`）：往粘贴框里填一条 `v=2` 的串、只按「解析」，卡片下面一行就是「配对信息读不出来：对端协议版本 v2 本机听不懂」，而那趟对端的计数器停在 `hello 0 / pair 0`——这一支真的没往外拨；同一份 bundle 上合法密码那趟仍然「已连接 探针对端（首次，已固定指纹）」；H5 那一格见 §3.4 同一行） |
| UI 七页（首页/文件/传输/我的/发送/扫码连接/探针） | 完成 | `截图` + `模拟器`；自定义导航页让出状态栏安全区（#102） |
| 收：同一个 `offer_id` 只问用户一次，答过的按 id 复述那一答（#145，与 PC 同一条规则） | 完成 | `编译门`（`.probe/c145_android.log`：`项目 chuanshu 编译成功。`；鸿蒙那一道见 §3.3 同一行）+ `浏览器`（`接收自检 66 项全部通过`，`bad=0`，原文 `.probe/c145_web_selftest.txt`；第 14 组那五条腿见 §3.4）。**这一支只有一份代码**：记答案的活儿从宿主收进共用状态机 —— `sweep` 里窗口到点没人答＝`DECLINED`、闲置回收与对方 `DELETE`＝`OFFER_UNKNOWN`、用户点拒绝与 `STORAGE_FULL`＝当场记下；改之前只有"用户点了拒绝"这一种答案是靠宿主记得调 `settleOffer`，宿主漏一次就再弹一次窗，而"这一单已经结束了"那两种根本没有记。`settleOffer` 自己按 id 去重，所以安卓宿主里那两处旧调用留着也不会记两遍。<br>**设备腿在安卓模拟器上跑过了**（`模拟器`，`.probe/a_145_leg.py` 连过三趟，原文 `.probe/a_145.txt`）：本机把同一份清单（**同一个 `offer_id`**）连投四遍，头两投都拿回 `200 {"accepted": false}` 而屏上始终只有一张卡（`.probe/a_145_card.png`：「有一个传输在等你决定」＋下面一行 `a145-145d.bin · 195.3 KB · 来自 DESKTOP-58TSA70`「等你决定」），在卡上点一次「拒绝」，第三、四投拿回的都是 `403 DECLINED`，卡一张也没有多出来（`.probe/a_145_answered.png` 上那张卡已经没了）。第二条腿只投一次、六十八秒里一个请求都不发，窗口到点自己收（屏上 0 张卡），之后两投还是 `403 DECLINED`——重发没有把用户叫醒第二次。两单都被拒，所以 `files/chuanshu-receive` 腿前腿后一样空。**鸿蒙那一端同一形状也跑过了**（两趟 `PASS`，见 §3.3 那一行末）——这一支两端各自有一份宿主代码，现在两端各自有一份屏 |
| 身份：设备名是用户改得了的那一项，改完 hello / 广播 / 清单都念新的，落在私有目录 `settings.json`（#146，合同 §1） | 完成 | `编译门`（`.probe/c146_android2.log`：`项目 chuanshu 编译成功。`。第一趟 `.probe/c146_android.log` 是红的：`store/session.uts:27` 报 `找不到名称"nameReject"`——**Android 的插件只保留入口抵达得到的名字**，`app-android/index.uts` 顶上那串 `export { … } from '../cs-protocol.uts'` 没带新名字，补进去就过；这条坑 §7 已经写着，是新名字忘了挂号）+ `浏览器`（规则与 hello 那一份副本见 §3.4 的第 15 组五条腿，`接收自检 71 项全部通过`）+ `浏览器`（`我的` 页那张卡真的按过一次：改名后头像那行、输入框里的草稿（空格被吃掉）和「已保存…」那一行同时换，填一串空格再按保存则三样都不动、那一行改口说「名字不能是空的」；这一趟是在 H5 上按的，所以档位是 `浏览器` 而不是 `模拟器`）。本端改了四处：`CsIdentity.kt`（`storedName`/`saveName`/`hardwareName`，`self()` 不再附 `name`——§1 那条规则只该有一份）、`app-android/index.uts`（`myName()` 组合两份、`deviceNameSave` 写文件后顺手刷掉 `recvSelf.name` 与 `discName` 那两份**已经抄出去的**名字）、`store/session.uts`（`renameSelf` 走共用 `nameReject`，写不进就不改屏幕）。名字不进指纹：对端钉的是密钥摘要，所以改名不需要重新配对。**安卓这一端现在对着屏跑过了**（`模拟器`，`.probe/a_146_leg.py`，原文 `.probe/a_146.txt`，截图 `.probe/a_146_saved.png` + `.probe/a_146_restarted.png`；§6 第 16 条因此了结）：改名前屏上三处都还是 `Build.MODEL` 那句「手机 · Google sdk_gphone64_x86_64」，`run-as` 读 `files/settings.json` 回 `No such file or directory`，PC 经 `adb forward tcp:43746 tcp:43720` 拨进来读 `GET /v1/hello` 拿到的也是那句；在 `我的` 页把输入框换成 `h146-renamed-phone` 并按保存，屏上三处一起换、下面那一行改口说「已保存：对端在 hello、广播和清单上读到的都是它」，`run-as` 读回 `{"device_name":"h146-renamed-phone"}`，PC 再读一次 hello 就是它——这一端刷的是**宿主自己那两份**（`deviceNameSave` 里直接改 `recvSelf.name`、顶掉 `discName`），与鸿蒙由 store 丢 `recvSelf` 的那一支是两处代码，现在各有一份屏。第二条腿 `am force-stop` 再拉起、中途一个键都不按：屏上三处仍是 `h146-renamed-phone`（**没有**回落成 `Build.MODEL` 那一句），而「已保存…」那一行已经不在了（那句活在内存里），所以这三处只可能来自磁盘上那个文件；文件还是它，hello 还是它，`指纹 eabb89ec30a4ccd1…` 那一行没动，TLS 递出来的叶改名前后都是 `f693be2bb977…`，最后**留空配对码**再配一次拿到 `resumed=True` |
| 收：接收中挂前台服务，挂不上时卡片自己说为什么（#143，`spec.md` §6） | 代码完成 + `模拟器`；**真挂上**要等自定义基座 | 落点是四处：`utssdk/app-android/CsKeepAlive.kt`（`Service` + 一个 `object`，`startForeground` 只在 API 34 带类型，读的是 `ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC`——合同 §6 原来写的 `dataTransfer` 是 14 预览期的叫法，正式版改名 `dataSync`，已用 HBuilderX 自带的 `android.jar` 逐字节查过那张常量表并把 §6 改口）、`utssdk/app-android/AndroidManifest.xml`（`android:foregroundServiceType="dataSync"`、`exported="false"`，组件只能进清单，代码里 `startService` 造不出一个 `<service>`）、`config.json` 补 `FOREGROUND_SERVICE`/`FOREGROUND_SERVICE_DATA_SYNC`/`POST_NOTIFICATIONS`、`app-android/index.uts::receiveHoldStart/receiveHoldStop`（13+ 那一句"要不要问"必须留在 UTS，运行时权限是 activity 上的 UI 线程调用）。**三件事都读设备、不假设**：`getServiceInfo` 抛 `NameNotFoundException` 就说明这个包的清单没带它，`checkSelfPermission` 少哪一项就报哪一项，`startForeground` 之后还要 `AtomicBoolean` 落定才算挂上——返回值走 `{ok, note}`，界面因此不需要匹配任何句子。`store/session.uts::armHold/disarmHold` 把结论写成卡片那一行（挂上=绿，挂不上=合同那句红字），关掉监听跟着收回。<br>证据：`编译门`（`.probe/c143_gates_final.log`：两道 `项目 chuanshu 编译成功。` + `运行包制作成功`）+ `模拟器`（`.probe/c143_device_legs.md`：标准调试基座 `targetSdk=32`、`POST_NOTIFICATIONS granted=false`，打开监听后卡片说「这台机器没让挂上保活（这个包的清单里没有保活服务这一项，所以保活挂不上：它要打进自定义基座才生效），退到后台可能被系统掐断：请保持传书在前台」，关掉后那行收回；`传输` 页日志同轮留着 `接收已打开…`/那句拒绝/`本来就没有保活挂着`）+ `浏览器`（接收 59 / 发送 17 / 发现 22 项全过，证明 store 那段条件编译没伤到 web）+ `截图`（`.probe/_c143_hold.png`：同一屏上「正在监听…」是绿的，下面那句保活拒绝是红的，开关在开位——挂上那句走的是同一个 `stateOk`）。**这一趟还真抓到一个只有设备能给的缺陷**：第一版按 `Build.VERSION.SDK_INT < 33` 决定要不要问通知权限，跑上去就在 `store/session.uts:997` 抛 `IllegalStateException: ... The targetSdkVersion SDK must be 33 or more`——问不问取决于**包**的 target 而不是系统的 API，现在读 `activity.getApplicationInfo().targetSdkVersion`（`mayAskNotify`）。至于"退到后台还收得到"这一条，只有把服务打进自定义基座才可能测（`pack --iscustom` 花用户的 DCloud 账号，等点头） |

### 3.3 HarmonyOS Next

| 功能点 | 状态 | 证据 |
|---|---|---|
| 身份：`@kit.CryptoArchitectureKit` 出 Ed25519 签名；服务叶仍是 RSA-2048 | 完成 | `真机`（平台 TLS 签不出 Ed25519 叶，这是上机才发现的） |
| 收：0x00 截断 → `X-Chunk-Escape` 转义、TLS 记录乱序到达仍解析得出、立即应答 + 轮询 | 完成 | `真机` + `模拟器`（#56/#59/#94/#61） |
| 收：对端已消失的 offer 不再谎报"还没收到分块" | 完成 | `模拟器`（#95） |
| 收：§3 那句「同一来源 5 次失败锁 60s」按**来源**计数（#162；共用状态机一直是对的，缺的是这一端递给它的号） | 完成 | `编译门`（`.probe/c162_harmony.log`：`项目 chuanshu 编译成功。` + `运行包制作成功`）+ `浏览器`（`接收自检 71 项全部通过`——锁 60 s 那三条腿都在共用状态机上，`cs-receive.uts::failCount/pushFail`）。改的是一个参数：`app-harmony/index.uts::dispatch` 原来交 `c.ip == '' ? c.id.toString() : c.ip`，地址还没读出来就把**连接序号**当成来源交了出去，而这一端的每条请求都开一条新连接，于是一个猜码的人每试一次都分到一格全新的 5 次额度——这把锁在这条路上永远填不满，屏上那句「配对码连错 5 次会锁 60 秒」在说一件不发生的事。现在交 `'?'`：一个还没落到手的地址就是"一个没人叫得出名字的来源"，全部记进同一格，安卓那一端（`CsServe.kt:236` 的 `?: "?"`）本来就是这样。共用状态机按 `client` 这个字符串分桶，它不认得任何一端怎么读地址，所以三个宿主各自交一个号；这条句子只有一份，落在哪一格由宿主说了算。细节见 §6 第 19 条 |
| 收：整文件摘要推翻台账时当场作废 + 写入不再拦"文件已经不在了" | 完成 | `模拟器`（#127 鸿蒙两条腿全 YES。第一条：落第一块后 `aa force-stop`，重启靠固定接管同一单，`接管以后的台账：received=1 missing=[1]`——没从 0 重写，收尾 `sha=6f25483fb457…` 逐字节一致。第二条：两块写完先不 finalize、杀掉、只删那个文件（`<offer_id>/` 目录留着，与 `a_127.py` 同形），手机自称 `received=2 missing=[]`，`finalize` 拦住并当场改口缺 `[0, 1]`，整单重发后 `verified_ok=True`、磁盘摘要仍是 `6f25483fb457…`。原文 `.probe/h_127.txt`。本端那一处改动是 `app-harmony/index.uts::storeWrite` 里的 `写入超出文件末尾` 拦截去掉了：续传写进一个已被删掉的文件走 `openSync(READ_WRITE \| CREATE)`，落回上一块之后的偏移，不是从零重写） |
| 收：一单一个目录，同名两单不互相截断 | 完成 | `模拟器`（#128 鸿蒙三条腿全 YES：第 1 单落 `files/chuanshu-receive/c090222556d40a5b/同名两单.bin`（`ef73ba275276…`），第 2 单送**同一个名字**另起一个目录 `23628597861315ff/`（`e4d4f54ad031…`），第 1 单那份摘要一个字没变；文件页同一屏上写着这个名字的 7 行里，标「已收到」的正好是这两行（195.3 KB 与 293.0 KB），计数行从「已验证 0 个（11 个已经不在了）」变成「已验证 2 个（11 个已经不在了）」。原文 `.probe/h_128.txt`。这一条不需要改鸿蒙本端：`app-harmony/index.uts::storePrepare` 本来就是先 `mkdirSync(parent, true)` 再 `truncateSync`，多出来的那一级目录是它已经会建的） |
| 收：一份清单里两个同名条目各落各的位置，后拿到的加 ` (2)` 后缀而不覆盖（#163，§5 第二句；鸿蒙没有第二份落盘代码） | 完成 | `编译门`（`.probe/c163_harmony.log`：`项目 chuanshu 编译成功。` + `运行包制作成功`，未配置签名证书故产物未签名，与之前几轮同一状态）+ `浏览器`（同一份 `cs-receive.uts`、同一趟 `接收自检 76 项全部通过`，见 §3.2 那一行）。这一端读 `land` 的位置和安卓一样：`landingOf(offerId, uniqueName(relpath, used))` 写进台账，`recv` 的写块、整文件摘要、卡片行与 `state` 回的 `path` 都从台账里取它 |
| 发：同单第二块不再写出几 KB 就停摆；串包（往正在关闭的连接里写字节）修掉 | 完成 | `模拟器`（#99/#121，全程无串包） |
| 发：同一单多个文件 + 中文子目录 | 完成 | `模拟器`（#125 鸿蒙腿：与安卓那趟同一批三份，PC 侧逐字节比对全对、目录层级保住；发送页三行都报到「对方已收下 3 个文件 / 5.00 MB」） |
| 发：接收方声明的节奏真用上，守卫那一支在有条节奏的对端上跑到过一次 | 完成 | `模拟器`（#62/#122：少写 139264 字节，重发整单落对） |
| 发：一写的回复没来时先问一次对方的 `state`，对方说没到就用剩下的次数重写那一块（#132，与 PC 的 #120/#130 同一条） | 完成 | `模拟器`（#133：`.probe/h_133.py` 与安卓那趟同一个对端、同一种注入，只是把节奏声明回 15 毫秒——安卓那趟声明的是 0（四 MiB 体一秒内落完），而两端都会照声明的节奏写记录（`CsWire.kt` 的 `PACE_LADDER`、`app-harmony/index.uts` 的 `paceFloor`），15 毫秒这一档是这一端一贯落得住整块的速度，用它就是为了保证账本里少掉的那次回复只可能是本机注入的。四条腿全 YES：`held` 写块 2 次 / state 1 次 / 落盘 `6f25483fb457` 逐字节一致；`blind` 写块 3 次 / state 仍 1 次 / 一致；`dead` 写满 3 次、问满 3 次就判死，屏上 `失败：协议错误：PROTOCOL 对端没答话` + `推送失败 0/2 块`；`mute` 体不收、那一问也不答 → `写块请求 1 次，state 询问 1 次（其中 1 次没答）`，一次就收口，不重写、不挂住。原文 `.probe/h_133_held.txt`、`h_133_blind.txt`、`h_133_dead.txt`、`h_133_mute.txt`。顺带量到一件事：回复被吞掉那一次之后，写入阶梯自己从 15 毫秒那一档爬到了 40 毫秒那一档（1024 条 TLS 记录花 18.3 秒≈每条 18 毫秒，其后 256 条花 11.1 秒≈每条 43 毫秒；`blind` 那趟被重写的那一块 44.3 秒也是 40 毫秒那一档），也就是说这条恢复支与 #130 的爬档是叠在同一条连接上跑的）+ `浏览器`（H5 那 14 项）+ `编译门`（`.probe/_h_gate_132b.log`；这一趟跑之前重新出过包，并验过 `chuanshu-probe-5mb` 那单走的 `cs-client.js` 里确有 #132 那句「对方说它已经有了」） |
| 发：取消两级（闭包注册表 `inflight` → `CANCELLED`，且不爬阶梯） | 完成 | `模拟器`（#124 鸿蒙腿五项全 YES。**#136 在 #132 之后重跑同一趟**，仍五项全 YES，这一趟守的正是 #132 新加的那一支：`status == 0` 现在会先问一次 `state`、问到"没到"还要重写那一块，而"本机按下了取消"不能被当成"回复没来"。守卫那一行自己说了它在写块中途收的手：`剩下的 1393344 字节不写了：这一单已经交出去了`，紧跟 `→ CANCELLED 收到 0 字节 用户按下了取消`，屏上 `失败：本机取消了这次传输 用户按下了取消` + `推送失败 0/2 块`，5.3 秒内收口；这一段的请求行里只有那一个 PUT，没有第二个写块、也没有多出来的 `state` 询问；第二趟节奏仍是 15 毫秒，对端 `offer 2 / 分块 2 / finalize 1`、落盘 `sha=6f25483fb457` 逐字节一致。原文 `.probe/h_124.txt`） |
| 失败原因的渲染：`detailOf` 读 `detail.reason`（+`detail.peer`），别的键才按原文出 | 完成 | `模拟器`（#126：同一条取消，鸿蒙这页从 `{"reason":"用户按下了取消"}` 变成整句，与 Android 一致；那一趟的五条判据仍全 YES。#134 又把 **A 级**那一句在这台机器上真按出来一次：对端每次都对清单回 `{"accepted": false}`，发送方因此每秒重投一次清单，投到第 11 次时按下取消——对端账本 `写块请求 0 次，真正收下 0 块，finalize 0 次，落盘 {}`（一个字节都没上过线，所以这一按必然是收回一条还没发出去的请求），3.2 秒后这页说 `失败：本机取消了这次传输 这一单还没发出去就被本机收回了`，整句、不带裸 JSON，六条判据全 YES，原文 `.probe/h_134.txt`，对端账本 `.probe/h_134_peer_pick.txt`） |
| 收：本机**拨出过**的对端不带配对码回拨时认成同一台（#141） | 完成 | `编译门`（`.probe/c141_harmony.log`：`项目 chuanshu 编译成功。` + `运行包制作成功`）+ `浏览器`（共用状态机那 59 项，见 §3.4）。鸿蒙这一端的地址钉在 `app-harmony/index.uts` 的 `chuanshu-trusted.json` 里，一行 `fp|host|port|peer_id|name|identity`（第 6 个字段是这次加的，`oneLine()` 早把 `|` 与换行剔掉，所以旧行读出来 `identity=''`）；`identityForAddress(host, port, declaredKey, declaredLeaf)` 先读第 6 格，读不到就照 §3 那条签名内的叶声明补一格，补完才交给 `adoptPin`。真正跑接收的是 `store/session.uts::harmonyReceive`（`#ifdef APP-HARMONY`），它过去把 `pinForAddress` 的叶直接当身份交出去——这一支就是那里的号错。**这一端的地址桥已经上机跑过**（`模拟器`，`.probe/h_154_leg.py`，2026-10-27，两台之间的对照腿与安卓那趟同一形状）：手机第一次拨出去那一趟把对端钉成 `…|10.0.2.2|43720|6578f3…|DESKTOP-58TSA70|e5fb55…`（第 6 格就是这次要读的身份摘要），PC 侧念的是「手机 · emulator（127.0.0.1）配上了」；然后由**同一把钥匙**（`app.cli receive` 那份身份目录）带空码从这台机器唯一那条进门的路（`hdc fport tcp:43745 tcp:43720`）拨回去——手机答 403 `BAD_PAIR_CODE`，PC 命令行翻成「对方不认识这把钥匙…用 --code 传给我」，`rc=1`，`files/chuanshu-receive/` 里一个字节都没有，`chuanshu-receiver-trust.json` 也没长出记录。**同一条路、同一把钥匙，只把码带上**就整趟走通：`pair` 收下（`resumed=false`）、清单在首页被按「接受」以后落定、200 000 字节进 `chuanshu-receive/7210e1b1bb2528e7/h154.bin`、本机 `hdc file recv` 读回来按同一条规则重算 sha256 逐字节一致（`size=200000/200000 一致=True`）。所以**拒的是地址，不是这条路**：`identityForAddress('127.0.0.1', 43720, …)` 读不到那条钉在 `10.0.2.2` 的记录，桥没接上——而这是这台模拟器的拓扑决定的，不是这一端的代码决定的：`h_154_src.py` 量到 `hdc fport` 给 guest 的来源永远是 `127.0.0.1:<临时端口>`，`h_154_slirp.py` 量到这台 DevEco 模拟器没有任何一条能在进门时把来源写成 `10.0.2.2` 的路（hdc 隧道在 guest 的 TCP 表里根本没有行，是 virtio；它只拨出不拨入）。于是**「桥接采纳」那半个正证在单台 DevEco 模拟器上构造不出来**，仍停在 `编译门` + `浏览器`，要等一台真局域网里的手机（§6 第 9 条）；安卓那一侧之所以能出正证，是因为它的控制台 `redir add` 恰好以 `10.0.2.2` 示人（§5 `a_149_src.py` 那一行） |
| 发：点中的局域网候选**先按前缀核对，再进 §3 配对**（#142，核对的位置由 #150 搬到套接字上） | 完成 | `编译门`（`.probe/c142_harmony.log`，#150 重跑：`.probe/c150_harmony.log`，两道都是 `项目 chuanshu 编译成功。` + `运行包制作成功`）+ `浏览器`（`发送自检 24 项`，E 组那几条腿）。这一支落的位置和安卓那一条是同一处——`store/session.uts::buildOptions` 把名单那一行的前缀交给共用的 `pinPrefix`；鸿蒙真正跑接收的 `harmonyReceive` 完全不经过它，所以本端没有第二份代码要改，但发的那一边有：`app-harmony/index.uts::httpRun` 在写完请求行**之前**用本地重述的 `pinAccepts` 判一次（这个文件不能 import `.uts`，规则只能抄一份并留指路注释），对不上就回 `TLS_PIN_MISMATCH` 并说清「广播里报的是 xxx…，这台在 TLS 上递出来的是 yyy…」。**设备腿已在模拟器上跑过**（`模拟器`：假 `fp` 那一趟停在「对端证书与要核对的指纹不符，已中止 广播里报的是 0badc0ffee000000…，这台在 TLS 上递出来的是 3b0108120c6000ee…」且对端一条请求行都没收到、真 `fp` 那一趟日志出现「已核对：…」且配对照常成，见 §3.4 末尾与 `.probe/h_150.txt`；那句判死的话在 #153 之后重读过一次，原文 `.probe/a_153_harmony.txt`——当时那一趟屏上还是「与**已固定的**指纹不符」，见 §6 第 17 条）。**#153 当时欠的那一格（鸿蒙×已固定）也补跑到了**（`模拟器`，同一台 `127.0.0.1:5557`：本机钉表上 `10.0.2.2:43731` 那条真是 64 位、对面换成一把新钥匙，屏上「对端证书与要核对的指纹不符，已中止 已固定 3b0108120c6000ee…，这台在 TLS 上递出来的是 b2abfbfb23a2323a…」，同一时间那一侧 TLS 监听自己说「handshake ok, 0 字节应用数据」——请求头一个字节都没写出去；对照腿同一端口摆对的证书，屏上「已连接 …（沿用旧指纹）」且对端读到 `GET /v1/hello` + `POST /v1/pair`，原文 `.probe/h_153_pin.txt`，见 §6 第 17 条）。§3.2 那行写的限制只剩一条：从名单点中到 `pinPrefix` 那条线在 `#ifdef APP-*` 里，浏览器走不到 |
| 鸿蒙 ↔ 鸿蒙 同端互传（两台模拟器） | 完成 | `模拟器`（#97） |
| 发现：`@ohos.net.mdns` + UDP 广播，名单接进既有连接流程 | 完成（模拟器） | `模拟器`（#91/#93/#115：`局域网设备` 卡片点一台就把 served-leaf 前缀填进连接卡；browse 不重发会静默，改成 9 s 一次） |
| 真机腿：#45 传输半边 / #46 收发 runbook | 待用户点头 | 唯一剩下的真机设备 `2UCUT23C27052382` 是用户的个人机（装了银行/学信网/税务），开机解锁需要本人同意 |
| UI 七页与鸿蒙 design 一致、density 恢复手机值 | 完成 | `截图`（#101/#102/#114 改口：那条"被裁掉"是探针点了视口外节点） |
| 协议 §7：版本按两个集合的交集判（#144） | 完成 | `编译门`（`.probe/c144_harmony.log`：`项目 chuanshu 编译成功。` + `运行包制作成功`）+ `浏览器`（`发送 20 / 接收 61 / 发现 22` 三项全过）。**本端没有第二份代码要改**：判据与集合都在共用的 `cs-protocol.uts` / `cs-client.uts` / `cs-receive.uts` 里（见 §3.2 那一行），`app-harmony/index.uts` 只负责把体里的 `compatible_versions` 原样递给状态机。发现那一条支仍在 `cs-discovery.uts` 里只比一个数——UDP 的公告只印得下一个版本，集合本身要等 hello，注释写在那里。**设备腿四条都在鸿蒙模拟器上跑过了**（`模拟器`，`.probe/h_144_leg.py` + 观察壳 `.probe/h_144_v2_recv.py`，原文 `.probe/h_144.txt` 2026-10-27 07:32–08:19 那几趟；跑的是**装着 `parsePairUrl` 那道改动的 hap**，改完重新出的包、重新装完再验的）。四格各自读到的是：一、手机发 → PC 收（接收方是本机出货的 `app.cli receive`，只把 `Protocol.intersects` 包一层打印它读到的东西）——`#144 OBSERVED pair/offer body: compatible_versions=[1] protocol_version=1 -> 交集非空=True` 在这一趟出现 **3 次**，5 MB 落 `.probe/h144_root/0e246ecc04ea5167/chuanshu-probe-5mb.bin` 逐字节一致，「verdict: PASS 手机发 → PC 收：PC 这一侧看得见它读了手机那份集合，5 MB 逐字节一致」；二、拨向一台只报 v2 的对端，两道门各停各的——A（配对串上就写着 `v=2`）「hello 0 次、pair/offer 0 次，说的是『配对信息读不出来：对端协议版本 v2 本机听不懂』」，B（串报 v1、hello 里才报 `[2]`）「hello 1 次、pair/offer 0 次，说的是『对端版本不兼容（对端 2）』」，「verdict: PASS 两道门各停在自己要停的那一关（A 不拨、B 拨了 hello 就没往下走），pair 一次都没发出去」；三、PC 发 → 手机收（手机在 `pair` 应答里重述它那份集合）——「本机从对端读到 compatible_versions=[1] … 交集非空=True」、「手机在 hello 里说的 protocol_version=1 compatible_versions=[1]」、「手机的 pair 应答 resumed=False … 它重述的集合=[1]」，200 000 字节经 `hdc file recv` 读回本机按同一条规则重算 sha256 逐字节一致，「verdict: PASS 两个方向都读得到对方那份集合（hello [1] / pair 应答重述 [1]），本机交集非空，200000 个字节逐字节一致」；四、同一把钥匙只报 v2 拨进去——手机回 `ProtocolError: UNSUPPORTED_PROTOCOL`、`应答已写出：400`、接收目录里什么都没有，「verdict: PASS 手机读得动本机那份集合，并且照 §7 判死了它（UNSUPPORTED_PROTOCOL，一个字节没落）」。**这一轮还补上了 §7 在手机这一端最后没实现的那半边**：`cs-protocol.uts::parsePairUrl` 过去把串上的 `v=` 和 `PROTOCOL_VERSION` 这一个数比，现在按 `versionsOverlap(COMPATIBLE_VERSIONS, [], v)` 问集合——配对串上那一个数就是它那份集合的全部，与 PC 的 `app/net/spec.py:215`（`proto.supports(int(v))`）同一条规则；这一改动在 `COMPATIBLE_VERSIONS == [1]` 时行为不变（`v=1` 照样过），A 那条腿就是它的正证。**顺带量到一屏上的缺口，也一起补了**（#157）：那道解析判死过去只往传输页的日志里写一句，按下「解析」的这一页不说话——与 #123 量的那次静默同一形状，当时探针把"屏上没话"读成"根本没拨出去"。现在 `applyConnectText` 走 `refuse()`（`log` + `s.sessionLabel`），成功那一路把上一次那句拒言清回「未连接」，A 那一趟在鸿蒙模拟器上因此读到「扫码页上说 | 配对信息读不出来：对端协议版本 v2 本机听不懂」（原文同批 08:13 那趟；改完两道编译门 `.probe/c157_harmony.log` / `.probe/c157_android.log` 都 `项目 chuanshu 编译成功。`）。发现那一条支仍在 `cs-discovery.uts` 里只比一个数——UDP 的公告只印得下一个版本，集合本身要等 hello，注释写在那里。§6 第 14 条因此了结 |
| 收：同一个 `offer_id` 只问用户一次（#145，与 PC、与安卓同一条规则） | 完成 | `编译门`（`.probe/c145_harmony.log`：`项目 chuanshu 编译成功。` + `运行包制作成功`）+ `浏览器`（`接收自检 66 项全部通过`）。**本端没有第二份代码要改**：记答案的五处都在共用的 `cs-receive.uts`（见 §3.2 那一行）。改之前鸿蒙这一头只记一种——用户在卡片上按的那一句由 `store/session.uts` 的 `receiveDecide`（`#ifdef APP-HARMONY` 那一段）补进 `settleOffer`，安卓对应的那一处在 `utssdk/app-android/index.uts`；而"这一单已经结束了"那两种（闲置回收、对方 `DELETE`）谁都没记，重发的清单于是会再弹一次卡片。<br>**鸿蒙这一端也对着屏跑过了**（`模拟器`，`.probe/h_145_leg.py` 两趟都 `PASS`，原文 `.probe/h_145.txt`）：本机经 `hdc fport tcp:43745 tcp:43720` 拨进这台正在监听的模拟器，`pair` 上了以后把**同一个 `offer_id`**（`4b5f660a`）的清单连投四遍——头两投都拿回 `200 {"accepted": false}` 而屏上始终一张卡（`.probe/h_145_card.jpeg`：「有一个传输在等你决定」＋「来自 PC-scratch-sender 的传输在等你决定」＋「接受／拒绝」两颗按钮），在卡上点一次「拒绝」（@ 945,1838），第三、四投拿回的都是 `403 DECLINED`，卡 0 张（`.probe/h_145_answered.jpeg`）。第二条腿（`2747aeea`）只投一次，然后这一支 68 秒里一个请求都不发，每 10 秒读一次屏（**读屏不是请求，代价是零**）：+10/20/30/40 秒都还是一张卡，+50 秒读到 0 张，之后两投还是 `403 DECLINED`。两单都被拒，`files/chuanshu-receive` 腿前腿后一字不差。第二趟还顺带读到一件事：`配对 | resumed=True`——上一趟留下的钉这一次被认出来了，同一条清单规则跑在一条已经配过对的关系上 |
| 身份：设备名用户可改，改完 hello / 广播都念新的，落在沙箱 `settings.json`（#146，合同 §1，与安卓同一条规则） | 完成 | `编译门`（`.probe/c146_harmony.log`：`项目 chuanshu 编译成功。` + `运行包制作成功`）+ `浏览器`（共用规则与 hello 那份副本的腿见 §3.4 第 15 组）。本端只有两处：`app-harmony/index.uts` 里 `deviceName()` 先读 `settings.json` 的 `device_name`、读不到才回落 `marketName`/`productModel`（§1 那个文件名保留合同的写法，不加 `chuanshu-` 前缀；`fieldOf` 已经够用，不需要 JSON 库），新导出 `deviceNameSave` 同步写文件；**刷副本的活儿落在 `store/session.uts`**——这一端的接收状态机跑在页面旁边（`harmonyReceive`），hello 用的 `recvSelf` 与公告用的 `discName` 都是 store 的变量，不像安卓宿主那样自带缓存，所以改名成功后由 store 把 `recvSelf` 丢掉（下一次请求照 `deviceNameText()` 重建，读到的就是刚写进去的那一个）并顶掉 `discName`。ArkTS 侧不能 import 同目录的 `.uts`，`nameWithDefault` 那两行只能在 `deviceName()` 里照写一遍——与 `TRANSPORT_PORT` 同一个理由。**鸿蒙这一端现在对着屏跑过了**（`模拟器`，`.probe/h_146_leg.py`，原文 `.probe/h_146.txt`，截图 `.probe/h_146_saved.jpeg` + `.probe/h_146_restarted.jpeg`）：改名前三处（头像那行、`设备名` 行末的值、输入框里的草稿）都还是那句硬件自己的话「手机 · emulator」，PC 经 `hdc fport tcp:43745 tcp:43720` 拨进来读 `GET /v1/hello` 拿到的也是它，`pair` 上了（`resumed=False`），而沙箱里这时候**还没有** `settings.json`（`hdc file recv` 回 `no such file or directory`）。在 `我的` 页把输入框换成「鸿蒙改名腿146」并按保存：屏上三处一起换，下面那一行改口说「已保存：对端在 hello、广播和清单上读到的都是它」，`/data/app/el2/100/base/com.chuanshu.app/files/settings.json` 读回本机是 `{"device_name":"鸿蒙改名腿146"}`（36 字节），PC 再读一次 hello 拿到的就是它——这一端 hello 那一份副本确实由 `store/session.uts::applySelfName` 丢掉、下一次请求照 `deviceNameText()` 重建。第二条腿 `aa force-stop` 再 `aa start`，中途一个键都不再按：屏上两处加草稿仍是「鸿蒙改名腿146」（**没有**回落成「手机 · emulator」），文件还是那 36 字节（sha `9325495bec4d…` 一字不差），而「已保存…」那一行已经不在了（那句活在内存里），所以屏上这三处只可能来自磁盘上那个文件；hello 还是它，`指纹 558f78d300672ac7…` 那一行没动，TLS 递出来的叶摘要改名前后都是 `30630f39ace7…`，最后**留空配对码**再配一次——`resumed=True`，对端名字那一句已经是新名字。名字改了、进程杀过又活了，旧钉照样认得这台 PC：§6 第 16 条鸿蒙那一格因此了结 |
| 收：§5 最后一条——写出前把路径一环一环核到底，中间那一环是符号链接就不许写过去（#148） | 完成 | `编译门`（`.probe/c148_harmony2.log`：`项目 chuanshu 编译成功。` + 同一趟 `运行包制作成功`；另有一道 `.probe/c148_android2.log` 干净缓存复跑，证明那半边的 `#ifdef` 没被伤到）+ `模拟器`（`127.0.0.1:10001`，`我的` → `平台能力探针` → 新加的那一个按钮，原文 `.probe/h_148.txt`：「还没收过东西时的接收根：none」→ 落过一个文件以后「dir」；新建出来的那一环「dir」；那个文件「file（要的是 file，不是 link）」；写进去的 8 字节读回来磁盘摘要 `9ac2197d9258257b…`，宿主机上 `sha256("ABCDEFGH")` 是同一个数；`_guard/deep/again.bin` 那种"中间还没建出来"的放行，续传才可能穿过一个刚被回收掉的目录；`../escape.bin` 拒掉；清场后 `_guard` 读回 none）+ `截图`（`.probe/h_148_guard.jpg`：那十行就在屏上）。**规则只有一份**，落点是 `app-harmony/index.uts::recvPath`——这一端把 relpath 变成磁盘位置的地方只有它，六个调用点（prepare / write / digest / drop / `storeFileExists` / 台账那一个）全从它走，所以守卫不必抄第二遍，也不可能漏一处。这一平台确实没有 `realpath`（`@ohos.file.fs.d.ts` 里查不到这个导出），安卓那句 `File.canonicalFile` 算完再比前缀在这里没有对应的调用，能问的只有 `lstatSync(path): Stat`（同一份 d.ts 第 1755 行，文档原话就是 "Obtains information about a symbolic link"）和 `Stat.isSymbolicLink()`（5056），于是 `noLinkBelowRoot` 改成**从接收根往下的一环一环问**：任何一环是链接，整条路径不作数；问到不存在的那一环就停——不在＝后面更不会在，prepare 那句 `mkdirSync(parent, true)` 负责把剩下的补出来。用 lstat 而不是 access 是这一条的关键：`accessSync` 跟着链接走，一个悬空的链接它正好答"没有这个文件"，于是写入会顺着那条链接出去。**拒绝链接那一支在这台机器上造不出来**，这一点也写进了屏上那一行：`fs.symlink` 从 API 11 起只对系统应用开放（还是那份 d.ts 的注释），而模拟器的 shell 是 uid 2000、连这个沙箱都进不去（`ls /data/app/el2/100/base/` 报 Permission denied，也没有 `su`）——所以那一支的证据到 `编译门` + 代码读为止，档位不往上编。另外把 `relOk` 顶上那句注释改了口：它说"这一平台没有 canonical-path 调用"是实情，但被读成了"§5 这一条做不到"，而做得到 |
| 后台限制的产品处理（#143 的另一半：这一端没有机制，只有合同要求的那句话） | 完成 | `模拟器` + `截图`（`127.0.0.1:10001`：监听开着时「我的」页那行「这一端没有后台保活，退到后台或锁屏可能被系统冻住：请保持传书在前台」，点掉监听那行跟着收回；`.probe/_c143_hold_harmony.jpeg` 里它是红的，与同屏那句绿色的「正在监听 43720…」并排。原文 `.probe/c143_device_legs.md`。这句话过去只在文档里，`pages/` 与 `store/` 里一个字都没有——写它的人把口径当成了实现） |

### 3.4 浏览器（H5 目标）

只承担一件事：**平台无关那一半能单独验**。接收状态机（`cs-receive.uts`）、发送状态机（`cs-client.uts`）、
发现模型（`cs-discovery.uts`）、页面路由与扫码/粘贴/发送/留空重连都在浏览器里跑过（`浏览器`）。
`utssdk/web/index.uts` 明说浏览器没有 `java.security`、也开不了 TCP，所以探针三个按钮在浏览器里的输出
**不是证据**；这个文件存在的唯一理由是 `import ... from '@/uni_modules/cs-identity'` 在非 App 平台也要解析得到。

页面那一半的证据是另一回事：#157 那句「配对信息读不出来：对端协议版本 v2 本机听不懂」在 2026-10-27 也在
这里对着屏重看过一次（`浏览器`，vite 5173 上 `#/pages/scan/scan`，往粘贴框填一条 `v=2` 的串、只按「解析」——
卡片下面一行就是那句话，而 `performance` 的资源表里一条指向那个地址端口的请求都没有，所以这一端同样是一个字节
都没往外写；原文 `.probe/a_157.txt`）。这一条之所以值得单记，是因为它改的正是**三端共用的那一份**
`store/session.uts`，浏览器是这三份屏里最容易重看的一块。

这一端跑的是 `我的` 页那三个内核自检按钮。收的那一条（`接收内核自检` → `store/session.uts::runRecvSelf` →
`web/index.uts::receiveSelfReport`），56 项断言全部由共用状态机 `cs-receive.uts` 作答。#128 把落点从
`relpath` 改成 `<offer_id>/<relpath>` 以后，这一趟按新的落点键重跑过一次：`接收自检 56 项全部通过`
（含「回收停摆清单不删同名收全的文件」「取消前文件已在收件箱里」「校验通过的文件带回落点」这几条直接踩在
`land` 上的）。原文在页面日志里，`.probe/launch_web_128.log` 是那一趟的编译门。

发的那一条是 #132 补的（`发送内核自检` → `runSendSelf` → `web/index.uts::senderSelfReport`），14 项断言，
四条腿都打在**手机共用的那份发送方** `cs-client.uts` 上，不是浏览器的替身实现：`connectPeer`/`sendFiles`
照原样调用，只有底下那层 `Caller` 换成了一个会按编号吞掉回复的探针。它喂的是同一件事——一块的体落对了、
回复在半路被吃掉；#133 之后这件事在设备上也能按需造出来了（见 §3.2 / §3.3 那两行），浏览器这一条剩下的
价值是快：四条腿一次跑完只要几秒，而设备上一趟要写满三个四 MiB 的体：

| 腿 | 喂进去的故障 | 判的是什么 |
|---|---|---|
| A | 吞掉第 1 块的回复，对端照常把字节收进自己的收件箱 | 这单仍然传成；为那块**只问过 `state` 一次**；对端只收到两次写块（问出来的那一趟没重写）；整文件摘要落到收到清单 |
| B | 吞掉第 1 块的回复，且对端说它没这块 | 也传成；仍只问一次；写块次数变 3 = 缺的那块重写了一次 |
| C | 每次都吞回复、且对端永远说没到 | 判死而不是挂住或死循环；判死前只写 3 次、问 3 次（一块最多三次写，合同 §4），报出去的是那一次的真实原因 |
| D | 吞掉第 1 块的回复、对端也没收字节，**且发送方为它问的那一次 `state` 也没人答**（#135 补的第四条腿，形状与设备上的 `mute` 同一支） | 判死；只问一次；**一次都不重写**（对端只收到 1 次写块）；报出去的是**那一问自己的错**而不是那次写的错 |
| E | 这一行广播的那个前缀**不是**对面这台在 TLS 上递出来的证书（#142 补的第五条腿，#150 把它挪到套接字上，直接调 `connectPeer`，不写文件） | **配对根本没发生**：请求行压根没出去（`hellosSeen == 0`），对方的固定名单还是空的（`inbox.trusted.length == 0`），判死那句话是「对端证书与要核对的指纹不符」（#153 之前是「与已固定的指纹不符」）而不是配对码的错；再拿一个对得上前缀的对照跑一遍，照常配对并传成，且那一趟**只放行了一次** hello；最后再加一条 64 位整摘要的对照——二维码那一种形状走的还是同一条规则 |
| F | 对端在 `hello` 里**不报** `compatible_versions`（`helloVersions = []`，即"这个字段之前的一版"）；再报一个**只含 v2** 的集合（#144 补的第六条腿，同一支注入器换值） | 前者照常配对传成——没报集合按它印出的那一个数判；后者**停在 hello**，且那一单一次 pair 都没打到对方的固定名单上 |

`发送自检 14 项全部通过`，同一趟重跑 `接收自检 56 项全部通过`（改 harness 不能把收的那半边碰坏）。
原文 `.probe/web_135_selftest.txt`，那一趟的编译门 `.probe/launch_web_135.log`。
#142 把第五条腿加进来以后是 `发送自检 17 项全部通过`（`.probe/c142_android.log` / `c142_harmony.log` 是同批的两道编译门），
但要说清这一条证到哪：E 腿打在**共用发送方** `cs-client.uts::helloPeer` 上，而"从名单点中的那一行把前缀交到
`pinPrefix`"这一步在 `store/session.uts` 的 `#ifdef APP-*` 里，浏览器根本走不到——那条线只有编译门。
#144 又把第六条腿（F）加进来，同一趟重跑的是 `发送自检 20 项全部通过`；收的那一边在 `receiveSelfReport` 里加了两条，
`接收自检 61 项全部通过`（原文 `.probe/c144_harmony.log` / `c144_android.log` 是同批的两道编译门）。这两条**故意打在
一个新建的隔离收件箱上**，而不是共用那一只：多出来的一个 pending 清单会把后面几条判据读的计数（`stateAll`、
`adopted`、`arrivalsAll`）顶歪——上一条错误要的是"这个 offer 被拒了"，不是"这一趟别人被拒过"。
判据是 §7 的两个方向各一条：清单报的集合里没有我们这一版 → `UNSUPPORTED_PROTOCOL`（400，`detail` 带 `peer_version`
与 `peer_compatible`）；清单压根没报集合 → **等人决定**（回的是 `pending` 那一形状，不是拒绝）。
`发现自检 22 项` 那一趟只证一件事：UDP 公告里本来就只有一个版本号，这一支没被改动碰坏。
#145 把收的那一边再加五条（`接收自检 66 项全部通过`，原文 `.probe/c145_web_selftest.txt`，同批两道编译门
`.probe/c145_android.log` / `c145_harmony.log`），也打在**另一只隔离收件箱**上——理由与上面那条一样：多一个挂着
没答的清单会把后面读的 `pendingOfferIds` 计数顶歪。这五条读的是 §4 那一问的三种答案：卡片还挂着时重发只回
"还没人决定"，而且**不占第二个待决名额**（`pendingOfferIds` 仍是那一条）；用户答过拒绝以后重发拿回同一句
`DECLINED`（403），并且不会再进一次决策；窗口到点没人答＝同一句 `DECLINED`（发送方那一头的超时本来也按
`DECLINED` 收，§4 后半句）；对方 `DELETE` 取消过的单重发＝`OFFER_UNKNOWN`（404）。这四条形状 PC 也在
`protocol_selftest.py` 里各有一条腿，外加一条"答案从问它的那条连接出来"（并发那一支：一个线程卡在决策回调里，
另一个线程在同一只服务上重投同一份清单）。
这四条腿在设备上各跑过一次同一支故障：A = `held`、B = `blind`、C = `dead`、D = `mute`，两台全 YES
（`a_133.py` / `h_133.py`，见 §3.2 / §3.3）。设备上 C 那条的机制略有不同——浏览器是"收下了但不答"，设备是"一个字节都不收
也不答"——发送方看到的都一样：没有回复，且 `state` 说没到。两台报出去的最后一句也各自是本平台自己的词
（安卓 `CONN_RESET Broken pipe`、鸿蒙 `PROTOCOL 对端没答话`），这正是 #132 那条判据只认 `status == 0`
、不认错误码字符串的原因。
`mute` 这一支判的是同一句合同的后半——「只有**问不到答案**、或尝试次数用尽，才把原来的错误抛出去」——的**前**
一种：一次都不重写，报的是那一次询问自己的错。安卓上它和 C 那条明显是两回事（`mute` → `PROTOCOL 对端没答话`，
`dead` → `CONN_RESET Broken pipe`，因为那一趟问到了答案、于是抛的是写本身的错）；鸿蒙上两趟的字面撞在一起（这一端
被拒的写与没答的问都落成 `PROTOCOL 对端没答话`），分开靠的是对端账本那一行：`mute` 写块 **1** 次、`dead` 写满
**3** 次。浏览器这一支与设备撞不上字面，是因为它注入的就是那句注入语（`自检注入：发送方来问这一块的账，这一问本机也不答`），
判据看的是"报出去的那句里带的是这一问"，不是错误码。
**不过这一支两端抛的不是同一句话**（#137 记下的口径分歧）：手机与 H5 报的是**那一问自己的错**，PC 报的是
**原来那次写的错**——合同那句的字面是「才把**原来的错误**抛出去」，PC 照字面做，手机在 #132 里做的是"哪一问没答案就报哪一问"，
理由是它对人说得更准（`对端没答话` 比 `Broken pipe` 更像发生了什么）。两条都满足这一支真正要守的东西——**一次都不重写**——
所以三份证据都算过；要不要把字面对齐（改合同那句的措辞，还是把 PC 也改成报那一问）留给 #138 定。
`我的` 页那个「吞一次回复」按钮（`pickSendFault('SWALLOW_REPLY')` → 演示对端 `demoPcSend`）是同一支故障的
手驱动版本，走的是屏上那套 UI 而不是探针：那一趟屏上打出
`PC：这一块的回复没来，但对方说它已经有了：/v1/offer/e71fe3bc9f4fbe55/chunk/beb0ef3355096750/0`，随后
`PC → 本机：完成 对方已收下 2 个文件 / 4.00 MB，最后落到 /模拟接收目录/e71fe3bc9f4fbe55/pc-大块.bin`。

**#146 那一轮把合同 §1 的另一半也在这端验了**：`name` 是身份五项里唯一「用户可改」的，而这一端是唯一能把这条规则
整套跑下来的地方。五条腿打在 `receiveSelfReport` 末尾（`接收自检 71 项全部通过`，原文 `.probe/c146_web_selftest.txt`，
同批两道编译门 `.probe/c146_android2.log` / `c146_harmony.log`）：没改名时 `GET /v1/hello` 的 `name` 就是这端自己的称呼
（浏览器 → `浏览器 · chrome`，安卓 → `Build.MODEL`，鸿蒙 → `marketName`，同一份 `nameWithDefault` 组合）、
空名字在**规则层**就被 `nameReject` 拒掉（压根不给写，所以 hello 上一个字没变）、写过的名字顶掉默认而空的才回落、
存进去时两端空格被去掉、把名字收回以后 hello 又回落。**判据看的是线上的那一句**，不是存储里的那一条：`name` 走的是
`cs-receive.uts::handleReceive` 的 hello 分支，配对回复与清单的 `from_name` 读的是同一个 `self`，所以这一趟证的
是"改一次，三处都跟着改"，而不是"改了一次、变量换了、没人读过"。
这一趟还在 H5 屏上把 `我的` 页那张新卡真按过两次：填 `  小字的安卓  ` 点保存，头像那行、输入框里的草稿（空格被吃掉）
和「已保存：对端在 hello、广播和清单上读到的都是它」同时换；填三个空格再点，那三样都不动，那一行改口说
「名字不能是空的：这台设备对别人总要有个称呼」——草稿与已生效的名字是两个状态，这一支就是为了让被拒的那次不把旧名字冲掉。
同一批的另一道门是红的过一次：安卓插件入口 `app-android/index.uts` 顶部那串 `export { … } from '../cs-protocol.uts'`
没把 `nameReject` 挂号，`store/session.uts:27` 直接 `找不到名称"nameReject"`——§7 那条"Android 的插件只保留入口
抵达得到的名字"对新加的名字同样成立，别只记得给 store 加 import。

**这一端的档位要说清楚**：`state` 那条恢复支在浏览器里是快而全的行为证据（14 项、四条腿、几秒跑完），
在两台手机上现在是 `模拟器`——#133 造了一个肯说真话的对端，四种喂法各上一趟，八条腿全 YES；编译门是另外两道
（`.probe/_and_gate_132b.log`、`.probe/_h_gate_132b.log`、H5 的 `.probe/launch_web_132.log` 与重跑第四条腿那趟的 `.probe/launch_web_135.log`）。
先前这里写过"一台真设备不会被按需制造出打嗝，所以 #132 不可能有上机复现"，那句是错的：造不出**管道自己**
的打嗝，但可以造一个会吞回复的对端，而合同 §4 那条支判的正是"回复没来"这件事本身。仍然没在设备上出现过的是
**自然发生**的那一次——目前只有 #130 在鸿蒙 40 毫秒下限上自己撞出来过一趟。身份那三个探针按钮在 H5 里
仍然不是证据，本节说的只有收发两台共用状态机。

**#150 把上面那条 E 腿的口径又改了一次**：核对的位置从 `helloPeer`（那读的是对方在 hello 里**自己声明**的 `served`，一个前缀本来就是
它广播出去的，偷到广播的机器照抄就行）搬到套接字上，判据收成一条 `cs-protocol.uts::pinAccepts`——整摘要比全等、更短的比
前缀、空钉放行（第一面由配对码带信任）、读不出证书永远不放行；Android 的 `CsWire.kt`、鸿蒙的 `app-harmony/index.uts`、
iOS 的 `CsWire.swift`（已终止，只读不跑）各重述同一条，因为宿主那三边都不能 import 一个 `.uts`；浏览器这一边由
`web/index.uts::pinnedCaller` 充当那只 socket，所以 E 腿现在的判据是 `hellosSeen == 0`（请求行压根没出去），另加两条
对照：对得上前缀那一趟只放行一次 hello、二维码那种 64 位整摘要走的还是同一条规则。同一趟 `发送自检 24 项全部通过`、
`发现自检 29 项全部通过`（3b 组七条腿打的就是这条规则本身），原文 `.probe/c150_web_selftest.txt`，同批三道编译门
`.probe/c150_web.log` / `c150_android.log` / `c150_harmony.log`。清单记账那一边也跟着换了来源：`markConnected` 补进名单的
完整摘要现在取自 `pinnedFor()`（传输自己在握手时写进钉表的那个数），不再取 `session.peerServed`——那个字段已经删掉了。
扫码页对用户说的那句话跟着改了（原来写的是"连上以后对一次"，现在写的是"拨过去的第一件事就在这条连接的 TLS 握手上，对不上就在这里断掉，
配对码根本不会发出去"），改了页面就得三道门全重跑：`.probe/c150b_web.log` / `c150b_android.log` / `c150b_harmony.log`
都是 `项目 chuanshu 编译成功。`，浏览器那三条自检在 `?fresh=150b` 上重跑仍是 71 / 24 / 29、124 条「通过 ·」零失败（原文同一份，末尾的追加段）。
**设备腿在鸿蒙模拟器上跑了一趟**（`127.0.0.1:10001`，档位 `模拟器`，原文 `.probe/h_150.txt`）。公告那一环走 mDNS：这台模拟器在
QEMU slirp 后面（eth0 `10.0.2.15/24`，网关 `10.0.2.2`），本机没有 `10.0.2.x` 的网卡，主机发的 UDP 广播进不去（照实试过，
页面自己说「两条通道都没听到设备」），而 slirp 会把 `224.0.0.251:5353` 反射进 guest——所以 `.probe/mdns_150.py` 手搓一条
`_chuanshu._tcp.local.`，地址填 guest 真拨得通的 `10.0.2.2`，TXT 里的 `fp` 由这一次运行决定。假的那一条（`fp=0badc0ffee000000`、
端口就是真监听的 43731、配对码与密码按真的填）屏幕上收在**「对端证书与已固定的指纹不符，已中止 广播里报的是 0badc0ffee000000…，
这台在 TLS 上递出来的是 3b0108120c6000ee…」**（这一句在 #153 之后重读过：同一趟现在印「对端证书与**要核对的**指纹不符」，见 `.probe/a_153_harmony.txt`），同一时间对端 `.probe/emu/recv.log`（DEBUG，请求行以 `http "` 打头）**一条请求行都没有**，
`netstat` 上只留下一个到 43731 的 TIME_WAIT——TLS 连接开了又关，配对码根本没发出去。那个 `3b0108120c6000ee` 正是这台监听的 TLS 叶
（`identity.served_fingerprint` 前 16 位），而它在 hello 里自报的是另一个数 `09947c0b…`（身份摘要）：这一趟把"核对发生在套接字上"
和"自报的值不参与定性"同时摆在屏幕上。把同一条记录的 `fp` 换成真前缀再点一次：卡片变成「已连接」，日志那一段依次是
「按广播里的指纹前缀钉住 10.0.2.2」→「对端 PC-probe-receiver fp=09947c0b52872289…」（照旧抄对方自报的那一句，只作记账）→
**「已核对：3b0108120c6000ee 这台机器在 TLS 上就是它自己（3b0108120c6000ee…）」**→「已连接 PC-probe-receiver（首次，已固定指纹）」，
对端同期拿到 `http "GET /v1/hello" 200` 与 `http "POST /v1/pair" 200`，随后 `INFO pinned peer 手机 · emulator (558f78d30067)`——
整份日志里只有这一条 `pinned`，也就是说假公告那一趟没在对端的固定名单里留下任何东西。**安卓那一边同一趟也跑过了**
（`模拟器`，2026-10-27，原文 `.probe/a_154.txt` 末段 + 截图 `.probe/a_154_card.png`：假公告由控制台 UDP 转发喂进名单，
点中、填真配对码与密码、按连接，屏上「对端证书与要核对的指纹不符，已中止 广播里报的是 0badc0ffee000000，收到 3ae1fc93c61c7b73…」，
对端那一段时间零请求行，只留 `SSLV3_ALERT_CERTIFICATE_UNKNOWN`；见 §5 的 `a_154_leg.py` 那一行与 §6 第 11 条），
真机两边都没跑（私人机锁着，未经同意不动）。这一支现在的档位：鸿蒙 `模拟器` + `编译门` + `浏览器`，安卓 `模拟器` + `编译门` + `浏览器`。

### 3.5 iOS（终止）

`utssdk/app-ios/` 的身份与传输两半边、NetService 那半边发现留在树里，不进任何验收，也不提议为它跑
`pack --iscustom`。#124 里 `app-ios/index.uts` 那一行 `cancelSend,` 只是保持文件之间一致；#150 里
`CsWire.swift::matchesPin` 同属这一类——它改的原因是共用的 store 现在会把 16 位前缀交给 `request`，那一处如果还按
整摘要比，那样一局每个请求都会被自己判死。**本机没有 Xcode，这一支连编译门都够不到，只有代码可读。**

## 4. 构建 · 部署 · 出包（可直接复制）

### PC（Windows）
```powershell
py -X utf8 scripts/protocol_selftest.py     # 合同 + 双向 + 路径清洗 + 恢复
py -X utf8 scripts/ui_selftest.py           # 图形界面流程（含设置窗口、多语言）
py -X utf8 scripts/cli_selftest.py          # 命令行八条子命令
py -X utf8 scripts/freeze_smoke.py          # 打完的 exe 冒烟
.\build.ps1                                 # PyInstaller → dist\ChuanShu + 安装包
```
跑之前先看 `netstat -ano` 与 owning pid：本机同时可能有 PyCharm 调试实例和已安装的
`D:\Program Files\ChuanShu\ChuanShu.exe` 都占着 43720，**不要为了腾端口去重启用户的进程**。

### PC（Linux / WSL）
```powershell
MSYS_NO_PATHCONV=1 wsl -d Ubuntu-24.04 -- bash /mnt/e/wowo3/scripts/linux_selftest.py  # 27 条断言；一次调用要跑完（/tmp 随调用消失）
bash build-linux.sh                                                                    # 直接在 /mnt/e 里建——只当脚本门，不当产物
```
最后那一条会和 Windows 的 `build.ps1` 抢同一个 `dist/ChuanShu`（两个 PyInstaller 都往那儿写，`--clean`
开机先删），所以两条不许同时在跑；真正要出货的 Linux 包走下面那个 ext4 脚本。
从 git-bash 调 `wsl` 时 `MSYS_NO_PATHCONV=1` 是必须的：不带它，`/mnt/e/...` 会被改写成
`C:\...\git\mnt\e\...`，命令当场报 No such file，而外层 shell 照样退 0（2026-10-26 踩过一次，别信 rc）。
```bash
# 产物那半：PyInstaller 必须在 ext4，不能在 /mnt/e
.probe/linux_build_real.sh   # 拷进 $HOME/csbuild 建，tar.gz 拷回 dist/
.probe/linux_smoke.sh        # 冻结包：CLI 四条腿 + WSLg 真屏那一趟
.probe/linux_receive.sh
```

### 手机（uni-app x，工程在 `mobile/chuanshu`）
```powershell
py -X utf8 mobile/scripts/check_protocol.py   # vendored 合同没被手改 + 契约没跑偏
& "F:\HBuilderX\cli.exe" compile app-android --project mobile/chuanshu --uni_module cs-identity
& "F:\HBuilderX\cli.exe" launch app-android --project E:/wowo3/mobile/chuanshu --compile true
& "F:\HBuilderX\cli.exe" launch app-android --project E:/wowo3/mobile/chuanshu --compile false --deviceId <serial>
& "F:\HBuilderX\cli.exe" launch app-harmony --project E:/wowo3/mobile/chuanshu --compile true --buildType debug
& "F:\HBuilderX\cli.exe" pack --project mobile/chuanshu --platform android --precheck true
py -X utf8 .probe/deploy.py --serial 127.0.0.1:5559    # 鸿蒙：build → install → start → 抓屏
```
三条口径：**`launch` 两条都以退出码 0 结束，无论成败**——只认日志里的 `编译成功` / `kotlin编译失败` /
`运行包制作成功`；`--file` 只能指 `.uts`，别拿它验页面；`pack --precheck` 不提交云打包不扣费，
`pack --iscustom` 花用户的 DCloud 账号，**要先问**。
第四条（2026-10-27 量出来的，安卓这一端）：**`--compile true` 就是"仅编译"，它不往设备上推任何东西**——
那一趟日志到 `ready in …ms` 就 `已停止运行`，屏上跑的还是上一版。真正上机的那一条是
`launch app-android --project … --compile false --deviceId <serial>`，判据是它自己那两行
`同步手机端程序文件成功` + `应用【chuanshu】已启动`，而且它**常驻不退出**（那就是运行会话，不是卡住），
所以要挂在后台。同一份改动只过了编译门就当"设备上也是这样"，是 #157 那一格拖了一天的原因。

### 模拟器
```powershell
E:\android-sdk\emulator\emulator.exe -avd chuanshu34 -no-window -no-audio -no-boot-anim -gpu swiftshader_indirect
E:\android-sdk\emulator\emulator.exe -avd chuanshu34b -no-window -no-audio -no-boot-anim -gpu swiftshader_indirect
```
序列号按可用控制台端口分配（`chuanshu34` 独占时是 `emulator-5556`，另一个也在时可能是 `emulator-5554`）——
**动手前先 `adb devices` 读实际序列号**，别抄文档。鸿蒙那台由 DevEco 的 Device Manager 起，
`hdc list targets` 空就意味着它掉了；掉的时候 `adb` 也一样，先确认设备在场再信 harness 里的"点不到按钮"。

## 5. 验证 harness 清单

### 仓库门禁（`scripts/`）
| 脚本 | 覆盖 |
|---|---|
| `protocol_selftest.py` | 合同镜像、七个端点、路径清洗（含中文目录）、多文件带目录、断点续传（含杀接收进程后 `reopen`）、整文件摘要推翻台账时台账作废（#127）、并发身份目录、节奏已在下限时的体中止只重写那一块（#130）、那一问也没人答时一次都不重写（#137）、§7 按两个集合的交集判版本 + 没报集合时按它印出的那一个数兜底，收发两个方向各两条腿（#144）、同一个 `offer_id` 重投清单只问用户一次——还挂着时回"还没人决定"、答过拒绝的回同一句、这一单已经结束的回 `OFFER_UNKNOWN`，八条腿（#145） |
| `ui_selftest.py` | 图形界面四页、接收确认弹窗、设置窗口、7 语言 |
| `cli_selftest.py` | CLI 八条子命令端到端（含 `receive` 的 offer 计时器） |
| `linux_selftest.py` | Linux 侧 27 条断言，Qt-free（stdout **和** stderr 都要读：发现通道写的是 stderr） |
| `freeze_smoke.py` / `window_pixels.py` | 打包产物冒烟、窗口像素验收（#119 改口后不再替别人的窗口报 PASS） |
| `i18n_sync.py` | 词条齐平与 `.mo` 编译 |
| `receiver_host.py` | 一台当对端的常驻接收器 |

### 端内自检（`我的` 页三个按钮，只有 H5 目标里跑得出结论）
| 按钮 | 判的是哪份共用代码 | 最近一次结论 |
|---|---|---|
| `接收内核自检` | `cs-receive.uts`（76 项） | `接收自检 76 项全部通过`（2026-10-27 #163 那一趟，原文 `.probe/c163_web_selftest.txt`：§5 的第二句补五条腿（5c 组），打在一只新建的隔离收件箱上——一单里两条 `relpath` 同名的清单先照样只问用户一次，然后两条各过自己的整文件摘要、落在两个不同名字上、后一条是 `同名-备忘 (2).txt`；71 → 76，前面那 71 项一条没少。同一趟改前读数（把 `uniqueName` 还原成 `return name`）是 `失败 3 项，通过 73 项`，所以这五条腿分得出两个版本。下一句是 2026-10-26 #146 那一趟，原文 `.probe/c146_web_selftest.txt`：末尾第 15 组五条腿走的是 §1 里唯一「用户可改」那个字段——没改名时 hello 念的是这端自己的称呼、空名字在规则层就被拒（压根不给写）、写过的顶掉默认而空的才回落、存进去时空格被去掉、收回以后又回落；66 → 71，前面那 66 项一条没少。#145 那一趟，原文 `.probe/c145_web_selftest.txt`：§4 那一问的形状补五条腿，也打在一只新建的隔离收件箱上——还挂着时重发只回"还没人决定"、重发不占第二个待决名额、答过拒绝的重发拿回同一句 `DECLINED`（403）、窗口到点没人答算同一句拒绝、对方取消过的单重发是 `OFFER_UNKNOWN`；61 → 66，前面那 61 项一条没少。上一趟是 #144：新增两条腿打在隔离收件箱上——清单报的集合里没有我们这一版 → `UNSUPPORTED_PROTOCOL`，清单没报集合 → 按它自己那一个数判、照样回 `pending` 等人决定；59 → 61。再上一趟是 #141：给 `adoptPin` 加了第五个参数（叶摘要）并补了三条腿——桥接交身份摘要留空码能 resume、只交叶摘要仍 `BAD_PAIR_CODE`、验签后同一条记录同时长出密钥与叶；56 → 59。#150 那一趟（`.probe/c150_web_selftest.txt`）重跑仍 71 项全通过——那一批改的是发的那一边和 `pinAccepts` 这条规则，收的这半边没动） |
| `发送内核自检` | `cs-client.uts`（24 项：四条吞回复的腿 + 第五条"先核前缀再配对"的腿 + 第六条"版本集合"的腿，见 §3.4） | `发送自检 24 项全部通过`（2026-10-26 #150 那一趟，原文 `.probe/c150_web_selftest.txt`：E 组换了口径并加了三条对照——核对搬到套接字上以后，判死那一单**连 hello 都没打到对方**（`hellosSeen == 0`）、那句错话是「证书与钉不符」而不是配对码的、对得上前缀那一趟整程只放行一次 hello、再加一条 64 位整摘要（二维码那一种）照常放行的对照；20 → 24，前面那 20 项一条没少。#144 新加 F 腿：对端在 hello 里不报集合→照常传成，报一个只含 v2 的集合→停在 hello 且对方名单里多不出那一条；17 → 20。`.probe/launch_web_135.log` 是补上第四条腿那一趟的编译门，原文 `.probe/web_135_selftest.txt`；#142 那趟的编译门是 `.probe/c142_android.log` / `.probe/c142_harmony.log`） |
| `发现内核自检` | `cs-discovery.uts`（29 项） | `发现自检 29 项全部通过`：喂合成报文，验名单合并/过期/自过滤，不验网卡。#144 里这一支只把版本常量收回成共用那一份（`cs-protocol.uts` 的 `COMPATIBLE_VERSIONS`）——UDP 公告只印得下一个版本号，集合要等 hello 才取交集。#150 在这里加了 3b 组七条腿，打的是 `pinAccepts` 这条规则本身（整摘要全等且不比大小写、整摘要不认"只是开头相同"的那一台、前缀认它开头那一段、前缀对不上就是另一台、读不出证书不是放行、空钉是第一面）；22 → 29 |

这三条都在浏览器里跑，所以档位只到 `浏览器`：它们证的是**平台无关那一半**，不代表某台设备的 socket 行为。
编译门是另外两道，各编一次：`.probe/_and_gate_132b.log`（Kotlin）、`.probe/_h_gate_132b.log`（ArkTS）；
#144 那一批改的是共用 `.uts`，所以两道都重跑过：`.probe/c144_android.log`、`.probe/c144_harmony.log`。
#150 那一批把规则同时写进了宿主那三边（`CsWire.kt`、`app-harmony/index.uts`、`CsWire.swift`），所以三道门都重跑：
`.probe/c150_web.log`（H5）、`.probe/c150_android.log`、`.probe/c150_harmony.log`；**iOS 那一支只有代码可读，本机没有
Xcode，够不到任何一档编译门**——它改的原因只是共用的 store 现在会把 16 位前缀交给 `request`，整摘要比较会把那样一局
的每一个请求都判死。改了 `pages/scan/scan.uvue` 那句对用户的话以后三道门再各跑一遍（页面属于所有端）：
`.probe/c150b_web.log`、`.probe/c150b_android.log`、`.probe/c150b_harmony.log`，三道都是 `项目 chuanshu 编译成功。`，
鸿蒙那道另有 `运行包制作成功`（未配置签名证书，产物未签名，与之前几轮同一状态）。

### 设备侧（`.probe/`，命名规则 `a_*` = Android、`h_*` = 鸿蒙、`*_peer.py` = 造出来的对端）
| harness | 判的是什么 | 最近一次结论 |
|---|---|---|
| `h_122_peer.py` | **共用探针对端**：按 `chunk_pace_ms` 发节奏、可选首块早拒、记 `chunk_heads` / `chunk_secs` / `broken` | 被 `a_122/123/124`、`h_122/124`、`a_133`/`h_133`（后两个把它的 `send_reply` / `read_body` 换成吞回复与丢体）、`a_134`/`h_134`（把 `send_reply` 换成「清单永远不表态」）复用 |
| `a_106.py` | 手机发 → PC 收 | `PASS 逐字节一致（5 MB / 2 块）` |
| `a_110.py` | 收过的文件被删掉后卡片怎么说 | 清单仍保留那一行并说自己不在 |
| `a_115.py` | PC 发 → 手机收（真指纹、5 MB） | `一致=True`，落到 `files/chuanshu-receive/` |
| `a_116.py` | 两台 Android 互传（双向），也是 `Phone` 类的出处 | `size=5242880 sha=6f25483fb457ffa0 期望=… 一致=True` |
| `a_123.py` | 连接按钮拒掉填错的配对串时，扫码页自述拒因 | 三条腿（小写密码拒 + 合法密码连得上 + `v=2` 停在解析、一个 hello 都不发）。**一条腿一趟进程**：2026-10-27 推上新 bundle 后三条各自单跑一遍，全 `YES`——leg1 `.probe/a_157_both.log`（那一趟是 `both`，只有它的**第一条腿**算数）、leg2 `.probe/a_157_leg2.log`（「已连接 探针对端（首次，已固定指纹）」＋对端 `hello 1 / pair 1`）、leg3 `.probe/a_157_android.txt`（点击轨迹 `.probe/a_157_walk_android.txt`）。同一趟里第二条腿起 `fill()` 就只进得去 0/122 字符（有一回框里留着 745 字符），所以 `both` 报的 `(没读到)` 不能当产品结论——见 §6 第 18 条。第三腿的形状是 `press_connect=False`：§7 那道解析门**必须**停在按钮之前，所以探针只按「解析」，判据是屏上那句话 **加上** 对端 `h_122_peer.py` 的 `hello/pair` 计数器一动没动——只看屏上那句话会替"拨了但被拒"报 PASS |
| `a_124.py` | 取消两级在 Android 上的两个 leg | `PASS`（leg1 半块断掉 + leg2 重发逐字节一致、15 ms 档没爬。2026-10-26 在 #132 之后的发送方上重跑，仍 `PASS`，原文换成了那一趟的 `.probe/a_124.txt`——#136 要验的就是这条腿没被 `putChunk` 的新支带跑） |
| `a_125.py` / `h_125.py` | 一次 offer 带三个文件、其中两个在中文子目录里（一块整 4 MiB / 零头 1023 B / 1 MiB 带空格与括号） | 两条都 `PASS`：`三份都落对 YES / 目录层级保住 YES`（原文 `.probe/a_125.txt`、`.probe/h_125.txt`） |
| `a_127.py` / `h_127.py` | 接收途中杀掉手机进程：接管续传 + 台账作废两条腿 | 两条都 `PASS`：安卓 `杀掉接收中的手机：续传把尾巴补齐，而结论仍然只由整文件摘要给`（四条判据全 YES，原文 `.probe/a_127.txt`），鸿蒙同一条 verdict 四条也全 YES（原文 `.probe/h_127.txt`；那一趟还顺手量出 #130——4 MiB 体在 40 ms 下限被 fport 连吐三次，第四次整块落对） |
| `a_128.py` / `h_128.py` | 两单送**同一个名字**：每单是否落在自己的目录里，后一单有没有碰前一单已校验的字节 | 两条都 `PASS`：安卓 `手机一单一个目录：后一单同名文件不再顶掉前一单已经校验过的字节`，鸿蒙 `鸿蒙收：一单一个目录，同名两单各留各的字节`（原文 `.probe/a_128.txt`、`.probe/h_128.txt`） |
| `a_133.py` / `h_133.py` | 发送方那条恢复支的设备腿：造一个**会说真话**的对端，四种喂法——`held`（体收下、回复吞掉）、`blind`（体一个字节都不收）、`dead`（每块都吞、每回都不答）、`mute`（体不收、那一次 `state` 也不答） | 八条腿全 `PASS`。判据是对端自己的账本：`held` 写块 2 次 + state 1 次 + 逐字节一致，`blind` 写块 3 次 + state 仍 1 次 + 一致，`dead` 写满 3 次 + 问满 3 次 + 一块都没落下 + 屏上报失败而不是挂住，`mute` 写块 **1** 次 + 问 1 次且那问没人答 + 报的是那一问的错（原文 `.probe/a_133_held.txt` 等八份，对端账本 `.probe/*_133_*_peer.txt`） |
| `a_134.py` / `h_134.py` | A 级取消那一句的设备腿：让对端**只回答"还没决定"**（`POST /v1/offer` 每次回 `{"accepted": false}`，与手机端接收方自己没决定时答的是同一句），发送方就每秒重投清单，趁这一秒一秒之间点屏上的「取消」 | 两条都 `PASS`，各六条判据全 YES：安卓 `清单进来 8 次 / 写块请求 0 次 / 5.3 秒收口`，鸿蒙 `清单进来 11 次 / 写块请求 0 次 / 3.2 秒收口`，两台屏上都是整句 `失败：本机取消了这次传输 这一单还没发出去就被本机收回了`、都不带裸 JSON（原文 `.probe/a_134.txt`、`.probe/h_134.txt`） |
| `a_149_src.py` | **量路的探针**：宿主机拨进 Android 模拟器这两条门，guest 看到的来源地址各是什么（控制台 `redir add tcp:` 与 `adb forward` 各试一次，读 guest 的 `netstat -tn` 与 `/proc/net/tcp`） | 量出来定死了 #149 那条腿能不能在一台 AVD 上跑：控制台 `redir add tcp:43740:43720` 让 guest 读到的来源是 **`10.0.2.2`**（正是这台手机拨出去时用的那个地址），`adb forward` 让 guest 读到的是 `127.0.0.1`。`app-android/index.uts::recvHandle` 按 `pinFor(req.client, 43720)` 认人，所以前者命中地址桥、后者必然走陌生人分支——后面那一颗就是对照腿 |
| `a_149_leg.py`（观察壳 `.probe/a_149_send.py`，PC 侧身份在 `.probe/a_149_pcdata`） | #141 那条留空码回拨的设备腿，四段：`recv` 起本机出货的 `app.cli receive --port 43720` → `pair` 清空两个信任文件后让手机第一次拨出去（把对端的叶钉在 `10.0.2.2:43720`）→ `send` 让**同一个出货命令行**不带配对码拨回来 → `send --control` 把回拨的门从 `redir` 换成 `adb forward`，其余一个字都不改 | 两条腿在**同一份干净状态**上跑完（原文 `.probe/a_149.txt` 末两段，2026-10-27 04:34 / 04:37）。对照腿 `rc=1`：线上仍是 `{"code": "", "secret": null, …}`（`pair() got code='' secret='' (trusted=True)`），手机上落不到任何东西，PC 读到的是 `对方不认识这把钥匙。把它屏幕上那 6 位配对码用 --code 传给我`。正腿 `rc=0`：同样一份请求体，`app.net.send` 记的是 `paired with 手机 · Google sdk_gphone64_x86_64 (resumed=True)`，屏上「手机在「首页」页答了接受」，200 000 字节落 `files/chuanshu-receive/56fd1a68d956ee6b/a149.bin`、`size=200000 一致=True`；落完再看钉表，那条从地址桥采纳进来的记录已经长出了 `public_key`。**这一对立了两条 harness 规则**：一、要在 AVD 上复现"对端用它拨出去的那个地址回拨"，门是控制台 `redir add tcp:<host>:43720`（它以 `10.0.2.2` 示人），不是 `adb forward`；二、手机把信任存**两处**——拨出时的 `chuanshu-trusted.json`（带地址）和收过别人之后的 `chuanshu-receiver-trust.json`（只按身份摘要），后者一旦记下这台 PC，`pairReply` 就从**任何地址**都答 `resumed`，跟地址桥再无关系；第一次的对照腿就是这么假通过的。所以每一趟拨号前都打印两份表，对照腿必须从"收的一边"为空的状态出发，并在拨号前关掉 `redir` |
| `h_154_src.py` | **量路的探针（鸿蒙侧）**：本机起 `app.cli receive` 之前先按产品的方式把监听立起来，再用唯一那条从宿主机进 guest 的路 `hdc fport tcp:43745 tcp:43720` 握一条连接，读 guest 的 `netstat -tn` 与 `/proc/net/tcp` | 量出来定死了 #154 那条腿在一台 DevEco 模拟器上能跑到什么程度：`hdc fport` 让 guest 读到的来源是 **`127.0.0.1:52404 → 127.0.0.1:43720`**（`/proc/net/tcp` 里 remote 就是 `0100007F`），而这台手机拨出去时看到的对端是 `10.0.2.2:43720`。`store/session.uts::harmonyReceive` 按 `identityForAddress(req.client, 43720, …)` 认人，来源是 `127.0.0.1` 就永远读不到那条钉在 `10.0.2.2` 的记录——所以这一趟只能出对照腿，出不了正腿（原文 `.probe/h_154.txt`） |
| `h_154_slirp.py` | 接着问第二句：这台 DevEco 模拟器有没有一条 slirp 端口转发，能在进门时把来源写成 `10.0.2.2`（像安卓控制台 `redir add` 那样） | 没有。hdc 那条隧道在 guest 的 TCP 表里**一行都没有**（跑 hdc 流量时 5555 上没有行，宿主机直连 `127.0.0.1:5557` 也没有）——它是 virtio 而不是 slirp 转发；`Emulator.exe` 只在 `127.0.0.1:5557` 监听，guest 侧只有**拨出去**的连接（`10.0.2.15:* → 外网`）。被排除的三条路也记在这里：`hdc rport tcp:43720` 与 app 自己那个 `0.0.0.0:43720` 抢同一个端口、而且挡的是回调那条腿；两台模拟器互拨拨到的是自己的 loopback；宿主机路由不到 `10.0.2.15`。原文 `.probe/h_154_slirp.txt` |
| `h_154_leg.py`（观察壳沿用 `.probe/a_149_send.py`，PC 侧身份在 `.probe/h154_pcdata`） | #141 那条留空码回拨的**鸿蒙**设备腿，五段：`recv` 起本机出货的 `app.cli receive --port 43720` → `pair` 打印两份信任表（这里的 shell 读得动沙箱但删不动，SELinux `u:r:sh:s0`；所以它**要求**"收的一边"本来就是空的，不空就停）后让手机第一次拨出去 → `callback` 用同一把钥匙带空码从 `hdc fport` 拨回来 → `road` 走同一条路、同一把钥匙，只把手机上读到的配对码带上（这一段不走 `app.cli send`：本机已经固定过对端时 `transfer` 走 resume 分支，`--code` 根本上不了线，见 `app/net/send.py:499`，所以自己 `pair(code, secret)`）→ `stop` 收尾 | 三条腿跑完（原文 `.probe/h_154_leg.txt`，2026-10-27）。`pair` `rc=0`：钉表长出 `…|10.0.2.2|43720|6578f3…|DESKTOP-58TSA70|e5fb55…`（第 6 格是身份摘要），PC 念「手机 · emulator（127.0.0.1）配上了」。对照腿 `rc=1`：线上 `{"code": "", "secret": null, …}`、手机答 403 `BAD_PAIR_CODE`、`files/chuanshu-receive/` 空的、`chuanshu-receiver-trust.json` 没长记录。路腿 `rc=0`：`resumed=false` → 首页按「接受」 → 200 000 字节进 `chuanshu-receive/7210e1b1bb2528e7/h154.bin`，`hdc file recv` 读回本机重算 sha256 `size=200000/200000 一致=True`。**这一行把安卓那两条 harness 规则原样搬过来，另加一条**：一、对照腿必须从"收的一边"为空出发（`pairReply` 一旦按身份摘要记下这台 PC，就从任何地址都答 `resumed`）；二、路腿要放在所有会收的腿之后；三、路腿要用**同一份身份目录**（`<APPDATA>\ChuanShu\ChuanShu\identity`，不是 `load_or_create(PCDATA)` 那把新钥匙）——带着一把别的钥匙拨进去，先撞上的是 §3 单会话名额的 `PEER_BUSY {reason:'one peer at a time', peer:'e5fb55e5a145a008'}`（`cs-receive.uts:817`，名额由 `store/session.uts:704` 的 `holdSlotFor` 在拨出时占住），那一句会被当成地址桥的结论读，其实它证明的是另一件事：**这台手机把"我拨出去过的那一台"也算进名额** |
| `a_145_leg.py`（PC 侧身份在 `.probe/pc145`，源文件 `.probe/a145src/`） | #145 的设备腿：本机对着一台正在监听的安卓模拟器，把**同一个 `offer_id`** 的清单连投几遍——绕开 `offer()` 那个轮询循环、自己 `POST /v1/offer`，每一投之间读一次屏上卡片的张数 | 跑到（`模拟器`，连过三趟，原文 `.probe/a_145.txt` + 截图 `.probe/a_145_card.png`、`.probe/a_145_answered.png`）：窗口里重投＝`200 accepted:false` 且卡还是一张（不是两张）；点一次「拒绝」以后两投＝`403 DECLINED` 且卡为 0；另一条只投一次、68 秒不投，卡自己没了，再投两投还是 `403 DECLINED`。**这一行立的 harness 规则有两条**：一、判据是"屏上卡片的张数"，而 `uiautomator dump` 一次 4–8 秒，所以腿 1 从第二投到点下「拒绝」要压在 60 秒里——先 dump 一次拿到按钮坐标再盲点，不要在窗口里滚动找它；二、**屏上那一读自己会把窗口收掉**：`receiveSnapshot()` 里带着一次 `sweep()`，而 `store/session.uts::recvTimerTick` 是 1 秒一次的兜底 ticker（`initReceivePanel` 在第一个页面挂载时就开），所以"到点没人答"不需要对端再发一个请求就会落定——测这一支时不能拿"屏上还有卡"当"窗口还开着"的证据，反过来 68 秒后读到 0 张也不说明有人答过 |
| `h_145_leg.py`（PC 侧身份在 `.probe/h145_pcdata`，源文件 `.probe/h145src/`，门是 `hdc fport tcp:43745 tcp:43720`） | 同一形状搬到鸿蒙那一端：绕开 `offer()` 的轮询循环、自己 `POST /v1/offer` 带固定 `offer_id`，每一投之间用 `uitest dumpLayout` 数一次屏上的卡头（`有一个传输在等你决定` 逐字匹配才算张数，因为「最近传输」那一行也带「等你决定」四个字） | 两趟都跑到 `PASS`（`模拟器`，原文 `.probe/h_145.txt`，截图 `.probe/h_145_card.jpeg` / `h_145_answered.jpeg`）。**这一行立的 harness 规则有三条**：一、**每一读屏之前先 `power-shell wakeup`**——第一趟在腿 2 中段断了（读到 0 张、投出第二投以后就没往下走），当时没留下原因；现在 `__main__` 那一层把 traceback 写进 trace（一条腿半路死了，死因得在证据里，不在猜测里），第二趟每次读屏前先唤醒，同一段路走通了。**这一条按"疑似熄屏后 `dumpLayout` 拿不到树"记，不是量出来的结论**——两趟之间唯一的差别就是那一次唤醒，而死了的那趟没留话。二、卡数按"每一次 dump 各自数"读，配合 §5 规则③ 的滚动扫法（读不到就先滚一下再读，最多四轮），所以 `0 张` 是"滚过也没有"而不是"这一屏没显示"；三、腿 2 每 10 秒读一次屏是**免费的**（读屏不给对端发请求，窗口不会被推着走），于是这一趟能说出卡是在 +40 到 +50 秒之间消失的，而不是只说"68 秒以后没了"。**没读到的一格照实记**：那一趟想顺带读手机自己在传输页记的那一句（`DECLINED（403）`），两趟都是空列表——那本账在页面下方，用的还是单次 dump，没套滚动扫；判据不靠它（卡数 + 每投的状态码），但那一格仍是 `未测` |
| `h_146_leg.py` + `a_146_leg.py`（PC 侧身份在 `.probe/h146_pcdata` / `.probe/pc146`，门是 `hdc fport tcp:43745 tcp:43720` 与 `adb forward tcp:43746 tcp:43720`） | #146 的设备腿：在 `我的` 页把这台设备的名字改掉并按保存，一次读**四处**（头像那行、`设备名` 行末的值、输入框里的草稿、下面那一行说的话），再读沙箱里的 `settings.json`（鸿蒙 `hdc file recv` 落回本机、安卓 `run-as cat`），再让 PC 读一次 `GET /v1/hello`；然后杀进程重开、一个键都不按，把上面这一串再读一遍，最后**留空配对码**再配一次 | 两端都 `PASS`（`模拟器`，原文 `.probe/h_146.txt` / `.probe/a_146.txt`，截图 `.probe/h_146_saved.jpeg`、`h_146_restarted.jpeg`、`a_146_saved.png`、`a_146_restarted.png`）。**这一行立的 harness 规则有三条**：一、**重开以后「已保存…」那一行会自己消失**（`s.nameMsg` 活在内存里），所以腿 2 屏上剩下的三处只可能来自磁盘——"这个名字活得过一次重启"这一句在屏幕上因此是可证的，而不是靠"看着还是它"。二、**`adb shell input text` 打不了中文**，所以安卓那一趟用的是 ASCII 名（`h146-renamed-phone`），中文那一形状由鸿蒙那一趟证（`hgui.setfield` → `uitest inputText`，「鸿蒙改名腿146」）；清字段沿用 a_154 那条：点进去 → `keyevent 123` → 连打 60 下 `67` → 再 `input text`。三、**重开那一支不要再走 `A.announce`**——第一趟就死在这段路上（重开 19 秒时「扫码连接」那张卡还没排版出来，`p.home()` 扑空；产品侧一个字没错，那一趟的腿 1 已经 `PASS`，原文留在 `.probe/a_146_run1.txt`）。重启不换钥匙也不换叶，所以第二趟照 leg 1 那份公告重建串，而"还是不是原来那台"改由 `served_leaf()` 与 `verify_peer` 在套接字上各自核一遍——那才是这句话的证据，不是它自己再念一次公告 |
| `a_144_leg.py` + `a_144_recv.py` | #144 的那一趟手机发 → PC 收：接收方是**出货的 `app.cli receive`**，只把 `app/net/spec.py::Protocol.intersects` 包一层，把它从体里读到的 `compatible_versions` 与交集结果打印出来 | 跑到（`模拟器`，原文 `.probe/a_144.txt`）：两次观察（`pair` 与 `offer`）都是 `compatible_versions=[1] protocol_version=1 -> 交集非空=True`，5 MB 落 `.probe/a_144_root/b537096fdc92f54c/chuanshu-probe-5mb.bin` 逐字节一致，手机屏上「完成：对方已收下 1 个文件 / 5.00 MB」。**这一行立的 harness 规则是"判成功不吭声的地方要自己造一只眼"**：`intersects` 返回 True 时产品代码一行日志都不写，所以"PC 读到了手机那份集合"这句话只能由一次带观察器的真跑来支撑，不能由源码读一遍来支撑 |
| `h_144_leg.py` + `h_144_v2_recv.py`（PC 侧身份在 `.probe/h144_pcdata`，接收根 `.probe/h144_root/`） | #144 在鸿蒙上的四格：`recv`/`send`（手机发 → 出货的 `app.cli receive`，同样只把 `Protocol.intersects` 包一层）、`v2`/`reject_send`（本机起一台**只报 v2** 的替身，手机拨过去看它停在哪一关）、`road`/`reject_road`（PC 发 → 手机收，收的方向；后者在把清单发出去**之前**把本机那份声明换成 `[2]`） | 四条都 `PASS`（原文 `.probe/h_144.txt`，见 §3.3 那一行末）。这一轮立的 harness 规则，一条比一条贵：**①"没拨出去"要有另一只眼证明**——第一版只按屏上那句话判，A/B 两趟长得一样，于是报了个假 PASS；现在替身自己数 `#144 HELLO answered: …` 与 `#144 OBSERVED pair/offer body: …`，A 必须是 hello 0 次、B 必须 ≥1 次，否则那句"停在版本这一关"不认。**②"这一趟新加了哪一句"要先冷启动**——`s.lines` 是内存里的账，跨趟不清，同一句「听不懂」上一轮就写过，于是"新加"永远是 0；`restart_app()`（`aa force-stop` + `aa start`）写在每一趟开头，并打印 pid 的前后。**③折叠下的行不在 dump 里**——这一端的 `dumpLayout` 只报**排版出来的那一段**（与 §7 先前记的"视口外也报"相反，那句是把"被软键盘挡住"读成了"在视口外"），所以读传输页的日志必须先滚一遍取并集（`transport_lines()`），否则判据读到的是"没有"。**④停在解析那一关的趟，`dial` 早退时要把屏上的话交回去**——它过去返回空列表，于是"扫码页没有那句话"是探针对自己早退的副作用（#157 就是被这条掩掉的）；现在早退前读一遍带坏话词的行。**⑤上一轮的「来自配对二维码」那一行不会自己消失**——解析被拒时 store 直接 return，旧行还站着，按钮照旧会拨**上一轮**那台；每一趟先按页面自己的「清除对端」（它顺带清空粘贴框，比 `hgui.clear` 可靠）。**⑥替身会到自己定的钟点**——`stage_v2` 用 `--seconds 2400` 起，跑久了那一头不再答话，手机老实说的是「协议错误：IO 对端在 20000 毫秒内没有答完」，看着像"版本这一关没生效"；现在每趟先 `port_open()` 探一次，不在就把替身重新起起来，并把「协议错误」加进坏话词表，让"停在错误的理由上"可见。**⑦入站的连接这台手机没有断开按钮**——`断开` 只在本机拨出过的那一段上出现（`scan.uvue:75` 是 `v-if="s.connected"`），头条说「X 正连着这台设备」时只能等它自己的闲置回收（`wait_inbound()` 等满一分钟就把"名额还占着"报出来并继续，不再滚遍整页找一个不存在的按钮）。**⑧「已连接」那个徽章不带名字**——要证"连上的是这一轮那台"得回首页读头条（`link_headline()`），拿两字徽章当判据会替上一段的连接报成功 |
| `h_110.py` `h_121.py` `h_122.py` `h_124.py` | 鸿蒙：重启仍列收过的 / 串包 / 守卫那一支 / 取消 | 四条都 `PASS`（原文见 `.probe/*.txt`；`h_124` 那一趟 2026-10-26 在 #132 之后的发送方上重跑过，仍 `PASS`——#136，见 §3.3 取消那一行） |
| `mdns_150.py` + `h_150_leg.py` / `h_150_type.py` | #150 的设备腿：手搓一条 mDNS 公告（地址与 `fp` 各由这一次运行决定），再从名单点中那一行、填真配对码、按连接，屏上那句与对端的访问日志一起读 | 两条腿都在鸿蒙模拟器 `127.0.0.1:10001` 上跑到（原文 `.probe/h_150.txt`）：假 `fp` → 屏上判死那一句（#153 之后重读成「对端证书与**要核对的**指纹不符，已中止 广播里报的是 0badc0ffee000000…，这台在 TLS 上递出来的是 3b0108120c6000ee…」，见 `.probe/a_153_harmony.txt`；当时那一趟印的还是「与已固定的指纹不符」）且对端**零请求行**；真 `fp` → 「已核对：…」＋对端 `GET /v1/hello` 与 `POST /v1/pair` 各一条 200。**这一对定了 harness 的一条平台规则，但只对鸿蒙**：QEMU slirp 把 `224.0.0.251:5353` 反射进 guest，却不把主机发的 UDP 广播送进去（`decoy_announce.py` 打 `255.255.255.255`/`10.0.2.255` 都收不到），所以要往鸿蒙模拟器名单上放一台"说话不可信的对端"只能走 mDNS；安卓那一边有另一扇门，见下一行 |
| `a_154_leg.py`（假公告正文 `.probe/a_154_ann.json`，对端是 `.probe/tlsserver.py` 的 `rsab`） | #142/#150 那条前缀核对在安卓上的同一趟：从控制台 UDP 转发往名单里塞一条假公告（`fp=0badc0ffee000000`、端口就是这台 `rsab` 在听的 43733），点中它、填**真**配对码与密码、按连接，屏上那句与对端日志一起读 | 跑到（`模拟器`，原文 `.probe/a_154.txt` 末段 + 截图 `.probe/a_154_card.png`）：屏上「对端证书与要核对的指纹不符，已中止 广播里报的是 0badc0ffee000000，收到 3ae1fc93c61c7b73…」，对端那一段时间**一条请求行都没有**，只留 `SSLV3_ALERT_CERTIFICATE_UNKNOWN`。**这一行同时立了三条 harness 规则**（细节 `.probe/a_153.txt` 末尾）：一、安卓这一边的门是 `redir add udp:43722:43721`，不是 mDNS；二、这条转发会**静默失效**，每一趟都要先 `redir del` 再 `redir add`；三、guest 本机 `nc -u` 打 `10.0.2.15`/`10.0.2.255`/`127.0.0.1` 的 43721 一个包都不到（`UdpNoPorts` +2、`UdpInDatagrams` 不动），所以"名单听不到外机"从来不是 `CsDiscovery.kt` 里那个 `is Inet4Address` 筛的——转发包以 `Inet4Address` 原样到达，名单上显示来源 `10.0.2.2` |
| `h_153_pin_leg.py`（`state` / `real` / `wrong` / `stop`；假的那一匹马由脚本当场生成 RSA-2048 自签，日志 `.probe/h_153_foreign.txt`） | #153 欠的最后一格：鸿蒙本机钉表上真有 `10.0.2.2:43731` 那条 64 位摘要时，对面换一把钥匙要说「已固定」——`state` 用 `hdc file recv` 把钉表读回来并和 `.probe/emu/id150/tls-leaf.pem` 的 SPKI 摘要对齐，`real` 在同一个端口摆对的证书当对照，`wrong` 换一把新的 | 两条腿都 `PASS`（`模拟器`，鸿蒙 `127.0.0.1:5557`，原文 `.probe/h_153_pin.txt`，截图 `.probe/h_153_real.jpeg` / `.probe/h_153_wrong.jpeg`）：`real` 屏上「已连接 PC-probe-receiver（沿用旧指纹）」＋对端两条请求行；`wrong` 屏上「…已固定 3b0108120c6000ee…，这台在 TLS 上递出来的是 b2abfbfb23a2323a…」＋那一侧「handshake ok, 0 字节应用数据」。**这一行立了三条 harness 规则**：一、手输那一行的两个框要按"同一排的两个 TextInput"认，不能按 `hint` 认——填过的框会在 `dumpLayout` 里丢掉 hint，而端口框是预填的，按 `hint=端口` 找不到它就留在传输默认的 43720 上，那一趟拨的是别人；二、`dumpLayout` 不报软键盘底下的行，于是"把它滚进可点带"的那套 `scroll_to`／`tap` 会把按「连接」这一下打在数字键上（一趟跑完端口框写着 `43731888888`，屏上却还是上一趟的「已连接」）——所以按下连接前后都要把两个框读回来比对；三、扫码卡片的状态是进程内存里的，上一趟的会话会让这一趟**根本不拨号却报「已连接」**，`清除对端` 不顶掉它，所以每一趟先 `aa force-stop` 再起（钉表在磁盘上，跨得过这次重启，这正是这一格要的前置） |
| `h_disc91.py` / `h_disc91_prod.py` | 发现层：名单、前缀是 served-leaf、点一台填进连接卡 | `found:5 lost:0`，两条通道 `ok` |
| `hgui.py` / `hdump.py` / `deploy.py` / `sweep.py` | 鸿蒙 UI 驱动与部署 | 工具，不产出结论 |
| `a_h13.py` / `agui.py` | Android UI 驱动（`uiautomator dump` → `input tap`） | 工具 |

设备侧结论只写进 `.probe/*.txt`，代码注释里引的是"哪一次跑、哪一句结论"，不抄提交号以外的东西。

## 6. 还欠什么（按依赖排序）

1. **#45 / #46 鸿蒙真机腿** — 需要用户同意唤醒并解锁 `2UCUT23C27052382`（个人机，有 PIN）。
   没有它，鸿蒙的真机矩阵停在 #57/#58 那两条（PC↔手机双向），发现与取消两级只有模拟器证据。
2. **#36 / #90 / #93 Android 发现层上机** — 卡的还是 `CHANGE_WIFI_MULTICAST_STATE` 要打进自定义基座，
   而 `pack --iscustom` 花用户的 DCloud 账号。**等用户点头**，期间可以用 `pack --precheck` 免费验配置。
   这一条的范围要按实测收窄：UDP 广播那一半**不需要自定义基座，也已经在模拟器上跑到**（`模拟器`，
   `.probe/a_154.txt`：外来公告进名单、点中、前缀交给 TLS 那一关），所以欠的是**真 LAN 上的组播/mDNS**；
   先前"安卓模拟器上发现听不到东西"是 harness 打不进 guest，不是应用筛掉了包（三条规则 `.probe/a_153.txt` 末尾）。
3. **物理 Linux 桌面** — 需要 `pip install PySide6` 与真实桌面环境；现在的 Linux GUI 结论停在 WSLg。
4. **Linux 防火墙落到实处** — `inspect()` 会读 `firewalld`/`ufw` 的判定并打印该跑的命令，但它不代跑；
   要真的验一条 Linux 入站放行，需要物理桌面 + 管理员口令（这台机器的 WSL 只能验到"包进得来"那一半）。
5. **#132 那条恢复支的设备腿** — 已经补齐（#133：两台四种喂法八条腿全 `PASS`，见 §3.2 / §3.3），
   浏览器那第四条腿也补上了（#135：`mute` 形状进 `senderSelfReport`，`发送自检` 从 10 项变 14 项，全通过，
   见 §3.4）。**这里只剩一件事**：**自然发生**的那一次（目前只有 #130 在鸿蒙 40 ms 下限上自己撞出来过一趟；
   哪趟上机跑出了「这一块的回复没来，但对方说它已经有了」，把那趟原文记进 §3.3 那一行）。
6. ~~**A 级取消那句上机**（#134）~~ 两台都上过了；~~**B 级在 #132 之后重跑**（#136）~~ 也补上了——**两台都重跑了**
   （原来只欠鸿蒙那一条，跑完发现安卓那趟的原文同样该换个日期：#124 那两条腿写于 #132 之前，而 #132 改的正是
   同一条 `putChunk`）。判据不在"停下得快不快"，在**对端只看见一个写块头**：#132 之后 `status == 0` 那一支会先
   问一次 `state`、问到"没到"还要重写那一块，取消如果被误读成"回复没来"，账本里就会多出第二次写块。两条都 `PASS`，
   原文 `.probe/a_124.txt`、`.probe/h_124.txt`，已记进 §3.2 / §3.3 取消那两行。
7. ~~**重出 PC 包**~~（#139 已做）— 跑这次时本机没有正在跑的 `ChuanShu.exe`，43720 也空着，所以直接出在正式
   `dist\` 上：`build.ps1 -Task all` → `dist\ChuanShu\ChuanShu.exe` + `dist\installer\ChuanShu-Setup-0.1.0-x64.exe`，
   `freeze_smoke.py` 全过；Linux 那半边 `.probe/linux_build_real.sh`（在 ext4 里建，不碰 `dist/ChuanShu`）+
   `.probe/linux_smoke.sh` 在 WSLg 真屏上 `ALL PASS`（第二次按下才亮出 27 行二维码定位点，与 #118 记的那条一致）。
   这一批含 #137。**安装包还是由用户自己双击装**——写防火墙规则那一步是安装器干的，属于本机外的动作。
8. **`mute` 那一支报哪句话**（#138，口径题不是代码题）——手机/H5 报那一问自己的错，PC 按合同字面报原来那次写的错，
   两边"一次都不重写"都做到了。要么把合同那句写成「抛掉这一块的失败（哪一支问不到就报哪一支）」并让 PC 跟上，
   要么维持字面、把手机那半边改成报写本身的错。**倾向第一种**（对人说得更准，而且不用重跑两台设备那四条腿），
   但它动的是冻结合同 §4，所以这一条要用户点头。
9. **#141 的设备腿** — 安卓那一半边了结了（`模拟器`，`.probe/a_149_leg.py` 两条腿：干净状态下带空码回拨答
   `resumed=true` 且 200 000 字节逐字节落盘，同一份状态只把进门的路换成 `adb forward` 就退回 `BAD_PAIR_CODE`，
   见 §5 那两行与 §3.2 那一行；顺带把同样欠着的 `#88` 那次真跑一起跑掉了——修的就是入站 pair 先认本机已有固定这一支）。
   **还欠的是鸿蒙那一端自己的同一形状**：`store/session.uts::harmonyReceive` + `identityForAddress` 与安卓的
   `recvHandle` 是两份代码，现在只有共用状态机（`接收自检 59 项`）和编译门撑着它。一台鸿蒙模拟器 + 本机就够，
   门是 `hdc fport`（它给 guest 的来源地址是什么还没量过——那正是 §5 `a_149_src.py` 在安卓上先做的那一次测量）。
   **这一条量完了，也跟着跑到头了**（`模拟器`，`.probe/h_154_src.py` + `h_154_slirp.py` + `h_154_leg.py`，见 §3.3
   那一行与 §5 那三行）：`hdc fport` 给 guest 的来源是 `127.0.0.1:<临时端口>`，而这台 DevEco 模拟器没有任何一条
   能在进门时把来源写成 `10.0.2.2`（安卓那侧的正腿靠的正是控制台 `redir add` 会示人 `10.0.2.2`）。于是三条腿里
   两条跑到了、一条按拓扑构造不出来：干净状态下带空码回拨答 403 `BAD_PAIR_CODE`、一个字节都没落（对照腿，就是
   #141 当初那个症状在鸿蒙代码上的再现）；同一条路同一把钥匙只带上码，`pair` 收下、200 000 字节逐字节落盘（证明
   拒的是地址不是路）；**"桥接采纳"那半个正腿要等一台真局域网里的手机**——它现在仍是 `编译门` + `浏览器`。
10. **#140 那一轮逐条巡检剩下的一条**（已立案，未动手）：
    #147 闲置回收删"半截文件"按单还是按文件（PC 连已校验的一起删，手机留着——口径题，要用户定）。
    （同批的 #142 已经落地，见 §3.2 / §3.3 那两行；它欠的那次上机是下面第 11 条。**#143 也落地了**，
    见 §3.2 那一行——顺带把合同 §6 里 `dataTransfer` 那个预览期叫法改成了正式版的 `dataSync`；
    它欠的那一次"退到后台还收得到"在第 13 条。**#144 也落地了**，见 §2 那一行与 §3.1 / §3.2 / §3.3 那三行：
    一条规则两份实现都补齐了，`pair`/`offer` 的请求体里多了一个字段、`pair` 的应答里也多了一个——这是**上线上的字节**，
    所以它欠的是真跑，而安卓那两个方向已经跑到 `模拟器`（`.probe/a_144.txt` + `.probe/a_149.txt`，见 §3.1 / §3.2 那两行）；
    剩下鸿蒙那一端与"故意只报 v2"那一格在第 14 条——**第 14 条现在了结了**，四格都在鸿蒙模拟器上跑到 `模拟器`，
    而那一台"只报 v2"是按本机改报造出来的（量的就是手机对陌生集合的判断，不需要第二个 v2 产品）；同一轮还补了
    配对串 `v=` 那半边（`parsePairUrl` 改成问集合）与它量出的 #157，见第 18 条。
    **#145 也落地了**，见 §3.1 那一行与 §3.2 / §3.3 / §3.4 那三行：PC 三个"已经答过"的出口统一记进
    `_answered`（上限 64，与手机 `settleOffer` 那份定长台账同一条规矩），手机把记答案这件事从两个平台的
    宿主搬进了共用的 `cs-receive.uts`（五个了结处）。证据到 `门禁` + `编译门` + `浏览器`，安卓那一端另已跑到
    `模拟器`（`.probe/a_145.txt`，见 §3.2 那一行末）；
    欠的那一次"鸿蒙自己对着屏看一遍"在第 15 条——**第 15 条现在也了结了**，两趟 `PASS` 在 `.probe/h_145.txt`。
    **#146 也落地了**，见 §3.2 / §3.3 / §3.4 那三行：合同 §1 那一
    唯一「用户可改」的身份字段，手机这一端以前根本没有能改它的地方（名字是 `Build.MODEL` / `marketName` / 浏览器名读出来的），
    现在三端共用一条规则、各端把名字存进自己私有目录的 `settings.json`、改名以后 hello / 广播 / 清单念的都是新的那一个。
    证据到 `编译门` + `浏览器`，两台模拟器各跑了一趟（第 16 条，`.probe/h_146.txt` / `.probe/a_146.txt`）：改名、读回
    磁盘上那个文件、PC 读 hello、杀进程重开还是它、旧钉照旧 `resumed=True`。**#148 也落地了**，见 §3.3 那一行：合同 §5
    最后一条（写出前核到符号链接）在鸿蒙这一端补上了——这一平台确实没有 `realpath`，能问的只有 `lstatSync` +
    `Stat.isSymbolicLink()`，所以守卫改成从接收根往下**一环一环问**，任何一环是链接就整条不作数；它是 `recvPath` 这一个
    咽喉上的唯一一份，六个调用点全从它走。设备腿在 `127.0.0.1:10001` 跑过（`模拟器` + `截图`），但**"中间那一环真的是
    链接"这一支在这台机器上造不出来**：`fs.symlink` 从 API 11 起只给系统应用，模拟器的 shell 是 uid 2000、进不了这个沙箱——
    那一支只有代码读，档位不往上编，屏上那行也这么写着。）
11. ~~**#142 的设备腿**~~ — **两端都在模拟器上跑完了**（#150 以后这一趟更值得跑，也确实更该跑）。鸿蒙那一边先跑
    （`模拟器`，`.probe/h_150.txt`：两半都在里面，「已核对：3b0108120c6000ee 这台机器在 TLS 上就是它自己」与假前缀那一趟判死＋对端零请求行，见 §3.3 末尾）。安卓这一边的同一趟补在 2026-10-27（`模拟器`，原文 `.probe/a_154.txt` 末段 + 截图 `.probe/a_154_card.png`）：
    一、往名单里放一条不可信的公告（`.probe/a_154_ann.json`，`fp=0badc0ffee000000`，端口填这台监听真在听的 43733），
    注入用的是模拟器控制台的 UDP 转发 `redir add udp:43722:43721`——宿主打 `255.255.255.255`/`10.0.2.255` 进不去 guest，
    这条转发才是安卓这一边的门（细节与三个坑记在 `.probe/a_153.txt` 末尾）；二、点中那一行 → 填**真**配对码与密码 → 按连接，
    11.7 秒后屏上是「对端证书与要核对的指纹不符，已中止 广播里报的是 0badc0ffee000000，收到 3ae1fc93c61c7b73…」——
    `CsWire.kt` 那句 `CertificateException` 的文本没被平台吞成"连不上"，两个数都到了屏上；三、对端 `.probe/tlsserver.txt`
    在那一段时间**一条请求行都没有**，只留下一句 `SSLV3_ALERT_CERTIFICATE_UNKNOWN`，也就是说配对码根本没发出去。
    正常路径没被误伤那一半由同一批里的真前缀对照证着（`.probe/a_152.txt` 的 HONEST_TRUE 那一趟：hello 与 pair 各一条 200、
    对方把这台机器落成固定）。
12. **#150 已落地，欠的是它自己的设备腿**（与第 11 条同一趟）— 手机上 §2 那句核对现在发生在套接字上：判据收成一条
    `cs-protocol.uts::pinAccepts`（整摘要比全等、不足 64 位比 `startsWith`、空钉放行＝第一面由配对码带信任、读不出
    证书永远不放行），Android 在 `CsWire.kt` 的 `checkServerTrusted` 里用它，鸿蒙在 `app-harmony/index.uts::httpRun`
    写请求行之前用它（这个文件不能 import `.uts`，规则只能重述一份），iOS 那半边同形但**只读不跑**；`store/session.uts`
    交出去的值从 `s.scannedFp` 换成 `activeOptions.pinPrefix`，也就是广播前缀从此真的当 TLS 钉用；`cs-client.uts` 里读
    `hello` 自报 `served` 那一段删掉了（`PeerSession.peerServed` 这个字段随之没有了），名单补全摘要改从 `pinnedFor()`
    取——那正是传输自己在握手时写进钉表的那个数。**这一改同时换掉了"谁说话"的优先级**：从名单点中那一行，过去由钉表
    （`pinFor(host, port)`）判，现在由公告判，钉表只在没有公告时才开口——这不是新口径，扫码那一条一直就是这样
    （`s.scannedFp` 早就顶住钉表），#150 只是把名单那一行并进同一个位置。代价要写清：钉表里那条陈记录（比如端口转发
    指向过另一台）不会挡路，它会在配对成功那一步被这一程握手看到的摘要改写；反过来，也没有必要让公告与钉表互相对账
    后在此刻拒绝——那会把 `adb forward`/DHCP 复用那几趟在跑的 harness 腿判死，而 socket 上那一次比较本来就能替它们把关。证据：`编译门` 三道（`.probe/c150_web.log` / `c150_android.log` /
    `c150_harmony.log`）+ `浏览器`（`发送自检 24 项`、`发现自检 29 项`、`接收自检 71 项`，原文
    `.probe/c150_web_selftest.txt`）+ **鸿蒙 `模拟器`**（原文 `.probe/h_150.txt`，两件事都读到了：一、正常那一趟「已核对：…」背后
    是从握手读回的叶摘要，而同一条日志里对方自报的 `09947c0b…` 只被抄去记账、不参与定性；二、假公告那一趟停在
    「对端证书与已固定的指纹不符，已中止 广播里报的是 0badc0ffee000000…，这台在 TLS 上递出来的是 3b0108120c6000ee…」（那是 #153 之前的措辞，同一趟在 #153 之后重读成「与**要核对的**指纹不符」，见第 17 条），
    配对码填得再对也没有一个字节写出去，对端那条 `pinned new peer` 只在真前缀那一趟出现）。**这一改带来的那个新的正当失败形状**
    也照实读到了：一台在**广播之后**换过叶的对端（重启过、或公告本来就陈的），前缀会对不上，这一端停在指纹不符那一句而**不是**
    去要配对码。那种时候的修法是把那一行重新点一次或重扫码，不是重试连接——这一条如果上机读起来像"连不上"，先确认公告是不是陈的。
    安卓那一边同一趟也跑过了（第 11 条），剩下的只有真机（私人机锁着，未经同意不动）。
13. **#143 的那一次"退到后台还收得到"** — 代码与卡片都落地了，但标准调试基座是别人的 APK，清单里没有我们那个
    `<service>`，所以 `CsKeepAlive.begin()` 在这一台上必然报"挂不上"（那正是这一趟要证的诚实降级）。要证保活本身，
    得先 `pack --iscustom` 出自定义基座——它花的是用户的 DCloud 账号，所以这一步等点头；判据是：开着监听把应用退到
    后台，通知栏那条「传书在收」还在，对端接着发的那一块照样落盘。
14. ~~**#144 的设备腿**~~ — **两端、两个方向、三道门都跑完了**（鸿蒙那四格见 §3.3 那一行末与 §5 那一行，
    安卓那两格见 §3.1 / §3.2）。原来列的"还欠的两格"是这样了结的：
    ①鸿蒙同一形状的两趟——`模拟器` 四格全 `PASS`，跑的是装着 `parsePairUrl` 那道改动的新 hap；
    ②"故意只报 v2"那一支在设备上的判死——**不需要第二个 v2 产品**：改报发生在**本机**这一侧
    （`h_144_v2_recv.py` 把 `spec.load()` 交回来的声明换成只含 v2，`reject_road` 更是在签完名以后才换），
    量的本来就是"手机对一份陌生集合的判断"，所以这一格按原样补上了，两个方向各一趟
    （`reject_send` 停在 hello、`reject_road` 停在 `pair` 前的 `UNSUPPORTED_PROTOCOL`、一个字节没落）。
    这一轮真正的收获比那两格多一半：手机上 §7 最后没实现的那半边（配对串 `v=` 拿单个数比）改成了问集合，
    以及它顺带量出的 #157——解析拒掉一条配对串时，按下「解析」的那一页不说话。两条都记在下面第 18 条。
15. **#145 的设备腿** — 安卓那一边了结了（`模拟器`，`.probe/a_145_leg.py` 连过三趟，原文 `.probe/a_145.txt`）：
    本机对着一台正在监听的模拟器，把**同一个 `offer_id`** 的清单连投几遍，两条腿都在同一趟里跑完——窗口里重投
    拿回 `200 accepted:false` 且屏上还是一张卡（不是两张），点一次「拒绝」之后两投都拿回 `403 DECLINED` 且卡为 0；
    另一条只投一次、六十八秒里一个请求都不发，那张卡自己收掉（`receiveSnapshot()` 里带着 `sweep()`，界面 1 秒一读），
    之后两投还是 `403 DECLINED`。两单都被拒，`files/chuanshu-receive` 腿前腿后一样空。§5 那一行记了两条 harness 规则。
    ~~**还欠的一格**：鸿蒙自己那一端对着屏的同一趟~~ — **这一格补上了**（#158：`模拟器`，`.probe/h_145_leg.py` 两趟都
    `PASS`，原文 `.probe/h_145.txt`，见 §3.3 那一行末与 §5 那一行）：鸿蒙的宿主确实是自己答的——`harmonyReceive`
    先回 `200 {"accepted":false}` 再松开那条 TLS 连接（它没法把连接挂住等人），而"重投只落在一行上"这件事是
    共用状态机 + 这一端每秒一次的 `refreshReceive()` 一起做出来的，现在两半都在屏上读到了。PC 当接收的那一边
    本来就在 `门禁` 里（八条腿），不欠设备腿。**第 15 条因此了结。**
16. ~~**#146 的设备腿** — 三端规则与三份存储都落地了，但浏览器没有私有目录，所以"这个名字活得过一次重启"这一句
    目前只有代码、没有观察。~~ **两台模拟器各跑完了一趟**（`模拟器`，原文 `.probe/h_146.txt` / `.probe/a_146.txt`，
    截图 `.probe/h_146_saved.jpeg`、`h_146_restarted.jpeg`、`.probe/a_146_saved.png`、`a_146_restarted.png`；两条腿与
    它们立的 harness 规则见 §5 那一行，屏上的逐条证据在 §3.2 与 §3.3 的 #146 行）。形状就是这一条原先许诺的那一串：
    `我的` 页改成一个新名字 → 头像那行、`设备名` 行末的值、输入框里的草稿三处一起换成它 → `hdc file recv` / `run-as`
    从私有目录读回 `settings.json`，里面写的就是那一个值（鸿蒙 36 字节，sha `9325495bec4d…`；安卓那一趟改名前
    这个文件根本不存在）→ PC 拨进来读 `GET /v1/hello`，`name` 念的是新名字 → 杀进程重开、中途一个键都不按 →
    屏上三处仍是新名字，**没有**回落成硬件那句（鸿蒙 `deviceInfo.marketName`、安卓 `Build.MODEL`），hello 仍是它 →
    叶与指纹前后逐字节一致（`30630f39ace7…` / `f693be2bb977…`），**留空配对码**再配一次照样 `resumed=True`。
    "活得过一次重启"这一句在屏幕上之所以是观察而不是印象：那句「已保存：对端在 hello、广播和清单上读到的都是它」
    活在内存里（`s.nameMsg`），重开后它自己消失了，而三处还在——剩下的名字只可能来自磁盘上那个文件。
    安卓的第一趟死在 harness 上（重开后 19 秒「扫码连接」那张卡还没排版出来，`A.announce` 扑空；产品侧一个字没错，
    腿 1 已经 `PASS`，原文留在 `.probe/a_146_run1.txt`），第二趟不再让手机自己重念一遍公告，改由 `served_leaf()` 与
    `verify_peer` 在套接字上各自核——那才是"还是原来那台"的证据。**这一条照实欠着的两格**：设备上这一趟读的是 hello
    那一处；清单的 `from_name` 与配对回复由 §3.4 那五条 `浏览器` 腿证到"读的是同一个 `self`"，那是同源论证而不是这一趟
    在设备上收到的清单；广播里的 `n=` 这一份副本这一轮没有设备上读数，且鸿蒙那一支只在 `discOpen` 时才顶掉 `discName`。
    浏览器那一端本来就不在这一条的范围里——它没有私有目录，所以关于重启的任何说法在那一端都无法证明，这一点原样保留。
    **第 16 条的设备腿因此了结。**
17. **#153 的判死措辞已改口，欠的那一格也在鸿蒙模拟器上落到了** — 共用那一份 `cs-client.uts::pinText` 过去写死
    「对端证书与**已固定的**指纹不符」，可从局域网名单点中那一趟手里只有广播里的 16 位前缀、一个钉子都没有，
    那句话在说自己没钉过的东西。现在共享那一句只说「对端证书与要核对的指纹不符，已中止」，是哪一种由宿主在数字
    前面补标签（64 位＝`已固定 `，短＝`广播里报的是 `）：`CsWire.kt:146`、`app-harmony/index.uts:1862` 各一份。
    屏上落地的四条合账在 `.probe/a_153.txt`，档位都是 `模拟器`：安卓×已固定（`.probe/a_153_pin_ok.png`）、
    安卓×广播里报的是（`.probe/a_154.txt` 末段 + `.probe/a_154_card.png`）、鸿蒙×广播里报的是
    （`.probe/a_153_harmony.txt`）。~~**欠的那一格说清楚**：鸿蒙×已固定（本机真有钉、对面换了证书）没有纹身上去，
    `index.uts:1862` 里 `expected.length == 64 → 已固定` 那一支是照安卓同一条规则抄的，**只过了编译门**~~
    ——**这一格 2026-10-27 补上了**（`.probe/h_153_pin_leg.py`，原文 `.probe/h_153_pin.txt`，截图
    `.probe/h_153_real.jpeg` / `.probe/h_153_wrong.jpeg`）。形状就是那条腿自己说的那个：钉不是这次摆上去的，是
    #150 真前缀那一趟留在设备上的，`state` 只把它读回来核——`hdc file recv` 出来的
    `chuanshu-trusted.json` 在 `10.0.2.2:43731` 上正好一条，摘要 `3b0108120c6000ee8f90735e5262f882f985d7482cd6afe88abeb84b077f8346`
    长 64，且等于 `.probe/emu/id150/tls-leaf.pem` 那把 SPKI 的 sha256，所以走的就是 `expected.length == 64` 那一支。
    然后同一个地址、同一个端口跑两趟，每趟两个证人（屏上那句话 + 那个端口上的监听自己说了什么）：
    **对照**（对的一匹马，`.probe/recv_lan.py` 身份 `id150`）→ 屏上「已连接 PC-probe-receiver（沿用旧指纹）」，
    对端访问日志读到 `http "GET /v1/hello"`、`http "POST /v1/pair"` 两条，证明这一趟真的拨了、请求头真的写出去了；
    **判死**（换一匹新马：当场生成的 RSA-2048 自签 `not-the-pinned-peer`，叶摘要 `b2abfbfb23a2323a…`）→ 屏上
    「对端证书与要核对的指纹不符，已中止 已固定 3b0108120c6000ee…，这台在 TLS 上递出来的是 b2abfbfb23a2323a…」，
    而那一侧监听自己说的是「handshake ok, 0 字节应用数据：b''」（`.probe/h_153_foreign.txt`）——TLS 握完了手，
    一个请求字节都没写，所以 §2 那道核对确实落在握手与请求头之间，不是"没连上"顺手蒙对的。判死之后 `state` 再读一次，
    钉表还是三行、那匹新马没被钉进去。**「这台在 TLS 上递出来的是」后面那 16 位每趟都变**（新马的钥匙每次都重新生成），
    别把它当成纹身。iOS 那半边（`CsWire.swift:106`）留的是中性的「期望 …，收到 …」，本来就没说"已固定"，这一端已终止、只读不跑，
    所以没有跟着改标签；它走的仍是共用那一句新话。
    另外 #153 之后这些文档里凡是照原文引「与已固定的指纹不符」的地方，读到的都是 2026-10-26 22:52 之前那一版的屏。
18. **#157：解析拒掉一条配对串，按下「解析」的那一页要自己说为什么** — #144 的 A 腿量到的，不是新猜的：
    `store/session.uts::applyConnectText` 在 `target.reject != ''` 那一支只写了 `log()`，而 `log()` 落在**传输页**
    那本账上；§7 那道"配对串上写的版本本机听不懂"因此是**这一端唯一一条不按下连接按钮的失败**，却也是唯一一条
    扫码页不说话的。#123 立的规则是"连接按钮欠的那个答案，要在按它的那一页还"，那一轮只把 `配对码：…`、
    `配对密码：…`、`没有连接：…` 三支接进了 `refuse()`（`log` + `s.sessionLabel`），解析这一步在它上游，没跟上。
    现在 `applyConnectText` 被拒那一支走同一个 `refuse()`，成功那一路把上一次那句拒言清回「未连接」
    （连着一条活的会话不动它——`已连接到 X` 那一句比"读没读进配对信息"更要紧）。**三端都在屏上读到了这一句**：
    鸿蒙 `模拟器`（原文 `.probe/h_144.txt` 08:13 那一趟；这一格能读到，靠的也是 §5 那条规则④——探针在解析早退时
    过去返回空列表，"这一页没有那句话"是自己造出来的）；安卓 `模拟器`（2026-10-27 10:04，
    `.probe/a_123.py emulator-5554 43937 3` → 原文 `.probe/a_157_android.txt`，同一张卡片下面一行就是
    「配对信息读不出来：对端协议版本 v2 本机听不懂」，探针只按下「解析」，那一趟对端的计数器停在 `hello 0 / pair 0`
    ——这一支确实一个字节都没往外写，不是"连了但被拒"）；H5 `浏览器`（vite 5173 上打开 `#/pages/scan/scan`，
    填同一条 `v=2` 串按「解析」，屏上同一句，且 `performance` 的资源表里没有一条指向那个地址端口）。
    两道编译门 `.probe/c157_harmony.log` / `.probe/c157_android.log` / H5 那一道 `.probe/c157_web.log` 现在都是历史。
    **还欠的那一格也一并跑齐了**：这一页在安卓上三条腿各自单独跑过一趟，都在 2026-10-27 推上去的那份 bundle 上——
    leg1（小写密码的拒因写在扫码页：「配对密码：连接密码只有大写字母和数字：p」，`.probe/a_157_both.log` 10:19）、
    leg2（合法密码真连上：「已连接 探针对端（首次，已固定指纹）」，对端 `hello 1 / pair 1`，`.probe/a_157_leg2.log` 10:36）、
    leg3（上面那条 `v=2` 停在解析）。**这一趟量出的 harness 规则，比那一格贵**：`a_123.py` 的 `both` 模式在一趟进程里
    连跑三腿**不可信**——只有 `restart()` 之后**第一条**腿能把 122 字符填满粘贴框，往后每条都只进去 0 字符，
    而且框里的旧字不清（有一回读出 745 字符，`fill()` 于是照着一堆垃圾算删除次数），于是 leg2 报的 `(没读到)` 是探针
    没把字送进去，不是页面拒了合法密码（10-26 07:35 那一趟 `both` 三条都过，所以这是**会翻脸**而不是**必然坏**）。
    一条腿一趟进程，每趟开头都有 `基座重启` 那一行——这就是这一格现在的花费，也是它的账。
19. **#162：合同逐条巡检第二轮——四处「只有一端照合同做」，四处都补了**（做法沿用 #140：把
    `mobile/shared/protocol/spec.md` 里每条规范性句子，对着 PC（`app/`）、安卓（`utssdk/app-android/`）、鸿蒙
    （`utssdk/app-harmony/`）和那份共用状态机各读一遍，专找"三端里有一端的答案和另两端不一样"的那一支）。
    - **§1「服务叶 = RSA-2048 自签，`CN=peer_id`」——安卓的主题写的是硬件名**。PC（`app/net/identity.py::ensure_leaf`）
      与鸿蒙（`app-harmony/index.uts::servedPair`）都照这句写，安卓 `ServedLeaf.kt::commonName()` 写的是
      `Build.MANUFACTURER + " " + Build.MODEL`。线上没有任何一端读主题（对端显示的名字来自 pair 请求里的 `name`，
      进 `trust(...)` 那本账，不进任何摘要），所以这不是一个会被对面发现的缺陷，而是"同一句合同，三端各自解释成
      三张不同的证书"。现在 `CsIdentity.kt` 新导出 `peerId()`（`loadOrMake().peerId`，问不到就回 `''`），
      `commonName()` 是 `CsIdentity.peerId().ifEmpty { CsIdentity.hardwareName() }`。
    - **§1「同一份证书一直 serve」——安卓在拿时钟投票**。`ServedLeaf.stored()` 读过私钥、验过公钥匹配之后还要
      `parsed.checkValidity()`，一句 `stored cert rejected by the clock` 就把这张叶判死、于是重铸一把**新钥匙**。
      改前在旧包上量到过一次（`.probe/a_162_leaf.py clock`，改法是把那 718 字节 DER 里 TBS 的两个 UTCTime 改成
      `2020-01-01`、用同一把私钥重签再按原长拼回去）：logcat 说了那句话，`served` 从 `f693be2bb977…` 变成
      `109a4b93…`——**同一条钉在每一台对端机器上的记录从此失效**，而 §1 的结尾那句说的是"换了叶要人工重新配对"。
      一次倒退的时钟不该有权限替用户做这个决定。这一支在设备上有更早的原文：`.probe/and_persist.txt` 152-155 那两行
      `stored cert rejected by the clock: CertificateExpiredException … expired at Sun Oct 24 06:09:43 GMT 1976`
      （#109 那回的年份编码把有效期写进了 1976，于是每一次重启都重铸一遍）。现在日期那一道**故意不读**，只保留
      "解析不出 DER"和"证书里的公钥与架上的私钥不是一对"两种重建。改后同一趟（`模拟器`，`.probe/a_162_clock.txt`）：
      「verdict: PASS 一张被日期判死的叶留在架上也照样递出去，摘要三个地方都是同一个数，日志没开口」——架上、
      套接字、`GET /v1/hello` 三个读数都是 `f693be2bb977…`，`cs-leaf` 那一栏一句话都没说；`cn` 段（把架子清空让
      它重铸）：「verdict: PASS 首次运行铸的那张叶，主题就是 §1 说的 peer_id」，`CN=「e813141dd9020102047c620538899a20」`
      与本机的 `peer_id` 相等，notAfter 2046-10-27，三处摘要仍是同一个数（`885c8d70489c514e…`）。三份原文件按
      `.probe/a_162_backup.json` 放回去了（`.probe/a_162_restore.txt`：架上摘要回到 `f693be2bb977…`）。
      **改前那一趟的数字只在这轮会话里读过，它的原文被改后那一趟同名覆盖了**——要引就引上面那两行 1976 的旧原文。
    - **§3「同一来源 5 次失败锁 60s」——鸿蒙把"来源"交成了"这一条连接"**。规则本身在共用状态机里，一直是对的
      （`cs-receive.uts:44-45` 的 `CODE_MAX_FAILS=5`/`CODE_LOCK_S=60`，`failCount`/`pushFail` 按调用方交来的
      `client` 字符串分桶，第 10 组那三条腿量的是这本账）；缺的是鸿蒙递给它的那个号：`index.uts::dispatch` 原来交
      `c.ip == '' ? c.id.toString() : c.ip`，而这一端**每条请求都开一条新连接**（`onAccept` 里 `openConns.push(c)`），
      所以地址一时读不到时，猜码的人每一次尝试都分到一格全新的 5 次额度——这把锁在这条路上永远不会填不满，
      首页卡片那句「配对码连错 5 次会锁 60 秒」于是是在承诺一件不发生的事。现在交 `'?'`：一个还没落到手的地址
      就是"一个没人叫得出名字的来源"，全部同桶，这是安卓那一端一直在做的写法（`CsServe.kt:233-236`
      `sk.inetAddress?.hostAddress ?: "?"`，宁可和陌生人同桶也不给它发新额度）。PC 按 `client_ip` 记
      （`app/net/receive.py:564`）。档位是 `编译门`（`.probe/c162_harmony.log`：`项目 chuanshu 编译成功。` +
      `运行包制作成功`）；共用状态机这一轮没动，所以浏览器那 71 项没有重跑（跑它证不到这一格）。
      **这一格为什么停在 `编译门`，说清楚**：`c.ip` 是 `onAccept` 里挂在 `getRemoteAddress().then(…)` 上的，地址
      是**异步落到 `Conn` 上**的，而请求监听就在同一个函数里紧接着注册——所以第一条请求完全可能在它落地之前就被
      派发出去，那正是漏额度的那一扇窗口（#94 那一轮量过这一端的请求与回调谁先到，没有结论）。模拟器出不了这一支的
      正证：`hdc fport` 拨进来的来源在 guest 看就是同一个 `127.0.0.1`，地址一旦落地，改前改后交出去的号是一样的，
      锁照样在第 5 次之后落——那一趟**分不出这两个版本**，所以它不算这一支的证据。要出正证需要一条"地址回调根本不
      落地"的路（真机上的局域网拨入，或这台设备拒绝 `getRemoteAddress` 的那一类），那一格跟着 #45/#46 的真机腿一起
      等用户点头。
    - **§1「配对回复和 hello 的 `fingerprint` 字段是同一个数」——手机停了，PC 照抄**。手机共用发送方早就按这句做
      （`cs-client.uts:218-222`：应答里那个数不等于 hello 的数就抛「配对应答里的指纹和 hello 不一致，已中止」）；
      PC 的 `app/net/send.py::pair()` 过去把 `payload["fingerprint"]` 直接交给 `identity.trust()`，**而那正是下一次
      连接查钉子用的键**——一台在 TLS 上被钉住、却在应答里报另一个身份的对端，会被记到第二个身份下面。
      现在 `hello()` 把这条连接读到的数存进 `self.peer_identity`，`pair()` 一拿到应答就先比它，比不过就抛
      `PeerIdentityMismatch`（`send.py:63-70`），而且**在写下 token 之前**——那一条连接上的会话因此也不建立。
      抛的是本机句子，没有新增错误码（`protocol/protocol.json` 与 `app/net/errors.py` 一字未动：这一支对端从不应答，
      给它一个合同里的码等于改冻结合同）。三处出口说同一句话：`app/ui/transfer.py:2059`（连接工作器）与
      `:2523`（发送工作器）共用一个 msgid，`app/cli.py:501`（命令行）。两端接收方对 hello 与 pair 本来就答同一个数
      （PC `app/net/receive.py:599`/`:629` 都是 `self.identity.fingerprint`，手机 `cs-receive.uts:871`/`:1186` 都是
      `self.fingerprint`），所以这道核对不可能把自己人判死。档位 `门禁`：`scripts/protocol_selftest.py` 新加一条腿
      （把 `service.handle_pair` 包一层，应答里的 `fingerprint` 换成 64 个 `0`）——
      `PASS  a pair reply naming another identity is refused`，判据是"抛了"并且 `sender.is_trusted("0"*64)` 为假，
      全文件 `RESULT ALL PASS`。**这条腿自己教了一件事**：接收方对每把钥匙只留一个 token
      （`app/net/receive.py:586-587` `self._tokens[fingerprint] = token`），所以被拒的那次 pair 照样顶掉了 `conn`
      的会话，于是 `finally` 里必须 `conn.pair()` 把 token 拿回来，不然同一 phase 后两条版本集合的腿会报
      `NOT_PAIRED`——那是 harness 的账，不是协议的账，但下一次读这段的人会需要它。`cli_selftest`、`ui_selftest`
      各自 `RESULT ALL PASS`；八套目录只多这一条（每份四个文件行），`scripts/i18n_sync.py --check` `guard rc=0`，
      逐语言把 `Translate` 真取回一次（`en -> The pair reply named a fingerprint that does not match hello; stopped.`）。
      babel 的 `extract`/`update` 会顺手重排约 1300 行行号与折行，照 `e33a7f0` 的先例那属于单独一趟，本轮把 churn
      存进 `.probe/a_162_locale_churn.diff` 后 `git checkout -- locale`，只用文本追加了这一条。
      **还欠的那一格**：PC 屏幕上那句话没有真窗口读数——要造一台说谎的对端（现成的形状是 `.probe/tlsserver.py`
      那一族），门禁那条腿证的是"本机不会写信任表"，UI/CLI 两支只是同一句子的两个出口。
    - **这一轮核过、没有动的句子**（记下来免得下一轮重查）：§1 那两个摘要都不进 `fingerprint` 的算法链；§3 的
      `pairReply` 三端一致只按**身份摘要**认人（#141 补的那座桥）；§5 的落盘路径守卫（#148）；§6 的
      `chunk_pace_ms`、锁时长与单会话名额；§7 的版本集合（#144）。**这一轮因此欠的三格都在设备或真窗口那一侧**：
      鸿蒙那把锁的 429 一跑、PC 那句判死的一屏、以及安卓那两条叶腿还没有真机（私人机锁着，未经同意不动）。
20. **#163：合同逐条巡检第三轮——限额与超时那一组数字，外加 §5 的第二句**（做法沿用 #140/#162：把
    `mobile/shared/protocol/spec.md` 的规范性句子逐条对着 PC（`app/net/`）、共用状态机（`utssdk/cs-*.uts`）、
    安卓宿主（`utssdk/app-android/`）与鸿蒙宿主（`utssdk/app-harmony/`）各读一遍。这一轮的数字那一半先扫完：
    `chunk_size` 4 MiB、`max_name_bytes` 255、`max_path_depth` 16、`max_files_per_offer` 2000、
    `session_idle_timeout_s` 900、`offer_idle_timeout_s` 3600、`pair_code_ttl_s` 120 + `pair_code_static`、
    `passphrase_chars` 8、`offer_wait_timeout_s` 60、阶梯 `[0, 15, 40]`、每块最多三次写——**三端读到的都是同一
    份数**，没有第二处 #137。扫的过程里给镜像守卫补了一格：`mobile/scripts/check_protocol.py` 以前不核
    `offer_wait_timeout_s`，而手机把它硬写在 `cs-protocol.uts::OFFER_WAIT_S` 里（发送方靠它决定重投清单到什么时候
    收手，接收方靠它决定没人答的单一什么时候下台）——现在它跟着合同里的那一个数走，`OK  cs-protocol.uts mirrors
    the contract`。
    - **真正找到的是 §5 的第二句：「同名文件加 ` (2)` 后缀而非覆盖」。这一句三端谁都没做**。它管的不是两「单」
      （那是 #128：一单一个目录），而是**同一份清单里的两个条目**——发送方按文件名取名是合法的：
      `app/net/send.py::plan(paths, base=None)` 在没有 `base` 时交回的是 `Path(entry.name)`，于是
      `ChuanShu-cli send C:eport.txt D:eport.txt` 把两个不同的 id 报成同一个 `relpath`。GUI 走不到这一支
      （`app/ui/transfer.py` 用 `os.path.commonpath([p.parent])` 先把跨根目录的选择拒了：「这些文件不在同一个文件夹
      下，请分开发送。」），命令行没有那道筛。两端接收方各自的错法也一样彻底：PC 每个分块都从 `relpath` 现算落点
      （`handle_chunk` 里 `sanitize_relpath(...)`），手机把同一个 `relpath` 往台账里存了两次——**两条 id 的字节
      写进同一个文件的同一批偏移量**，accept 时那道按声明长度的预分配还会先把先落的那一份截断。这一支不是"界面
      难看"：整文件摘要那一道从来不会被绕过，所以后果是一单永远传不完，而不是交付出错的字节。
    - **改法在两端各自只有一处**：PC `app/net/receive.py` 新增 `unique_landing(rel, used)`（第一个拿到名字的
      保留原名，后来的在**扩展名之前**加 ` (2)`、` (3)`…），并且**在问用户之前**就把算好的落点写进每个条目的
      `land` 键——被拒的名字、被改名的条目都不该先弹一次窗；`land` 跟着清单一起进 `.chuanshu.state.json`，所以
      重启接管一单时复述的是当初那一套名字，不会再洗一遍。新读口 `_land()`：状态文件里这个键为空就是这一支
      之前的旧文档，按 `relpath` 现算（与手机的 `landingOr` 同一个兜底）。`handle_chunk` 与 `handle_finalize`
      都改成问 `_land(file)`，不再各自从 `relpath` 现算。手机那一边落在共用的 `utssdk/cs-receive.uts`：新函数
      `uniqueName(name, used)`，`offerReply` 里 `file.land = landingOf(offerId, uniqueName(relpath, used))`，
      一份 `used` 名单在这一单的循环里累积；安卓与鸿蒙都没有第二份落盘代码，宿主的写块、卡片行、回收与
      `state` 回的 `path` 读的都是台账里的 `land`。改名只看最后一个路径成分，且**只有 `dot > 0` 才算扩展名**
      ——开头的点是名字不是扩展名，而 §5 本来就把 `.开头` 的名字整个拒掉。
    - **证据是两个版本各跑一遍，不是各说一遍**。PC 档位 `门禁`：`scripts/protocol_selftest.py` 新增
      `phase_same_name`（两份不同根目录、同名、大小不同的文件，`plan([big, small])` 不传 base），判据先确认
      「两个不同根目录下的同名文件在这一单里确实是同一个名字: report.txt / report.txt」，再看两条各自的
      `path` 与整文件摘要。改前（`.probe/a_163_before.py` 把 `receive.unique_landing` 换成恒等再跑同一 phase）：
      四行 `finalize rejected report.txt: missing chunks` 之后 `app.net.spec.ProtocolError: FILE_DIGEST_MISMATCH`
      （原文 `.probe/a_163_before.txt`、`.probe/a_163_before_run.txt`）；改后（`.probe/protocol_report.txt`）：
      `RESULT ALL PASS`，两份字节落在 `44c493788e3e92c1eport.txt` 与 `44c493788e3e92c1eport (2).txt`，
      各自对自己那一份源文件。手机档位 `浏览器`：H5 `我的` 页 `接收内核自检` 71 → **76 项全部通过**（5c 那五条
      腿：同名两条先只问用户一次、各收下自己那一块、都过整文件摘要、落在两个不同名字、后一条是
      `同名-备忘 (2).txt`），原文 `.probe/c163_web_selftest.txt`；同一趟的改前读数是把 `uniqueName` 临时还原成
      `return name`——`不符` 三条、`接收自检失败 3 项，通过 73 项`，而「两条都收下了自己那一块」在那一趟是**绿的**
      （两个 PUT 确实都回 200，因为字节落在同一个名字上），这正好说明为什么判据必须是摘要与路径而不是状态码。
      两道编译门：`.probe/c163_android.log`（`项目 chuanshu（模块 cs-transport）编译成功。`）、
      `.probe/c163_harmony.log`（`项目 chuanshu 编译成功。` + `运行包制作成功`，仍未配置签名证书故产物未签名）。
      `cli_selftest`、`ui_selftest`、`check_protocol` 各自全过。**手机这两个宿主因此停在 `编译门`**：这一支的规则
      只有共用状态机那一份，设备上跑它需要先让一台手机**发出**两个跨根目录的同名文件，而选文件那一道在手机上给
      的是各自的路径，凑这一单要动发送方的探针——那一格跟着设备腿一起排。
    - **这一轮还核到两个"合同里有、三端都没实现"的数**（都不是缺陷，是口径题，见本节末）：§4 那句写的
      `X-File-Size` 请求头没有任何一端发、也没有任何一端读——接收方用的预分配长度来自清单里的 `size`，
      分块长度校验用的是 `size - index * chunk_size`，所以这个头即使发出去也只是第二份真相；
      `transport.max_parallel_chunks: 2` 同样没人读（PC 与手机都是一条连接一块、顺序推）。合同里留着它们不影响
      互操作，但"合同写的数三端都不读"这件事本身，是下一轮巡检该接着找的形状。
    - **harness 自己教的一条**（已进 §7）：H5 那一套 `askOn()` 是八个参数
      （`inbox, client, method, path, jsonBody, token, body, sha`），5c 第一版把 `token` 写在了 `jsonBody` 的位置上，
      于是五条腿红了四条——而 vite 对 UTS 的参数个数只打 `warning: Expected 8 arguments, but got 7`，编译门照样绿。
      **端内自检的腿第一次跑出来是红的，先怀疑腿本身**：这一轮补齐参数后再跑，红的是三条（`都过了整文件摘要`、
      `落在两个不同的名字上`、` (2)` 后缀），而「两条都收下了自己那一块」在改前那一趟是**绿的**——那一趟正是
      `uniqueName` 被还原成恒等的改前跑法，两个 PUT 都回 200，字节却落在同一个名字上。这条腿绿得正好说明了
      为什么 §5 这一句的判据只能是整文件摘要与落点，不能是状态码。

### 需要用户点头才能做的四件事
- 唤醒/解锁并使用那台个人鸿蒙真机（#45/#46 + 鸿蒙发现真机腿）。
- 跑 `pack --iscustom`（Android 自定义基座，#36/#90 的钥匙，也是 #143 那条"退到后台还收得到"的钥匙）。
- 定 `mute` 那一支报哪句话（#138）：动的是冻结合同 §4 的措辞，改哪一边都能收口，但不该由实现各自留着两种说法。
- 定合同里那两个"三端都不读"的数怎么办（#163 顺带核到）：§4 的 `X-File-Size` 请求头没有任何一端发或读，
  `transport.max_parallel_chunks: 2` 没有任何一端读（两端都是一条连接一块、顺序推）。要么补进三端，要么在合同里
  标成"保留字段、v1 不实现"——留着现状不影响互操作，但下一轮巡检每次都要重新判断一遍它算不算缺陷。
  同一个口径题的另一半是 #147（闲置回收删半截文件按单还是按文件）。

## 7. 已知平台坑（写给下一次动手的人）

- **Windows**：第二个进程能 bind 一个正在服务的端口，所以任何"端口占用/单实例"判断都要先连上问一次。
- **Android**：`am force-stop` + `monkey` 重启；私有文件用 `run-as cat`（AVD 未 root，`pull` 是 Permission denied）；
  `uiautomator dump` 每次 4–8 s，可被打断的窗口只有一个块体那么长，所以按钮要**先量一次坐标再盲点**；
  `scroll-view` 不给视口外的节点排版，只往下滚的查找永远找不到卡片顶部那个按钮。
- **Android 模拟器的网络腿**（#152/#153 量出来的三条，别再把它们当成应用的毛病）：插件那个 UDP 套接字是
  `DatagramSocket(null)` + `bind(InetSocketAddress(43721))`，落到 `[::]:43721` 双栈（`bindv6only=0`），
  v4 包以 `Inet4Address` **原样**到达，不是 `::ffff:` 映射——所以"名单听不到外机"跟 `is Inet4Address` 那道筛无关。
  进不去的是投递：宿主打 `255.255.255.255`/`10.0.2.255` slirp 不转，guest 本机 `nc -u` 打 `10.0.2.15`/`10.0.2.255`/
  `127.0.0.1` 的 43721 也一个包都不到（`/proc/net/snmp` 里 `UdpNoPorts` 涨、`UdpInDatagrams` 不动）。能用的门是控制台
  `redir add udp:43722:43721`（认证走 `~/.emulator_console_auth_token`），包在名单上显示来源 `10.0.2.2`；
  这条转发**会静默失效**，每一趟先 `del` 再 `add`。名单上一行约 2 s 内出现、静默即过期，探针先滚 4 s 再读会扑空。
- **宿主机拨进 Android 模拟器的两条 TCP 门给出两个地址**（#149 量出来的，`.probe/a_149_src.py`）：控制台
  `redir add tcp:<hostport>:<guestport>` 让 guest 读到来源 `10.0.2.2`，`adb forward tcp:<hostport>:<guestport>` 让它读到
  `127.0.0.1`。凡判据是"对端是不是**我拨出去过的那个地址**"（`CsIdentity.pinFor(host, port)`）的测试，只能走前者；
  后者是它的对照。另外 `adb forward` 返回 0 **不等于**宿主机监听已经起来——那一秒拨进去读到的是`由于目标计算机积极拒绝`，
  与配对被拒同一句话，所以要重试到能连上再判定。`forward` 的两个参数必须分开传（`tcp:43741 tcp:43720`），
  拼成一个字符串是 `adb.exe: forward takes two arguments`。
- **DevEco 鸿蒙模拟器没有一条门能以"我拨出去的那个地址"示人**（#154 量出来的，`.probe/h_154_src.py`、`h_154_slirp.py`）：
  唯一那条从宿主机进 guest 的路是 `hdc fport tcp:<hostport>:<guestport>`，它在 guest 的 `netstat -tn` 与 `/proc/net/tcp`
  里给出的来源是 `127.0.0.1:<临时端口>`；这台模拟器不带可查的 slirp 主机转发（hdc 隧道在 guest 的 TCP 表里根本没有行，
  是 virtio；`Emulator.exe` 只在 `127.0.0.1:5557` 监听；guest 侧只有拨出去的连接）。所以 §3 那条按**地址**认人的支
  （`identityForAddress(client, TRANSPORT_PORT, …)`）在这台机器上**正腿构造不出来**，只有对照腿能跑——与安卓那侧恰好相反，
  那边的控制台 `redir add` 会以 `10.0.2.2` 示人。别试这三条：`hdc rport tcp:43720` 和 app 自己那个 `0.0.0.0:43720` 抢同一
  个端口、而且挡的正是回调那条腿；两台模拟器互拨拨到的是各自的 loopback；宿主机路由不到 `10.0.2.15`。
  还有一条只属于这台模拟器的 shell 规矩：它**读得动**应用沙箱（`cat`、`hdc file recv` 都行），**删不动、写不动**
  （`mv`/`file send` 一律 `Permission denied`，SELinux 上下文 `u:r:sh:s0`）——所以"先把收的那份清干净"在这里不是做一次
  删除，而是**开局就检查它是不是空的**，不是空就停下改用界面的撤销或 `bm clean -d`。逐字节比对因此也只能走
  `hdc file recv` 落回本机再算 sha256，不能拿 `shell cat` 的长度当证据。
- **手机把信任存两处，第二处绕过地址桥**（#149 第一次对照腿假通过的原因）：`chuanshu-trusted.json` 是**拨出去**时钉的，
  带 `host`/`port`；`chuanshu-receiver-trust.json` 是**收过别人**之后留的，只按身份摘要认人，而 `pairReply` 里
  `pinned = trustByFp(inbox, keyFp(declared))` 两个都算。所以一台已经被回拨采纳过的手机，从**任何地址**收到那台 PC 的
  pair 都答 `resumed`，此时"地址桥起了作用"这个结论不成立。判地址这一支的对端，必须先把收的那份清干净。
- **收侧那张卡的钟，是界面那一读在走的**（#145 量出来的）：`store/session.uts::recvTimerTick` 在第一个页面挂载时
  就开，1 秒一次 `refreshReceive()` → `receiveSnapshot()`，而安卓宿主那个 `receiveSnapshot()` 里带着一次 `sweep()`
  （注释写得很明白：一个不再说话的对方不会发请求来让线扫它）。所以"窗口放到点没人答"不需要对端再发一个请求就会
  落定——卡自己没了，同一刻答案记进 `settled`；也所以**"屏上还有卡"不是"窗口还开着"的证据**，68 秒后读到 0 张
  也不说明有人答过。反过来，能把那 60 s 推着走的是 `POST /v1/offer`（`offerReply` 里 `known.touched = now`），
  dump 与截图都不算：腿 1 那两次"投完就读屏"要压在同一个窗口里，腿 2 那 68 秒里一个请求都不能发。
- **鸿蒙**：TLS 记录乱序到达、0x00 截断体、`Connection: close` 丢回复体、Ed25519 签不出服务叶；
  `uitest uiInput inputText` 对页面靠下的框静默无效（先 fling 再点）；`扫码连接` 是 sheet 不是 screen，
  滑动和点击都要留在 sheet 的 y 区间里；`keyEvent Back` 按多了会把 App 退到拨号盘，回来用
  `aa start -b com.chuanshu.app -a EntryAbility -m entry`（别按 Back 去找入口）。
  `dumpLayout` 报的是**排版出来的那一段**，既不能当"看得见"、也不能当"这页只有这些字"：先前这里写过它"与 Android
  相反，把视口外的节点也报出来"，那句是**误读**——`h_127.py` 那一趟找得到的那个按钮，是**被软键盘盖住**（键盘自己
  根本不在 dump 里），点那个坐标打到的是挡在上面的东西；而 #144 这一轮在传输页直接量到相反的一半——折叠**下面**
  的日志行压根不在 dump 里，不滚就取不到（`h_144_leg.py::transport_lines` 因此是"滚一遍取并集"）。两条合起来只有一条
  规矩：**要找的按钮先滚进视野，只认精确标签，屏上"没有那句话"要先证明这一页确实滚遍了**。`h_127.py` 第一次就是
  这么烧掉整条 60 s 决定窗口——探针只会往下滑，越滑离卡片顶部那个「接受」越远，最后是自己的发送方按 §4 判了
  `DECLINED: no decision in time`，不是对面拒的。这页还有 `已接受，还没收到分块` 这种包含「接受」二字的行状态，
  所以子串匹配永远不能当按钮。
  另外：连着几条单跑挂以后，`hdc file recv` 那份 `chuanshu-serve.log` 会显示「连接进来 N，当前开着 9」
  和「停在 x/y … 不再推进」——那是发送方扔下的轮询连接还没被 §3 的窗口回收，此时下一条可能在半路被重置
  （`你的主机中的软件中止了一个已建立的连接`）。这不是落盘规则的问题：`aa force-stop` + `aa start` 再起一轮就干净，
  半路断掉落下的那个文件按声明长度预分配、字节数看不出没写完——只有整文件摘要说得出（`h_128.py` 有一次是
  第 1 单在这里被打断的）。
- **本地错误的 `detail` 形状两端不一样**：Android 的 `CsWire` 把平台异常直接写成字符串，鸿蒙的
  `transportError()` 出于一致目的把所有本地错误包成 `{"code":…,"detail":{"reason":…}}`。所以统一口径的位置
  只能是渲染那一层（`cs-protocol.uts::detailOf` 读合同点名的 `detail.reason`，`PEER_BUSY` 再补 `detail.peer`），
  改发射器会顾此失彼（#126）。
- **"对方根本没回这一写"这件事，两台唯一对齐的形状是状态 0**：Android 的 Kotlin 半边（`CsWire.kt::errorOf`）
  说的是 `error` 键，宿主 `app-android/index.uts::ioFail` 再把它重新烤成 `code`；鸿蒙的 `transportError()` 直接
  就是 `code`。到共用发送方手里，两边都是 `status == 0` + 一个**平台自己那套词**的 `code`（Android 还会多出
  一个 `IO`：应答根本解析不出来）。所以那条恢复支判的是 `status == 0` **并且**排除 `CANCELLED`——那是本端
  自己按下的取消，不能拿去问对面（#132）。判错误码字符串会在其中一台上漏掉一整类。
- **两台 AVD 互相到不了**：各自的 `10.0.2.15` 不出本机，机对机必须走宿主转发；`adb forward --remove-all`
  要收尾，否则宿主的产品端口一直被占。
- **`.uts` 到 Kotlin 后只保留平台入口再导出的名字**：共享文件里导出的符号若没被 `app-android/index.uts`
  列出，会被 tree-shake 掉，报 `找不到名称"cancelSend"`（鸿蒙/web 不管这条）。
- **接一单时按声明长度把每个文件预分配好**（Android `setLength` / 鸿蒙 `truncateSync`）：只收到第一块的
  文件读起来是"整长度 + 尾部为零"，**字节数证明不了没写完**。判"这是半单"要比第一块的分块字节 **加**
  整文件摘要不相等（`.probe/a_127.py::half_written`），拿 `size < 声明` 当前提是错的。
- **手机落盘按单建目录以后，台账里多了一个 `land`**（`cs-receive.uts`，与 PC 的 `接收根目录/<offer_id>/<relpath>`
  同形）：写分块、算整文件摘要、回收停摆单、卡片行、`state` 回的 `path` 读的都是 `land`，**不是** `relpath`。
  两处坑连着：① 旧的续传台账/收件箱文档没有这个字段，`landingOr` 用"空 `land` = 当年的平铺位置"兜住，
  别把它改成无条件加前缀（那样一重启就把上一单的字节判成不在了）；② 探针与 harness 里凡是按 `relpath` 认
  一份交付的断言都要跟着改键（H5 那 56 项用 `landOf(offerId, relpath)`，`a_128.py`/`h_128.py` 按 `<offer_id>/` 目录认）。
  平铺的坏处本身是 #128：同一个名字的第二单 accept 时预分配，会把第一单**已经校验过**的字节截断重写。
- **同名两单在 UI 上是两行一模一样的文字**：`.probe/h_110.py::page()` 那种"按文本去重收集整页"的抓取
  **天生数不出两行**（`#128` 第三条腿第一次就是这么假失败的）。要数重复行就别去重，按 y 坐标收成列表。
  鸿蒙这端的文件页还有两点：① 一张卡里**行在中间、计数行在末尾**（`pages/files/files.uvue` 第 31-43 行：
  `filerow` 循环之后才是 `recvSummary`），而列表比一屏长，所以固定次数的滑动碰不到"两样都在"的那一屏——
  `h_128.py::card_scan` 的做法是从顶往下一屏一屏走，停在**第一个同时看得见计数行和目标行**的抓取上，
  每条判据都只在**这一屏**里成立（跨屏累计会把没滑走的行重复数）。② 行的状态徽章要靠**列**认（x≈1019），
  别靠词表：`已收到` / `已不在` 之外这页还会渲染 `已接受，还没收到分块`、`等你决定`、`整文件校验没过`。
- **给 UTS 类的属性整体赋值编不过 Kotlin**：`file.chunks = new Map<number, string>()` 到 Kotlin 是 `val`，
  报 `'val' cannot be reassigned`（编译日志只给这一句，得回到共用文件里找）。要清空就改集合本身
  （`file.chunks.clear()`），要重新报缺哪几块就另算一个 `const holes`。
- **H5 那套 `askOn()` 是八个参数，vite 对 UTS 的参数个数只打 warning**（#163 自己踩的）：
  `web/index.uts:974` 的签名是 `askOn(inbox, client, method, path, jsonBody, token, body, sha)`，5c 第一版把 `token`
  写在 `jsonBody` 的位置上（少传一个 `''`），于是五条腿红了四条。编译门的输出是
  `warning: Expected 8 arguments, but got 7`——**不拦编译**，`launch web` 照样绿，红线只在自检里。所以自检第一趟
  是红的，先怀疑腿本身（参数顺序 / 是否漏了那个空 `jsonBody`），再怀疑被测代码。
- **浏览器里点不动 uni-app x 的按钮时，直接调页面的 `setupState`**（#163 跑 H5 自检用的路子）：应用内浏览器
  `visibilityState=hidden`，browser-use 的 pointer `click` 报 `NATIVE_BROWSER_VIEWPORT_UNAVAILABLE`，而 `.click()`
  和手放的 Pointer/Mouse 事件**都不会**触发 uni-app x 的 handler。能用的做法是从 DOM 节点摸到组件实例再调方法：
  `document.querySelectorAll('uni-button,button')` → 元素的 `__vueVNodeCtx` → 沿 `.parent` 往上走到
  `inst.type.__name === 'me'`（「我的」页）→ `inst.setupState.recvSelfCheck()` / `sendSelfCheck()` / `discSelfCheck()`，
  结果读 `inst.setupState.s.lines`（每行是「通过 · X」/「不符 · X」，末尾一句「接收自检 N 项全部通过」）。
  两个附带规矩：改过 `.uts` 后要带新的 `?fresh=NNN` 重新加载，否则 vite 用的是缓存里那份模块；
  不要在实例上枚举键（`Object.keys(inst)`）来探结构，会刷一屏 `[Vue warn]: Avoid app logic that relies on
  enumerating keys on a component instance`——只读已知的那几个 `setupState` 字段。

## 8. 索引

- 协议语义与理由：[protocol/spec.md](../protocol/spec.md)；合同本体：[protocol/protocol.json](../protocol/protocol.json)
- PC 端工程、界面、打包、i18n：[README.md](../README.md)
- 手机端工程结构、验收口径、平台账、待办：[mobile/README.md](../mobile/README.md)
- vendored 合同校验：`py -X utf8 mobile/scripts/check_protocol.py`（改协议的正确顺序：先改根目录 `protocol/`，
  跑 PC 自测，再 `vendor_protocol.py` 重新 vendor 并刷新 `SOURCE.json`）
