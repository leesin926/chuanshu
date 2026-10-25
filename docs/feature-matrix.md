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
| 版本 | `protocol_version: 1`，`compatible_versions: [1]`；跨版本先握手再决定 |
| 端口 | 传输 43720（TCP）、发现 43721（UDP） |
| 发现 | 三条通道：mDNS 优先 → UDP 广播补充 → 扫码/手输兜底。**顺序不可颠倒，也不能只留 mDNS**；TXT 带 `ver/name/fp/ts`，announce 3 s，名单 15 s 过期；**Presence is not trust**（听见 ≠ 信任） |
| 身份 | 一台设备**两个摘要**：Ed25519 身份密钥只签配对码；套接字递出的是独立签发的 **RSA-2048 自签叶**（`CN=peer_id`，20 年）。信任锚是叶的 SPKI SHA-256；二维码 `f=`、广播前缀、TLS 钉子钉的都是这个叶摘要。两个都**不是** `peer_id` |
| 端点 | 七个：`GET /v1/hello`、`POST /v1/pair`、`POST /v1/offer`、`GET /v1/state`、`PUT /v1/offer/{id}/chunk/{idx}`、`POST /v1/finalize`、`DELETE /v1/offer/{id}`；鉴权走 `X-Chuanshu-Auth`，分块摘要 `X-Sha256`，声明长度 `X-File-Size` |
| 分块 | 4 MiB，同一 offer 最多 2 块并行；`hello` 里接收方声明 `chunk_pace_ms`，发送方按节奏写记录（手机侧阶梯 `[0, 15, 40]`） |
| 恢复 | 状态文件只是提示，**结论只来自 `finalize` 的整文件摘要**；offer id 就是续传柄，接收方的 `missing` 列表决定还缺什么 |
| 限额 | 一次 offer 2000 个文件、名字 255 字节、路径深度 16、offer 等待 60 s、会话闲置 900 s、offer 闲置 3600 s、配对码 120 s（6 位数字，口令 8 位大写+数字） |
| 错误码 | 11 个，中英双语文案；`CANCELLED` 是**传输层自己的**词，永不上线 |
| 中继 | 只在合同里留字段位，没有实现 |

## 3. 功能点 × 端 主矩阵

格子写证据档。`—` = 该端不做这件事（不是"没做完"）。

### 3.1 PC

| 功能点 | Windows GUI | Windows CLI | Linux GUI | Linux CLI |
|---|---|---|---|---|
| 收发双向（7 端点、断点续传、路径清洗、多文件带目录） | `门禁`+`模拟器`+`真机` | `门禁`+`真机` | `门禁` | `门禁`+`真机` |
| 接收确认（谁在拨、几个文件、60/65 s 内必须回答） | `门禁` | `门禁` | `门禁` | `门禁` |
| 落盘记录持久化（`arrivals.json`，重启后仍按磁盘真相说话） | `门禁` | `门禁` | `门禁` | `门禁` |
| 固定对端管理 / 撤销（`unpair`） | `门禁` | `门禁` | — | `门禁` |
| 单会话名额 + 第三方连接拒 | `门禁` | `门禁` | `门禁` | `门禁` |
| 配对码 + 口令展示（同屏可核对） | `门禁` | `门禁` | `门禁` | `门禁` |
| 发现：mDNS + UDP 广播（`_chuanshu._tcp`，名单 15 s 过期） | `门禁` | `门禁` | `门禁`(脚本读 stdout) | `门禁` |
| 防火墙状态读取与自述（被挡时界面自己说） | `门禁`+`真机`(WSLg 侧为 `模拟器`) | `门禁` | `门禁` | `门禁` |
| 防火墙规则写入 | 安装器（per-exe，`netsh`，先清后放；本机实测过装完的判定） | 同左 | 不代跑：`fix_commands()` 给出 `firewall-cmd`/`ufw` 那两条命令，界面与 CLI 只打印 | 同左 |
| 无边框自绘标题栏 / 深浅主题 / 托盘 / 开机自启 / 关闭询问 | `门禁`+`截图`+`真机`(窗口像素验收 #119) | — | `截图`(WSLg 实测)；托盘随桌面环境降级 | — |
| i18n 8 语言（zh_CN/en/ja/ko/de/fr/es/ru）+ 错误码双语文案 | `门禁` | `门禁` | `门禁` | `门禁` |
| 打包产物 | `exe` + Inno 安装包，`门禁`(freeze_smoke 复验) | 同一份 | `tar.gz`(0.1.0-linux-x64) | 同一份 |

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
| 身份：纯 BigInteger Ed25519 签名 + 手搓 236 字节 X.509 DER（RSA-2048 叶） | 完成 | `模拟器`（不引 BouncyCastle：三方依赖要云打包才拉得到，这台机器验不了那条路） |
| TLS 服务 + 指纹固定（拨入/拨出都钉得住） | 完成 | `模拟器`；`真机`（#106 手机发→PC 收就是这条路的真机证据） |
| 发：同一单多个文件 + 中文子目录（一块整 / 零头 / 带空格与括号） | 完成 | `模拟器`（#125 安卓腿：4 MiB + 1023 B + 1 MiB 三份一次发出，PC 侧逐字节比对三份全对、目录层级保住、单里三行都报完成） |
| 发：`pair/offer/chunk/finalize` + 4 MiB 分块 + 0x00 转义 | 完成 | `模拟器`（5 MB / 2 块，接收方逐字节比对） |
| 收：立即应答 + 轮询 `state` + 落盘后本地重算 | 完成 | `模拟器`（PC 发→手机收；中文子目录保留） |
| 机对机（两台 AVD 互传，双向） | 完成 | `模拟器`（宿主是唯一的路：接收方 `adb forward`，发送方拨 `10.0.2.2`） |
| 三份记忆：固定对端 / 未完成的单 / 已收下的文件 | 完成 | `模拟器`（重启后 `run-as` 读回文件，卡片逐个问文件系统） |
| 写入节奏 `chunk_pace_ms` + 阶梯 `[0,15,40]`、记录上限 4096 | 完成 | `模拟器`（4 MiB 块在 15 ms 档实测 ~37 s） |
| 取消两级：收回排队里的请求（A 级）+ 掐掉正在写的那一块（B 级） | 完成 | `模拟器`（#124 两条 leg 全 YES：半块断掉对端看得见、按下 2.2 s 停下、重发逐字节一致、取消不让节奏爬阶梯） |
| 失败原因的渲染：同一支 `detailOf`（A 级那句也从 `detail.reason` 读） | 完成 | `编译门`（#126：改动在共用渲染层，鸿蒙那页已经实跑看过这句；Android 这一趟掐的是正在写的那一块，走的是 B 级，A 级那句要按下时还有一条请求没发出去才出现） |
| 发现：mDNS + UDP 广播 | 代码在，**卡在出包口径** | `编译门` + `浏览器`（模型共用）；上机要 `CHANGE_WIFI_MULTICAST_STATE`，而它必须打进自定义基座——`pack --iscustom` 花的是用户的 DCloud 账号 |
| UI 七页（首页/文件/传输/我的/发送/扫码连接/探针） | 完成 | `截图` + `模拟器`；自定义导航页让出状态栏安全区（#102） |
| 前台服务接收中、Android 13+ 通知权限 | 设计口径在（`spec.md` §6：界面直说"请保持传书在前台"） | `未验`（服务被杀 = 连接被掐，这条只有真机能判） |

### 3.3 HarmonyOS Next

| 功能点 | 状态 | 证据 |
|---|---|---|
| 身份：`@kit.CryptoArchitectureKit` 出 Ed25519 签名；服务叶仍是 RSA-2048 | 完成 | `真机`（平台 TLS 签不出 Ed25519 叶，这是上机才发现的） |
| 收：0x00 截断 → `X-Chunk-Escape` 转义、TLS 记录乱序到达仍解析得出、立即应答 + 轮询 | 完成 | `真机` + `模拟器`（#56/#59/#94/#61） |
| 收：对端已消失的 offer 不再谎报"还没收到分块" | 完成 | `模拟器`（#95） |
| 发：同单第二块不再写出几 KB 就停摆；串包（往正在关闭的连接里写字节）修掉 | 完成 | `模拟器`（#99/#121，全程无串包） |
| 发：同一单多个文件 + 中文子目录 | 完成 | `模拟器`（#125 鸿蒙腿：与安卓那趟同一批三份，PC 侧逐字节比对全对、目录层级保住；发送页三行都报到「对方已收下 3 个文件 / 5.00 MB」） |
| 发：接收方声明的节奏真用上，守卫那一支在有条节奏的对端上跑到过一次 | 完成 | `模拟器`（#62/#122：少写 139264 字节，重发整单落对） |
| 发：取消两级（闭包注册表 `inflight` → `CANCELLED`，且不爬阶梯） | 完成 | `模拟器`（#124 鸿蒙腿五项全 YES） |
| 失败原因的渲染：`detailOf` 读 `detail.reason`（+`detail.peer`），别的键才按原文出 | 完成 | `模拟器`（#126：同一条取消，鸿蒙这页从 `{"reason":"用户按下了取消"}` 变成整句，与 Android 一致；那一趟的五条判据仍全 YES） |
| 鸿蒙 ↔ 鸿蒙 同端互传（两台模拟器） | 完成 | `模拟器`（#97） |
| 发现：`@ohos.net.mdns` + UDP 广播，名单接进既有连接流程 | 完成（模拟器） | `模拟器`（#91/#93/#115：`局域网设备` 卡片点一台就把 served-leaf 前缀填进连接卡；browse 不重发会静默，改成 9 s 一次） |
| 真机腿：#45 传输半边 / #46 收发 runbook | 待用户点头 | 唯一剩下的真机设备 `2UCUT23C27052382` 是用户的个人机（装了银行/学信网/税务），开机解锁需要本人同意 |
| UI 七页与鸿蒙 design 一致、density 恢复手机值 | 完成 | `截图`（#101/#102/#114 改口：那条"被裁掉"是探针点了视口外节点） |
| 后台限制的产品处理 | 设计口径在 | "接收中"界面直说保持前台（`spec.md` §6，与 Android 同口径） |

### 3.4 浏览器（H5 目标）

只承担一件事：**平台无关那一半能单独验**。接收状态机（`cs-receive.uts`）、发现模型（`cs-discovery.uts`）、
页面路由与扫码/粘贴/发送/留空重连都在浏览器里跑过（`浏览器`）。
`utssdk/web/index.uts` 明说浏览器没有 `java.security`、也开不了 TCP，所以探针三个按钮在浏览器里的输出
**不是证据**；这个文件存在的唯一理由是 `import ... from '@/uni_modules/cs-identity'` 在非 App 平台也要解析得到。

### 3.5 iOS（终止）

`utssdk/app-ios/` 的身份与传输两半边、NetService 那半边发现留在树里，不进任何验收，也不提议为它跑
`pack --iscustom`。#124 里 `app-ios/index.uts` 那一行 `cancelSend,` 只是保持文件之间一致。

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
wsl -d Ubuntu-24.04 -- bash /mnt/e/wowo3/scripts/linux_selftest.py   # 一次调用要跑完（/tmp 随调用消失）
bash build-linux.sh                                                   # → dist/ChuanShu-0.1.0-linux-x64.tar.gz
```
```bash
# 真屏那半（WSLg）
.probe/linux_build_real.sh   # PyInstaller 必须在 ext4，不能在 /mnt/e
.probe/linux_smoke.sh
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
| `protocol_selftest.py` | 合同镜像、七个端点、路径清洗（含中文目录）、多文件带目录、断点续传、并发身份目录 |
| `ui_selftest.py` | 图形界面四页、接收确认弹窗、设置窗口、7 语言 |
| `cli_selftest.py` | CLI 八条子命令端到端（含 `receive` 的 offer 计时器） |
| `linux_selftest.py` | Linux 侧 27 条断言，Qt-free（stdout **和** stderr 都要读：发现通道写的是 stderr） |
| `freeze_smoke.py` / `window_pixels.py` | 打包产物冒烟、窗口像素验收（#119 改口后不再替别人的窗口报 PASS） |
| `i18n_sync.py` | 词条齐平与 `.mo` 编译 |
| `receiver_host.py` | 一台当对端的常驻接收器 |

### 设备侧（`.probe/`，命名规则 `a_*` = Android、`h_*` = 鸿蒙、`*_peer.py` = 造出来的对端）
| harness | 判的是什么 | 最近一次结论 |
|---|---|---|
| `h_122_peer.py` | **共用探针对端**：按 `chunk_pace_ms` 发节奏、可选首块早拒、记 `chunk_heads` / `chunk_secs` / `broken` | 被 `a_122/123/124`、`h_122/124` 复用 |
| `a_106.py` | 手机发 → PC 收 | `PASS 逐字节一致（5 MB / 2 块）` |
| `a_110.py` | 收过的文件被删掉后卡片怎么说 | 清单仍保留那一行并说自己不在 |
| `a_115.py` | PC 发 → 手机收（真指纹、5 MB） | `一致=True`，落到 `files/chuanshu-receive/` |
| `a_116.py` | 两台 Android 互传（双向），也是 `Phone` 类的出处 | `size=5242880 sha=6f25483fb457ffa0 期望=… 一致=True` |
| `a_123.py` | 连接按钮拒掉填错的配对串时，扫码页自述拒因 | 两条腿（小写密码拒 + 合法密码连得上） |
| `a_124.py` | 取消两级在 Android 上的两个 leg | `PASS`（leg1 半块断掉 + leg2 重发逐字节一致、15 ms 档没爬） |
| `a_125.py` / `h_125.py` | 一次 offer 带三个文件、其中两个在中文子目录里（一块整 4 MiB / 零头 1023 B / 1 MiB 带空格与括号） | 两条都 `PASS`：`三份都落对 YES / 目录层级保住 YES`（原文 `.probe/a_125.txt`、`.probe/h_125.txt`） |
| `h_110.py` `h_121.py` `h_122.py` `h_124.py` | 鸿蒙：重启仍列收过的 / 串包 / 守卫那一支 / 取消 | 四条都 `PASS`（原文见 `.probe/*.txt`） |
| `h_disc91.py` / `h_disc91_prod.py` | 发现层：名单、前缀是 served-leaf、点一台填进连接卡 | `found:5 lost:0`，两条通道 `ok` |
| `hgui.py` / `hdump.py` / `deploy.py` / `sweep.py` | 鸿蒙 UI 驱动与部署 | 工具，不产出结论 |
| `a_h13.py` / `agui.py` | Android UI 驱动（`uiautomator dump` → `input tap`） | 工具 |

设备侧结论只写进 `.probe/*.txt`，代码注释里引的是"哪一次跑、哪一句结论"，不抄提交号以外的东西。

## 6. 还欠什么（按依赖排序）

1. **#45 / #46 鸿蒙真机腿** — 需要用户同意唤醒并解锁 `2UCUT23C27052382`（个人机，有 PIN）。
   没有它，鸿蒙的真机矩阵停在 #57/#58 那两条（PC↔手机双向），发现与取消两级只有模拟器证据。
2. **#36 / #90 / #93 Android 发现层上机** — 唯一卡点是 `CHANGE_WIFI_MULTICAST_STATE` 要打进自定义基座，
   而 `pack --iscustom` 花用户的 DCloud 账号。**等用户点头**，期间可以用 `pack --precheck` 免费验配置。
3. **中途杀进程续传**（手机端，任务 #127）：`state` 只是提示，`finalize` 的整文件摘要才是结论；
   手机端还没在设备上把这一条走一遍——PC 侧 `protocol_selftest.py` 杀的是接收进程，重启后 `reopen` 同一个
   offer id 只补缺的尾巴；手机这一侧的接管（`adoptAll`）已经有代码，缺的是把这趟在模拟器上真杀掉一次。
   多文件那批（#125 的三个形状）就是现成的分块源。
4. **物理 Linux 桌面** — 需要 `pip install PySide6` 与真实桌面环境；现在的 Linux GUI 结论停在 WSLg。
5. **Linux 防火墙落到实处** — `inspect()` 会读 `firewalld`/`ufw` 的判定并打印该跑的命令，但它不代跑；
   要真的验一条 Linux 入站放行，需要物理桌面 + 管理员口令（这台机器的 WSL 只能验到"包进得来"那一半）。

### 需要用户点头才能做的两件事
- 唤醒/解锁并使用那台个人鸿蒙真机（#45/#46 + 鸿蒙发现真机腿）。
- 跑 `pack --iscustom`（Android 自定义基座，#36/#90 的钥匙）。

## 7. 已知平台坑（写给下一次动手的人）

- **Windows**：第二个进程能 bind 一个正在服务的端口，所以任何"端口占用/单实例"判断都要先连上问一次。
- **Android**：`am force-stop` + `monkey` 重启；私有文件用 `run-as cat`（AVD 未 root，`pull` 是 Permission denied）；
  `uiautomator dump` 每次 4–8 s，可被打断的窗口只有一个块体那么长，所以按钮要**先量一次坐标再盲点**；
  `scroll-view` 不给视口外的节点排版，只往下滚的查找永远找不到卡片顶部那个按钮。
- **鸿蒙**：TLS 记录乱序到达、0x00 截断体、`Connection: close` 丢回复体、Ed25519 签不出服务叶；
  `uitest uiInput inputText` 对页面靠下的框静默无效（先 fling 再点）；`扫码连接` 是 sheet 不是 screen，
  滑动和点击都要留在 sheet 的 y 区间里。
- **本地错误的 `detail` 形状两端不一样**：Android 的 `CsWire` 把平台异常直接写成字符串，鸿蒙的
  `transportError()` 出于一致目的把所有本地错误包成 `{"code":…,"detail":{"reason":…}}`。所以统一口径的位置
  只能是渲染那一层（`cs-protocol.uts::detailOf` 读合同点名的 `detail.reason`，`PEER_BUSY` 再补 `detail.peer`），
  改发射器会顾此失彼（#126）。
- **两台 AVD 互相到不了**：各自的 `10.0.2.15` 不出本机，机对机必须走宿主转发；`adb forward --remove-all`
  要收尾，否则宿主的产品端口一直被占。
- **`.uts` 到 Kotlin 后只保留平台入口再导出的名字**：共享文件里导出的符号若没被 `app-android/index.uts`
  列出，会被 tree-shake 掉，报 `找不到名称"cancelSend"`（鸿蒙/web 不管这条）。

## 8. 索引

- 协议语义与理由：[protocol/spec.md](../protocol/spec.md)；合同本体：[protocol/protocol.json](../protocol/protocol.json)
- PC 端工程、界面、打包、i18n：[README.md](../README.md)
- 手机端工程结构、验收口径、平台账、待办：[mobile/README.md](../mobile/README.md)
- vendored 合同校验：`py -X utf8 mobile/scripts/check_protocol.py`（改协议的正确顺序：先改根目录 `protocol/`，
  跑 PC 自测，再 `vendor_protocol.py` 重新 vendor 并刷新 `SOURCE.json`）
