# 传书 ChuanShu — 手机端（uni-app x）

一套代码出 Android 与 HarmonyOS Next。iOS 自 2026-10-24 起终止：没有 Mac 就出不了可签名的包，
`utssdk/app-ios/` 那两半边代码留在树里不再推进（协议契约的 vendored 副本、它的校验器，以及一个已经
能用 HBuilderX CLI 编译的 uni-app x 工程（`chuanshu/`）都在仓库里）。

**证据口径**：本仓库对手机端的"已验证"分两档写，别混着看。*编译通过*（UTS→Kotlin→dex，没有设备也能
跑完）只覆盖那条路径改得动；跨平台 TLS 的事实（Android 的 provider 不暴露 Ed25519、平台解析器接不接受
手搓的 DER、握手能不能成）一律以**模拟器/真机实测**为准，已经跑过的方向见下面「待办」第 5 条。跨语言
的正确性在桌面上也验过：同一套 Java/Python 实现在这台机器上和 PC 端 `app/net/identity.py` 双向通过。

手机端在整体产品里的位置（与 PC 的 Windows/Linux × GUI/CLI 放在同一张表上比）见
[`../docs/feature-matrix.md`](../docs/feature-matrix.md)；这份 README 讲工程结构与待办，那份讲功能点与证据档。

## 现状

```
shared/protocol/protocol.json   唯一真相源（从 PC 端 protocol/ vendored，只读）
shared/protocol/spec.md         语义与理由
shared/protocol/SOURCE.json     来源戳：仓库、commit、protocol_version、两份文件的 sha256
scripts/check_protocol.py       校验 vendored 副本没被手改 + 契约自身没跑偏
scripts/vendor_protocol.py      从 PC 端重新拉一份并刷新上面那三个文件
chuanshu/                       uni-app x 工程（AppID __UNI__8DB2EF6，目标 APP-ANDROID / APP-HARMONY）
chuanshu/uni_modules/cs-identity/   UTS 插件：能力探针、手搓自签 X.509、回路 TLS 自检（四端各自半边）
chuanshu/uni_modules/cs-transport/  UTS 插件：收发那一半
  ├─ cs-protocol.uts / cs-receive.uts   协议与接收状态机，平台无关，三端共用一份
  ├─ cs-client.uts                      发出去那四条端点（pair/offer/chunk/finalize）
  ├─ cs-discovery.uts                   发现层模型（mDNS 优先、UDP 广播补充、扫码兜底）
  └─ app-android / app-harmony / app-ios / web   各自的平台半边（iOS 那份随 iOS 终止，只留不推进）
chuanshu/store/session.uts            跨页共用的会话：连接、发送、接收、日志都在这一份状态里
chuanshu/pages/home/home.uvue         首页：连接状态 + 连对端（扫码/粘贴/配对码）
chuanshu/pages/scan/scan.uvue         扫码连接页：附近设备名单（发现层）+ 扫二维码或粘贴配对串，解析出卡片再连
chuanshu/pages/files/files.uvue       文件页：收到的文件与待发送的清单
chuanshu/pages/me/me.uvue             我的页：本机身份、配对信息、监听开关、探针入口
chuanshu/pages/send/send.uvue         发送文件页：选文件、发送、进度
chuanshu/pages/detail/detail.uvue     传输详情页（tabBar「传输」）：两个方向的任务 + 日志
chuanshu/pages/probe/probe.uvue       三个按钮的平台能力探针 + 造 5 MB 测试文件发给对端
chuanshu/static/tabbar/               tabBar 图标，由 mobile/scripts/gen_tabbar.py 画
chuanshu/manifest.json                出包口径：鸿蒙 bundleName 与 deviceTypes 都在这儿（bundleName 必须
                                      等于签名描述文件里绑定的包名，否则 HBuilderX 直接报"未正确配置
                                      鸿蒙应用的包名"）；Android 的权限不写在这份里，写在插件的
                                      `uni_modules/cs-transport/utssdk/app-android/config.json`（组播锁
                                      那条就在那儿声明着，但标准调试基座不带它——见「待办」第 4 条）
```

```powershell
py -X utf8 scripts/check_protocol.py
```

它在三件事上给结论：输出里的 commit 等于 `SOURCE.json` 的 `source_commit`（那个号以文件里写的为准，
别抄进文档，抄一次就 stale 一次），否则就是副本被手改过；契约自身没跑偏（错误码、端点、分块、配对码
口径）；`cs-protocol.uts` 与合同镜像一致。改协议的正确顺序：先改本仓库根目录的 `protocol/`，跑 PC 自测，
再 `py -X utf8 scripts/vendor_protocol.py` 重新 vendor 并刷新 `SOURCE.json` 的 commit 与摘要。

编译链（不需要真机，也不需要 HBuilderX 图形界面）：

```powershell
& "F:\HBuilderX\cli.exe" compile app-android --project chuanshu --uni_module cs-identity
& "F:\HBuilderX\cli.exe" launch app-android --project E:\wowo3\mobile\chuanshu --compile true
& "F:\HBuilderX\cli.exe" launch app-harmony --project E:\wowo3\mobile\chuanshu --compile true --buildType debug
& "F:\HBuilderX\cli.exe" pack --project chuanshu --platform android --precheck true
```

第一条把插件编到 Kotlin 字节码；第二条和第三条编译**整个应用**（`.uvue` 页面一起），不需要接设备，
鸿蒙那条还会顺带把 hap 签好名。`--file` 只能指 `.uts`，所以别拿它验页面。**两条 launch 都以退出码
0 结束，无论成败**：只认日志里的 `编译成功` / `kotlin编译失败` / `运行包制作成功`。
第四条只做打包前的配置预校验，**不会**提交云打包、不扣费。真正出安装包要 `pack --iscustom true`，
那一步用你的 DCloud 账号，别顺手跑。

## 两端共用同一套验收

协议不看谁实现都得遵守同一条约定，所以手机端**不能只信 PC 端跑绿了**。要落地的是：

1. 身份：一台设备两个摘要（`spec.md` §1）。Ed25519 密钥只签配对，信任锚是它的 SPKI SHA-256；套接字
   递出来的是一张 RSA-2048 自签叶（CN=peer_id），二维码的 `f=`、广播前缀、TLS 钉子钉的都是叶的摘要。
   两个都不是 peer_id。为什么不能是一把钥匙：Android 的 Conscrypt 不广告 ed25519、鸿蒙的平台 TLS 签不出
   Ed25519 叶，PC 因此也跟着挂独立叶。
2. 七个端点、`X-Chuanshu-Auth` token、`X-Sha256` 分块摘要、`X-File-Size`。
3. 路径清洗（`spec.md` §5）——手机当接收方时这条同样致命，不能因为"手机不跑 Windows 保留名"就省。
4. 断点续传：状态文件只是提示，结论只来自 `finalize` 的整文件摘要。被摘要推翻的那本台账当场作废、缺块
   列表跟着改口成全缺——留着它，发送方最后那一手（整单重发）会被逐块的"已经存过"挡回来，一个字节也写不回去。

## 平台账（写代码前先认清成本在哪）

| 端 | 必须做 | 卡在哪 |
|---|---|---|
| Android | 接收中起前台服务（`dataTransfer` 类型）、13+ 通知权限、局域网权限 | 服务被杀 = 连接被掐 |
| ~~iOS~~ | **2026-10-24 终止**：出包要 Mac 与签名，这台机器没有。剩下两条事实记在这儿，别当待办 | Info.plist 里 `NSLocalNetworkUsageDescription` + `NSBonjourServices` 声明 `_chuanshu._tcp`；**退后台后监听 socket 不再接受新连接**，协议层绕不过 |
| HarmonyOS Next | uni-app x 走 ArkTS 通道；mDNS 用 `@kit.NetworkKit` 的 `mdns` | 卓易通这类 APK 兼容层发不了 UDP 广播，发现只剩扫码 |

鸿蒙（和被终止的 iOS）的后台限制属于产品事实，处理方式是在"接收中"界面直说"请保持传书在前台"，而不是
让用户以为还在收。这是 `spec.md` §6 的口径，Android 与鸿蒙一致。

手机这一端的接收有三份记忆，都写在本 App 的沙箱里：固定过的对端、没传完的单、以及传完且校验通过的文件
（`chuanshu-receiver-trust.json` / `chuanshu-receiver-offers.json` / `chuanshu-receiver-arrivals.json`）。
第三份是后来补的，因为前两份都回答不了"收到的文件"这张卡的标题：续传台账在单子完成的那一刻就把它去掉了
（一份写着不可能续传的清单只会让下次开机把它当成那一单），于是重启后屏幕上一个都不列，而磁盘上还躺着两个。
现在卡片每次刷新都拿这份记录逐个问一次文件系统——还没落地就说落到哪儿，已经不在了的那一行仍然留在列表里
并说自己不在，而不是悄悄少一项让人去猜。口径与 PC 的 `arrivals.json` 一致。

## 探针在真机上要回答什么

`cs-identity` 的三个导出函数按"最后一行写到哪"读，而不是只看有没有报错：

| 函数 | 回答的问题 | 失败时最关心的那一行 |
|---|---|---|
| `identityProbe()` | Android 自带 provider 里有没有 `Ed25519`，`getEncoded()` 是不是 44 字节 SPKI，PKCS12 + KeyManagerFactory 能不能起来 | `stopped here:` |
| `certProbe(peerId)` | 平台 `CertificateFactory` 接不接受我们手搓的 DER，签名能不能被外人验过 | `parsed:` / `stranger rejected:` |
| `tlsSelfCheck(peerId, port)` | App 内的 HTTPS 服务能不能和"只信这一张证书"的客户端握手成功，且换一张证书就被拒 | `pinned match:` / `stranger REJECTED:` |

浏览器目标下走的是 `utssdk/web/index.uts`：它明说浏览器没有 `java.security`、也开不了 TCP，所以三个按钮在浏览器里的输出**不是证据**，只是界面与路由通了。这个文件存在的唯一理由是 `import ... from '@/uni_modules/cs-identity'` 在非 App 平台也要能解析——只有 `app-android` 目录时，web 端会直接 `Cannot find module`。

三个都不依赖第二台设备，`tlsSelfCheck` 走 127.0.0.1。设备之间怎么连已经不是待验证的假设了：PC 与手机
双向都跑过真机/模拟器回归，见下面第 5 条。

不引 BouncyCastle 是刻意的：UTS 插件里的三方依赖要云打包时才从仓库拉，这台机器到那些仓库没有可
靠路线。证书改用手搓 DER（约 236 字节），只需要 JDK 自带的 `Signature`/`MessageDigest`/
`CertificateFactory`。桌面侧同一套构造已经跑通：`E:\wowo3\.probe\probeB\` 的 Java 实现与 PC 的
`app/net/identity.py` 双向 9 项全过，含"前缀不符要拒"和"陌生指纹要拒"两条负例。

## 待办（按依赖排序）

1. ~~HBuilderX 建 uni-app x 工程~~（已建，Android 与鸿蒙两个目标都开着）
2. ~~UTS 侧实现身份与 TLS 指纹固定~~（Android `java.security` + 手搓 DER，鸿蒙 `@kit.CryptoArchitectureKit`；
   两端各自的服务叶见 §1 的两个摘要。iOS 那条随 iOS 一起终止）
3. ~~接收端服务~~（Android 前台服务 + pending 立即应答 + 重启不丢固定对端；鸿蒙仅前台可用，UI 按 §6 直说）
4. 发现：mDNS 优先、UDP 广播补充、扫码/手输兜底（顺序不可颠倒，也不能只留 mDNS）。两条通道的代码与
   设备侧规则都在（`cs-discovery.uts` 一份模型，三端共用），**卡在一件事**：Android 的组播锁要
   `CHANGE_WIFI_MULTICAST_STATE`，而它得打进自定义基座才生效——`pack --iscustom` 花的是用户的 DCloud
   账号，所以这一步等用户点头。鸿蒙的 `@ohos.net.mdns` 那半边同理待上机。
5. 真机/模拟器互传回归。跑过的方向，结论都停在**接收方自己重算 sha256 逐字节比对**这一层，不是"两边都
   说了 ok"：PC↔鸿蒙（双向，真机 + 模拟器）、鸿蒙↔鸿蒙（两台模拟器）、PC↔PC、Android 收 PC 发、
   Android 发 PC 收（#106）、**Android↔Android 双向（#116，`.probe/a_116.py`）**。
   机对机那一条要记住宿主是唯一的路：两台 AVD 各自的 10.0.2.15 互相到不了，所以接收方
   `adb -s <收> forward tcp:<宿主端口> tcp:43720`，发送方拨 `10.0.2.2:<宿主端口>`；粘过去的那串
   只许挪 `h` 与 `p`，`f=` 保持接收方自己 announce 的原样——那是它这一轮真正递出来的叶。反向那一腿
   （先前被拨出去的那台现在当接收方）也连上了，说明"拨出去过"不等于"进不来"。
   同一单里的其它形状现在都上机跑过了：中文目录与多文件带目录（#125，安卓和鸿蒙两条腿各把三份一次发出，
   PC 侧逐字节比对）、中途杀进程续传（#127，`.probe/a_127.py` 在安卓模拟器上两条腿：接管后只补尾巴并逐字节
   一致；台账说"全有"而文件已经被删掉时，`finalize` 拦住并当场改口缺 `[0, 1]`，整单重发随后落对）。鸿蒙那一端
   的判据就在共用的 `cs-receive.uts` 里，但这一趟没在鸿蒙上真杀过一次接收，`app-harmony/index.uts::storeWrite`
   那一处本端改动仍停在 `编译门`。
6. **#128：手机接收目录是平铺的**。PC 落 `接收根目录/<offer_id>/<relpath>`，手机落 `接收根目录/<relpath>`，
   所以同一个 `relpath` 被第二单送到时，后一单 accept 里的预分配会把前一单**已经校验过**的交付截断重写。
   #127 第二条腿原本的前提是"两块写完、删文件、看台账撒谎"，第一次跑就不成立——上一单同名的完整文件就躺在
   同一个路径上。修法两条：按单建目录（与 PC 对齐，`arrivals` 与卡片路径跟着改），或名字撞了加后缀并把最终
   落点记进 `file.dest`（`state`、卡片、`finalize` 的 `path` 都读 `dest`，改动面小）。

M2a 的最小切口是"手机发、PC 收"：扫（或粘贴）PC 的二维码拿到地址与完整指纹，用户只核对同屏的
一次性配对码——PC 侧接收端已经跑绿，手机只要把
`/v1/pair`、`/v1/offer`、`PUT chunk`、`/v1/finalize` 四条打出去就能有结论，发现层可以先不做。
这条切口在 #106 上撞到的不是网络：手机拨不进 PC，是因为 PC 当时把自己那把 Ed25519 身份密钥直接当 TLS
叶递出来，而 Android 的 TLS 客户端不接受这种服务器证书（同一个端口换成 RSA-2048 叶就握手成功）。
现在三端一致：身份密钥只签名，套接字只递独立签发的 RSA 叶。
