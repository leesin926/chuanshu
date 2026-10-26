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
| Android | 接收中起前台服务（合同 §6 写的 `dataTransfer` 在 Android 14 正式版改名 `dataSync`，权限是 `FOREGROUND_SERVICE_DATA_SYNC`）、13+ 通知权限、局域网权限 | 服务被杀 = 连接被掐；而这两项都要打进**自定义基座**才落得进安装包（标准调试基座是别人的 APK，清单里没有我们这个 `<service>`） |
| ~~iOS~~ | **2026-10-24 终止**：出包要 Mac 与签名，这台机器没有。剩下两条事实记在这儿，别当待办 | Info.plist 里 `NSLocalNetworkUsageDescription` + `NSBonjourServices` 声明 `_chuanshu._tcp`；**退后台后监听 socket 不再接受新连接**，协议层绕不过 |
| HarmonyOS Next | uni-app x 走 ArkTS 通道；mDNS 用 `@kit.NetworkKit` 的 `mdns` | 卓易通这类 APK 兼容层发不了 UDP 广播，发现只剩扫码 |

鸿蒙（和被终止的 iOS）的后台限制属于产品事实，处理方式是在"接收中"界面直说"请保持传书在前台"，而不是
让用户以为还在收。这是 `spec.md` §6 的口径。Android 有机制（前台服务），但机制不是保证：清单、类型权限、
通知权限任何一项读不出来，那句话就同样回到 Android 的卡片上——挂不上的保活和不挂等价（#143，两端同一句
文案在 `store/session.uts::armHold`）。

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
   —— 这一条的"Android 前台服务"在 2026-10-26 之前只是账面上的：`CsKeepAlive.kt` 与它的清单、权限那天才落地
   （#143），而它在这一台标准调试基座上必然挂不上，界面上因此显示的是那句退让的话。真挂上要等自定义基座。
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
   一致；台账说"全有"而文件已经被删掉时，`finalize` 拦住并当场改口缺 `[0, 1]`，整单重发随后落对）。鸿蒙那一端也照同形
   跑过一遍（`.probe/h_127.py`，四条判据全 YES，原文 `.probe/h_127.txt`）：`app-harmony/index.uts::storeWrite` 去掉
   的"写入超出文件末尾"那一拦，量的就是续传写进一个已被删掉的文件——`openSync(READ_WRITE | CREATE)` 落回上一块之后的
   偏移，不是从零重写。那一趟还顺手量出一条发送端的规则（#130）：4 MiB 体在 40 ms 下限被 fport 连吐三次时，
   先问一次 `state`，对方说没到就重写那一块，而不是把整单判死。**这条现在也在手机共用的发送方里了**（#132，
   `cs-client.uts::putChunk`）：合同那句话说的是"发送方"，不分端。它已经升到设备档位了——先前那句"打嗝造不出来、
   所以没有上机复现"是错的：造不出**管道自己**的打嗝，但能造一个**会吞回复的对端**，而合同 §4 那条支判的正是
   "回复没来"这件事本身。#133 用 `.probe/a_133.py` / `.probe/h_133.py` 在两台模拟器上各喂了四种形状
   （`held` / `blind` / `dead` / `mute`），八条腿全 `PASS`；H5 那边同一支现在是 14 项四条腿（#135 补上 `mute`）。
   取消那两级也都上机过：A 级那句（还没发出去就收回）是 #134，B 级那句（掐掉正在写的那一块）在 #132 之后
   重跑了一遍（#136，两台各一趟）——要守的是"本机自己收回"没被 `putChunk` 新加的那一支当成"回复没来"去问
   `state`，判据是对端账本里**只上过线一次**。PC 同一支的对应改动是 #137（`_chunk_landed` 变三态）。
   这里只剩一件事没结：**自然发生**的那一次（目前只有 #130 在鸿蒙 40 ms 下限上自己撞出来过一趟）。
6. ~~**#128：手机接收目录是平铺的**~~（已修，选的是"按单建目录"那一条）。现在手机与 PC 同形：
   `接收根目录/<offer_id>/<relpath>`，落点记在共用状态机的 `land` 字段里（`cs-receive.uts`：写分块、算整文件
   摘要、回收停摆单、卡片行、`state` 回的 `path` 读的都是它），旧的续传台账与收件箱文档没有这个字段，
   `landingOr` 把"空 `land`"解释成当年的平铺位置——那些字节确实还躺在那里，不能一升级就把上一单判成不在了。
   上机结论：安卓 `.probe/a_128.py` 三条腿 `PASS`，鸿蒙 `.probe/h_128.py` 三条腿 `PASS`（同名两单各起一个目录、
   前一份摘要一个字没变、卡片为这两单各留一行），H5 那 56 项按新落点键重跑过。鸿蒙本端没改：
   `app-harmony/index.uts::storePrepare` 本来就 `mkdirSync(parent, true)` 再 `truncateSync`。
7. **#141：手机收的"拨出去过"那座桥记错了号**（代码已修，两道编译门 + `接收自检 59 项` 都过；**安卓的设备腿已跑到 `模拟器`，鸿蒙那一端还欠**）。
   #116 那条反向腿证的是"先前被拨出去的那台现在也能当接收方"，它俩各自都带着配对码上线，所以没碰到 §3 里
   真正留空码的那一支：已经固定过对方的一台**不再发配对码**（`pair|peer_id|nonce|tls_fingerprint` 的签名就是它的
   凭证）。手机为拨出的地址钉的是那台机器**serve 的叶**，而 `cs-receive.uts::pairReply` 只按**身份摘要**认人——
   #47/#106 以后每一端都serve独立 RSA 叶，这两个数从此不相等，于是回拨的一台掉进陌生人分支，被要一个它拿不到的码
   （`403 BAD_PAIR_CODE`，现象是"明明连过对面，对面却连不回来"）。现在三个平台的地址钉都多存一格身份摘要
   （Android `chuanshu-trusted.json` 的 `identity`、鸿蒙那行第 6 个字段），旧记录由 pair 请求自己补：调用方把
   自家叶写在签过名的字节里，声明与钉住的叶一致才补这一格。留空码那条腿在**安卓模拟器**上跑过了（`模拟器`，
   2026-10-27，原文 `.probe/a_149.txt`：先让手机第一次拨出去把叶钉在 `10.0.2.2:43720`，再由出货的 `app.cli send`
   带着空码回拨——屏上答的是 `resumed=true`，200 000 字节落 `files/chuanshu-receive/56fd1a68d956ee6b/a149.bin`
   且逐字节一致；对照腿只换进门的路（`adb forward`，手机上看起来是 `127.0.0.1`），同一份请求体就换回
   `对方不认识这把钥匙…用 --code 传给我` 且一个字节都不落。鸿蒙那一端同一形状的另一份代码仍然欠，见 §6 第 9 条
   （[docs/feature-matrix.md](../docs/feature-matrix.md)）。
8. **#142：局域网点中的候选，核对发生在配对之后**（代码已修，两道编译门 + `发送自检` 那几条腿都过；设备腿两端都在模拟器上跑到
   `模拟器` 档——鸿蒙跟着 #150 那一趟（见第 13 条末尾），安卓补在 2026-10-27（`.probe/a_154.txt` 末段 + `.probe/a_154_card.png`，见第 14 条）。
   §2 要的是"收到候选后必须先核对前缀再进入 §3 配对"，而手机把这句话放在了错的地方：`pinPrefix` 只在扫过码之后
   才有值，从名单点中的那一行只把前缀记在 `discPicked`，共用的 `cs-client.uts::helloPeer` 拿不到东西，核对于是被
   推到 `markConnected`——那时候 `/v1/pair` 已经打完，对面已经把这台落成固定、把单会话名额占掉，才发现"这不是刚才
   广播的那台"。合同这句话 PC 一直是对的（`app/net/discovery.py:122` 在握手时比，比不过直接抛），这次是把手机补齐。
   当时补齐的那一版比的是对方在 `hello` 里自己声明的 `served`，还差一层——**那一层由 #150 补上了**，见下面第 13 条。
   设备腿见 §6 第 11 条。
9. **#144：§7 的版本交集，手机两边各只拿了一半**（代码已修，两道编译门 + `发送自检 20 / 接收自检 61 / 发现自检 22`
   都过；**安卓的设备腿两个方向都跑到了 `模拟器`，鸿蒙那一端与"故意只报 v2"那一格还欠**，
   见 [docs/feature-matrix.md](../docs/feature-matrix.md) §6 第 14 条）。合同那句是
   「`compatible_versions` 列出双方都能跑的版本集合，取交集非空才继续」，但这一支在手机上是两条各断的腿：发送方
   只看对端在 `hello` 里印出的那一个 `protocol_version`（一台印 1、集合却是 `[2]` 的机器被放行），接收方自带的
   `supports()` 只看对方报的集合（一台在这个字段之前就发清单的机器被当成陌生人拒掉）。而**谁都交集不了**：发送方
   从来没把自家集合送到接收方读得动的地方——接收方不会回拨去读对面的 `hello`。所以判据收回成一份（`cs-protocol.uts`
   导出 `COMPATIBLE_VERSIONS`、`versionsOverlap`、`versionsText`，`cs-receive.uts` 里那份私有的 `supports()` 删掉），
   集合跟着 `pairJson`/`offerJson` 的请求体走，`pair` 的应答把它在 `hello` 里说过的话重述一遍；没报集合按它印出的
   那一个数当作整个集合，那是这个字段之前的一版，不是把它当陌生人的理由（与 §3 的 `served` 空值兜底同一条思路）。
   发现层只比一个数，因为 UDP 公告本来就只印得下一个版本号——集合要等 `hello`，那里的注释写着这件事。
10. **#145：同一个 `offer_id` 重发清单会再弹一次窗**（代码已修，两道编译门 + `接收自检 66 项` 都过；**安卓的设备腿
   已跑到 `模拟器`，鸿蒙那一端对着屏的同一趟还欠**，见 [docs/feature-matrix.md](../docs/feature-matrix.md) §6 第 15 条）。合同 §4 那句是「同一个 `offer_id` 只弹一次窗口；
   用户已经拒绝或这一单已经失败的回答按 `offer_id` 记在本场会话里，再问一遍就拿同一份回答，不会因此又去打扰用户」。
   手机确实把回答记进了台账（`settleOffer`），但记账的位置在**两个平台宿主各自的手里**，而它们只覆盖了自己那一支：
   鸿蒙的"拒绝"由 `store/session.uts::receiveDecide` 补写，安卓的那两处在 `app-android/index.uts`，而**两种"这一单已经完了"
   谁都没记**——窗口放到点没人答、以及发送方 `DELETE` 取消。于是一份重投的清单（#96：轮询读不到回答就再投一遍，
   这是发送方该做的事）会把同一个问题再问用户一次，答过拒绝的单还可能被第二张卡片意外接受。现在记账搬回共用的
   `cs-receive.uts`，五个了结处都写：`sweep()` 的到期与闲置回收、`abortReply()`、`resolveOffer()` 的拒绝与
   `STORAGE_FULL` 回滚。三种回答各有各的形状——还在问 → `200 accepted:false`（不占第二个名额）、已经拒绝（含没人答而到期，
   那正是发送方 §4 超时的镜像）→ `403 DECLINED`、已经完了 → `404 OFFER_UNKNOWN`。宿主那两处 `settleOffer` 保留：
   函数自己按 id 去重，写两次不会多出第二行。
   设备上跑的那一趟是 `.probe/a_145_leg.py`（原文 `.probe/a_145.txt`，截图 `.probe/a_145_card.png` /
   `.probe/a_145_answered.png`）：本机对着一台正在监听的安卓模拟器，把**同一个 `offer_id`** 的清单连投几遍，
   每一投之间读一次屏上卡片的张数。窗口里重投＝`200 accepted:false` 且卡还是一张；在卡上点一次「拒绝」，
   之后两投都是 `403 DECLINED` 且卡为 0；另一条腿只投一次、六十八秒里一个请求都不发，那张卡自己收掉
   （`receiveSnapshot()` 里带着一次 `sweep()`，而界面 1 秒一读），之后两投还是 `403 DECLINED`——重发没有把用户
   叫醒第二次。两单都被拒，`files/chuanshu-receive` 腿前腿后一样空。三趟连过。
11. **#146：这台设备的名字改不了**（代码已修，两道编译门 + `接收自检 71 项` 都过；**设备腿还欠**，
   见 [docs/feature-matrix.md](../docs/feature-matrix.md) §6 第 16 条）。合同 §1 的身份五项里只有 `name` 写着
   「用户可改，存 `settings.json`」，PC 早就有这一行，而手机这一端**根本没有能改它的地方**：名字是读出来的——
   安卓 `Build.MANUFACTURER + Build.MODEL`、鸿蒙 `deviceInfo.marketName`、浏览器 `browserName`，屏幕上也就不存在
   一个能让对端认出"这是我的那台手机"的入口。这一支要补的不是一个输入框，是四条线：这个名字会说四次——
   发出去时的 `pairJson` 与清单的 `from_name`（每次发送现取）、自己 hello 与配对回复里的 `name`、局域网公告里的
   `n=`，还有屏上头像那一行；只把变量换掉的话，监听已经抄走的那份和广播已经抄走的那份会一直念旧名字，直到进程重启。
   所以规则与落点分三层：判据（`cs-protocol.uts::nameReject` / `nameWithDefault`）**只有一份**，PC 那条规则就是
   trim 之后非空、合同不给长度，手机不许自己发明上限；组合（存过的顶掉默认、空的才回落）也在同一份里；
   存储各家自己管——安卓 `CsIdentity.kt` 的 `storedName/saveName`（`self()` 从此不再附 `name`，因为 §1 那条规则
   该由 UTS 那层说一次），鸿蒙 `app-harmony/index.uts::deviceName()` 先读 `settings.json` 的 `device_name`，
   浏览器只能存在模块变量里（**这一端没有私有目录，所以关于重启的任何说法在这里都无法证明**，设备腿就是这么欠着的）。
   刷副本的位置按平台不同，因而是分支而不是"一条统一规则"：安卓与浏览器在 `deviceNameSave` 里就把 hello 与公告
   那两份改掉；鸿蒙的接收状态机跑在页面旁边（`harmonyReceive`），`recvSelf`/`discName` 是 store 的变量，于是由
   `store/session.uts::applySelfName` 在写成功之后把 `recvSelf` 丢掉、下一次请求照 `deviceNameText()` 重建。
   改名**不是**重新入网：对端钉的是密钥摘要，名字不在指纹里，所以旧固定照旧、留空配对码照样能 resume。
   UI 那一行有两个状态而不是一个（`s.nameDraft` 是草稿、`s.selfName` 是已经生效的），因为被规则拒掉的那次要留得住
   用户刚打的字，同时屏幕上那行还是旧名字——写进私有目录失败也是同一处理：不显示一个重启后会变回去的名字。
12. **#148：鸿蒙这一端，落盘的路径没核到符号链接**（代码已修，两道编译门 + `模拟器` 腿都过了，见
   [docs/feature-matrix.md](../docs/feature-matrix.md) §3.3 那一行）。合同 §5 那条清单的最后一行写的是「符号链接、重解析点：
   写出前 `resolve()` 一次，若结果不在该 offer 目录内 → 拒绝」，安卓早就按字面做到了（`CsStore.kt` 的 `canonicalFile` 算完再比
   前缀），鸿蒙这一端却只有一句"这平台没有 realpath"的注释就算过关——**这句注释是错的**，它把"没有那一个调用"说成了"做不到"。
   `@ohos.file.fs` 确实查不到 `realpath`，能问的是 `fs.lstatSync(path): Stat` 配上 `Stat.isSymbolicLink()`，于是这一条不是照着
   安卓抄，是换一种问法：从接收根往下**一环一环问**，任何一环是链接，整条路径就不作数；问到不存在的那一环就停下（不在＝后面
   更不会在，剩下的由 prepare 那句 `mkdirSync(parent, true)` 补出来——不然续传会死在一个刚被回收掉的目录上）。用 lstat 而不是
   access 是这里的要害：`accessSync` 跟着链接走，一个悬空的链接它正好答"没有这个文件"，写入于是顺着那条链接出去了。
   守卫只有一份，落在 `app-harmony/index.uts::recvPath` 这个咽喉上——这一端把 relpath 变成磁盘位置的地方只有它，六个调用点
   全从它走，所以既不用抄第二遍，也漏不了一处。屏幕上加了一个「接收路径守卫读数」的按钮把这些问出来，包括那句造不出来的：
   `fs.symlink` 从 API 11 起只对系统应用开放，模拟器的 shell 又是 uid 2000、连这个沙箱都进不去，所以**"中间那一环真的是链接"
   这一支只有代码读，没有设备上的一跑**——那一行把这个边界印在屏上，而不是报成过了。
13. **#150：§2 那句核对，手机此前比的是对方自己写的那句话，不是套接字**（代码已修，三道编译门 +
   `发送自检 24 / 接收自检 71 / 发现自检 29` 都过；**设备腿两端都在模拟器上跑到 `模拟器` 档**（鸿蒙 `.probe/h_150.txt`，
   安卓 `.probe/a_154.txt` 末段，见第 14 条），见
   [docs/feature-matrix.md](../docs/feature-matrix.md) §6 第 11、12 条）。#142 把"先核对再配对"的顺序改对了，可比的东西还是
   错的：`cs-client.uts::helloPeer` 读的是对端在 `hello` 里自报的 `served`——而那个前缀本来就是对面广播出去的，一台抢了
   公告的机器把前缀**抄回来**就过了这一关。合同那句写的是「核对发生在套接字上，读回来的是对方实际递出的那张证书的摘要」，
   PC 一直照这句做（`app/net/discovery.py:122` → `identity.read_fingerprint`，在写请求行之前就比）。三端的套接字层其实
   早就拿到了真摘要（鸿蒙 `httpRun` 的 `out.fp`、安卓 `PinTrust.seen`、iOS 同形），只是没交给调用方，于是这一支补在
   真正的位置上：判据收成一条 `cs-protocol.uts::pinAccepts`——**整摘要比全等，不足 64 位就比 `startsWith`，空钉放行
   （第一面的信任由配对码带），读不出证书永远不放行**；广播里那个 16 位前缀从此**直接当 TLS 钉用**（`callWire` 交的是
   `activeOptions.pinPrefix`，不再是只有扫过码才有的 `s.scannedFp`）。顺带把"谁说话"的优先级写在这里：从名单点中那一行，
   过去由钉表（`pinFor(host, port)`）判，现在由公告判，钉表只在没有公告时才开口——扫码那一条一直就是这个口径，#150 只
   是把名单那一行并进同一个位置；钉表里那条陈记录不挡路，配对成功那一步会被这一程握手看到的摘要改写它。宿主三边各重述一份，是因为这三处都 import 不了
   `.uts`：安卓 `CsWire.kt::checkServerTrusted`、鸿蒙 `app-harmony/index.uts::httpRun`（在拼请求体之前）、iOS
   `CsWire.swift`（**这一端已终止，改动只读不跑**，改它是因为共用的 store 现在会递一个前缀过来，整摘要比较会把那样一局
   的每个请求都判死）。`PeerSession.peerServed` 这个字段随之删掉；名单补全完整摘要改从 `pinnedFor()` 取——那正是握手时
   写进钉表的那个数。浏览器这一边由 `web/index.uts::pinnedCaller` 充当那只 socket，所以 E 腿现在的判据是 `hellosSeen == 0`：
   前缀对不上那一单**连 hello 都没打到对方**，对方的固定名单还是空的，报出来的是「对端证书与要核对的指纹不符」（#153 之前那句写的是「与已固定的指纹不符」）而不是配对码
   的错；对照那两趟是前缀对得上的照常传成（整程只放行一次 hello）和二维码那种 64 位整摘要照常放行。发现自检里新增的 3b 组
   七条腿打的是这条规则本身。扫码页那句对用户的话也跟着改了：原来写「连上以后会拿 TLS 上读到的完整指纹跟它自己广播的
   前缀对一次」，那是 #142 那一版的口径（而且比的根本不是 TLS）；现在说的是"拨过去的第一件事就在这条连接的 TLS 握手上，
   对不上就在这里断掉，配对码根本不会发出去"。**上机要多看一眼的新形状**：一台在广播之后换过叶的对端（重启过、或公告本来就陈了）现在会被
   这一端拒绝，那句要说得出「广播里报的是 xxx…，这台在 TLS 上递出来的是 yyy…」，修法是把那一行重新点一次或重扫码，
   不是重试连接。**这一趟已经跑过**（鸿蒙模拟器 `127.0.0.1:10001`，原文 `.probe/h_150.txt`）：公告由
   `.probe/mdns_150.py` 手搓一条 `_chuanshu._tcp.local.`（这台模拟器在 QEMU slirp 后面，主机发的 UDP 广播进不去——
   `decoy_announce.py` 打 `255.255.255.255` 和 `10.0.2.255` 都试过，名单诚实地说「两条通道都没听到设备」；但 slirp 会把
   `224.0.0.251:5353` 的 mDNS 反射进 guest），地址填 guest 拨得通的 `10.0.2.2`，TXT 里的 `fp` 由这一次运行说了算。
   假的那一趟（`fp=0badc0ffee000000`，端口与配对码都用真监听的）屏幕收在「对端证书与已固定的指纹不符，已中止 广播里报的是
   0badc0ffee000000…，这台在 TLS 上递出来的是 3b0108120c6000ee…」（#153 之后同一趟重读成「与**要核对的**指纹不符」，`.probe/a_153_harmony.txt`），对端 `.probe/emu/recv.log` 那一段时间**零条请求行**；
   换成真前缀那一趟日志里是「按广播里的指纹前缀钉住 10.0.2.2」→「对端 PC-probe-receiver fp=09947c0b52872289…」→
   「已核对：3b0108120c6000ee 这台机器在 TLS 上就是它自己（3b0108120c6000ee…）」，对端同期拿到 `GET /v1/hello`、
   `POST /v1/pair` 各一条 200。那两个数正好把这一支说完：**自报的身份摘要只被抄去记账，定性用的是从握手读回的叶摘要**。
14. **#153：判死那句话说的是"已固定"，可广播前缀那一趟一个钉子都没有**（代码已修，`模拟器` 两端各读到一次）。
   共用那一份 `cs-client.uts::pinText` 过去写死「对端证书与**已固定的**指纹不符，已中止」，而从名单点中那一行手里只有
   广播里那 16 位前缀——同一张卡片下面一行就写着「10.0.2.2 还没有固定过」，那句话在说自己没钉过的东西时"与钉不符"。
   现在共享那一句只说要核对、不猜它是哪一种（「对端证书与要核对的指纹不符，已中止」），是哪一种由宿主在数字前面补标签：
   长度 64 位＝`已固定 `，短的就是 `广播里报的是 `（`app-android/CsWire.kt:146`、`app-harmony/index.uts:1862` 各一份，
   这两处 import 不了 `.uts`，与 #150 那三条重述同一个理由）。屏上落地的四条合账在 `.probe/a_153.txt`，档位都是 `模拟器`：
   安卓×已固定（`.probe/a_153_pin_ok.png`，本机有钉、对面换了证书）；安卓×广播里报的是（`.probe/a_154.txt` 末段 +
   `.probe/a_154_card.png`，假公告由控制台 UDP 转发 `redir add udp:43722:43721` 喂进名单，点中、填**真**配对码与密码、按连接，
   11.7 秒后屏上「…广播里报的是 0badc0ffee000000，收到 3ae1fc93c61c7b73…」，对端那一段时间一条请求行都没有，只留
   `SSLV3_ALERT_CERTIFICATE_UNKNOWN`——`CsWire.kt` 那句 `CertificateException` 的文本没被平台吞成"连不上"，两个数都到了屏上）；
   鸿蒙×广播里报的是（`.probe/a_153_harmony.txt`）。**没证到的那一格照实说**：鸿蒙×已固定（本机真有钉、对面换证书）
   没有纹身上去，`index.uts:1862` 里 `expected.length == 64 → 已固定` 那一支是照安卓同一条规则抄的，只过了编译门。
   这一趟顺手量出安卓发现腿的三条 harness 规则（`.probe/a_153.txt` 末尾）：控制台那条 UDP 转发会**静默失效**，每一趟都要
   先 `redir del` 再 `redir add`；guest 本机 `nc -u` 打自己的 43721 一个包都不到（`UdpNoPorts` +2、`UdpInDatagrams` 不动）；
   转发包以 `Inet4Address` 原样到达，所以「名单听不到外机」从来不是 `CsDiscovery.kt` 里那个 `is Inet4Address` 筛的——
   先前那句注释怀疑错了对象，已按实测改掉，`asIPv4OrNull` 留着只做 v4-mapped 归一化。

M2a 的最小切口是"手机发、PC 收"：扫（或粘贴）PC 的二维码拿到地址与完整指纹，用户只核对同屏的
一次性配对码——PC 侧接收端已经跑绿，手机只要把
`/v1/pair`、`/v1/offer`、`PUT chunk`、`/v1/finalize` 四条打出去就能有结论，发现层可以先不做。
这条切口在 #106 上撞到的不是网络：手机拨不进 PC，是因为 PC 当时把自己那把 Ed25519 身份密钥直接当 TLS
叶递出来，而 Android 的 TLS 客户端不接受这种服务器证书（同一个端口换成 RSA-2048 叶就握手成功）。
现在三端一致：身份密钥只签名，套接字只递独立签发的 RSA 叶。
