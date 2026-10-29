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
2. 七个端点、`X-Chuanshu-Auth` token、`X-Sha256` 分块摘要（发送方必发，接收方只在它非空时才校验——头缺了就照收、不校验）。
   `X-File-Size` 已经不是合同里的分块请求头了：三端都不发也不读，长度比的是清单里那条自己的 `size`（#183 把它从纸上收掉了）。
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

合同给鸿蒙钉的那句「按真机实测结论」，两半都在活设备上量过了（#168，`模拟器`）：退到后台（鸿蒙 `aa dump -a`
读到 `app state #BACKGROUND`、安卓 `dumpsys window` 的焦点换成 launcher 之后才开始问）和灭屏（由
`hidumper -s PowerManagerService` 的两枚表记定住）以后，hello / PUT / state / finalize 四格全部当场答话，
回前台仍是同一个进程，那一份字节逐字节对得上源。这不等于那句「可能被系统掐断」被推翻——模拟器不进 doze，
也没有真机那套省电冻结，所以这三趟证明的是一件更窄的事：**这一端自己不会因为退到后台就把监听收掉**。文案里
那个「可能」照旧不改，真机那一格照旧欠着。安卓那一趟跑的是**没挂上保活**的标准调试基座，所以它量的不是保活
本身（那一支仍要自定义基座，见 `docs/feature-matrix.md` §6 第 13 条）。

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
   前一份摘要一个字没变、卡片为这两单各留一行），H5 那 56 项按新落点键重跑过（`接收自检` 的项数此后随
   #141/#144/#145/#146 一路涨到 71 项，那一趟的 56 项是当时的数）。鸿蒙本端没改：
   `app-harmony/index.uts::storePrepare` 本来就 `mkdirSync(parent, true)` 再 `truncateSync`。
7. **#141：手机收的"拨出去过"那座桥记错了号**（代码已修，两道编译门 + `接收自检 59 项` 都过；**安卓、鸿蒙的设备腿都跑到了
   `模拟器`，只有"桥接采纳"那半个正腿在一台 DevEco 模拟器上造不出来**，见本项末尾）。
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
   `对方不认识这把钥匙…用 --code 传给我` 且一个字节都不落。
   鸿蒙自己那一支（`store/session.uts::harmonyReceive` + `identityForAddress`，与安卓的 `recvHandle` 是两份代码）也在
   DevEco 模拟器上量过了（`模拟器`，2026-10-27，原文 `.probe/h_154_leg.txt`，脚本 `.probe/h_154_leg.py`）：第一次拨出
   那趟把钉写成了 6 个字段（第 6 格是身份摘要 `e5fb55e5a145a008…`，`.probe/h_154_phone_pins.txt`），随后**对照腿**用同
   一把钥匙、空配对码、走这台机器唯一可用的门（`hdc fport tcp:43745 tcp:43720`）打进去——403 `BAD_PAIR_CODE`、落盘目录
   一个字节没有、收的那份账本没长；**路腿**只把码加上，同一把钥匙同一条门，`/v1/pair` 应了（对端=手机 · emulator），
   清单在屏上被按过接受后落地 200 000 字节，`files/chuanshu-receive/7210e1b1bb2528e7/h154.bin` 逐字节一致（本地重算
   sha256）。这两条腿把"这个现象在鸿蒙宿主的代码上是真的、且它其余部分都通"钉住了，可它们**证不到采纳那半边**：这台
   模拟器没有任何一条门能以"我拨出去过的那个地址"示人（`fport` 给 guest 的来源是 `127.0.0.1:<临时口>`，`.probe/h_154_src.py`
   与 `.probe/h_154_slirp.py` 量过三条路，全不是 `10.0.2.2`），所以桥在那里永远不会被触发。那一格仍是 `编译门` + `浏览器`，
   等一台真局域网里的手机，见 §6 第 9 条（[docs/feature-matrix.md](../docs/feature-matrix.md)）。
8. **#142：局域网点中的候选，核对发生在配对之后**（代码已修，两道编译门 + `发送自检` 那几条腿都过；设备腿两端都在模拟器上跑到
   `模拟器` 档——鸿蒙跟着 #150 那一趟（见第 13 条末尾），安卓补在 2026-10-27（`.probe/a_154.txt` 末段 + `.probe/a_154_card.png`，见第 14 条）。
   §2 要的是"收到候选后必须先核对前缀再进入 §3 配对"，而手机把这句话放在了错的地方：`pinPrefix` 只在扫过码之后
   才有值，从名单点中的那一行只把前缀记在 `discPicked`，共用的 `cs-client.uts::helloPeer` 拿不到东西，核对于是被
   推到 `markConnected`——那时候 `/v1/pair` 已经打完，对面已经把这台落成固定、把单会话名额占掉，才发现"这不是刚才
   广播的那台"。合同这句话 PC 一直是对的（`app/net/discovery.py:122` 在握手时比，比不过直接抛），这次是把手机补齐。
   当时补齐的那一版比的是对方在 `hello` 里自己声明的 `served`，还差一层——**那一层由 #150 补上了**，见下面第 13 条。
   设备腿见 §6 第 11 条。
9. **#144：§7 的版本交集，手机两边各只拿了一半**（代码已修，两道编译门 + `发送自检 20 / 接收自检 61 / 发现自检 22`
   都过；**两个方向、三道门现在两端都跑到 `模拟器`**——安卓见 `.probe/a_144.txt`/`a_149.txt`，鸿蒙见
   `.probe/h_144.txt`（`.probe/h_144_leg.py` 四格全 `PASS`），见 [docs/feature-matrix.md](../docs/feature-matrix.md) §6 第 14 条）。合同那句是
   「`compatible_versions` 列出双方都能跑的版本集合，取交集非空才继续」，但这一支在手机上是两条各断的腿：发送方
   只看对端在 `hello` 里印出的那一个 `protocol_version`（一台印 1、集合却是 `[2]` 的机器被放行），接收方自带的
   `supports()` 只看对方报的集合（一台在这个字段之前就发清单的机器被当成陌生人拒掉）。而**谁都交集不了**：发送方
   从来没把自家集合送到接收方读得动的地方——接收方不会回拨去读对面的 `hello`。所以判据收回成一份（`cs-protocol.uts`
   导出 `COMPATIBLE_VERSIONS`、`versionsOverlap`、`versionsText`，`cs-receive.uts` 里那份私有的 `supports()` 删掉），
   集合跟着 `pairJson`/`offerJson` 的请求体走，`pair` 的应答把它在 `hello` 里说过的话重述一遍；没报集合按它印出的
   那一个数当作整个集合，那是这个字段之前的一版，不是把它当陌生人的理由（与 §3 的 `served` 空值兜底同一条思路）。
   发现层只比一个数，因为 UDP 公告本来就只印得下一个版本号——集合要等 `hello`，那里的注释写着这件事。
   **鸿蒙那条腿又补上了第三处，也是最后没实现的那半边**：配对串上的 `v=` 过去和 `PROTOCOL_VERSION` 这一个数比，
   现在问的是 `versionsOverlap(COMPATIBLE_VERSIONS, [], v)`——串上那一个数就是对方那份集合的全部，与 PC 的
   `app/net/spec.py:215`（`proto.supports(int(v))`）同一条规则；`COMPATIBLE_VERSIONS == [1]` 时行为不变，`v=1` 照样过。
   **它顺带量出 #157**：那一关判死的时候，`applyConnectText` 只往**传输页**那本账里写了一句，按下「解析」的这一页
   不说话——与 #123 那次"小写密码按下去没有反应"是同一个形状，而探针把"屏上没话"读成了"根本没拨出去"。现在这一支
   走同一个 `refuse()`（`log` + `s.sessionLabel`），成功那一路把上一次那句拒言清回「未连接」。**三端这一格都在屏上读到了**：
   鸿蒙 `模拟器`（`.probe/h_144.txt` 08:13 那一趟，「扫码页上说 | 配对信息读不出来：对端协议版本 v2 本机听不懂」）、
   安卓 `模拟器`（2026-10-27 10:04 `.probe/a_123.py emulator-5554 43937 3` → `.probe/a_157_android.txt`，同一句在卡片下面一行，
   而对端计数器停在 `hello 0 / pair 0`——探针只按「解析」，这一支真的没往外拨）、H5 `浏览器`（vite 5173 上
   `#/pages/scan/scan` 填同一条 `v=2` 串按「解析」，屏上同一句，`performance` 资源表里没有任何一条指向那个地址端口）。
   同一份 bundle 上另外两条腿也各自单跑过（leg1「配对密码：连接密码只有大写字母和数字：p」、leg2「已连接 探针对端
   （首次，已固定指纹）」＋对端 `hello 1 / pair 1`）。
   合上这一格花的是两条先前没写下来的规矩（§6 第 18 条）：**`cli launch app-android --compile true` 只编译、不推设备**，
   那句"编译成功"后面没有 `同步手机端程序文件成功`，就等于设备上一个字节没变——#157 那一格拖了一天，是被这个当成"上机看过"；
   另一条是**这一腿的判据必须带对端的眼睛**，只看屏上那句话，"停在解析"和"拨了但被拒"长得一模一样。
10. **#145：同一个 `offer_id` 重发清单会再弹一次窗**（代码已修，两道编译门 + `接收自检 66 项` 都过；**两端各自对着屏
   跑到了 `模拟器`**——安卓 `.probe/a_145.txt`，鸿蒙 `.probe/h_145.txt` 两趟都 `PASS`，见
   [docs/feature-matrix.md](../docs/feature-matrix.md) §6 第 15 条，那一条已了结）。合同 §4 那句是「同一个 `offer_id` 只弹一次窗口；
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
11. **#146：这台设备的名字改不了**（代码已修，两道编译门 + `接收自检 71 项` 都过；**设备腿两端都在模拟器上跑完了**，
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
   浏览器只能存在模块变量里（**这一端没有私有目录，所以关于重启的任何说法在这里都无法证明**——这一句今天仍然成立，
   欠的那次观察不是由浏览器补的，是两台模拟器各自跑了一趟，见这一条末）。
   刷副本的位置按平台不同，因而是分支而不是"一条统一规则"：安卓与浏览器在 `deviceNameSave` 里就把 hello 与公告
   那两份改掉；鸿蒙的接收状态机跑在页面旁边（`harmonyReceive`），`recvSelf`/`discName` 是 store 的变量，于是由
   `store/session.uts::applySelfName` 在写成功之后把 `recvSelf` 丢掉、下一次请求照 `deviceNameText()` 重建。
   改名**不是**重新入网：对端钉的是密钥摘要，名字不在指纹里，所以旧固定照旧、留空配对码照样能 resume。
   UI 那一行有两个状态而不是一个（`s.nameDraft` 是草稿、`s.selfName` 是已经生效的），因为被规则拒掉的那次要留得住
   用户刚打的字，同时屏幕上那行还是旧名字——写进私有目录失败也是同一处理：不显示一个重启后会变回去的名字。
   设备上跑的那两趟是 `.probe/h_146_leg.py` 与 `.probe/a_146_leg.py`（原文 `.probe/h_146.txt` / `.probe/a_146.txt`，截图
   `.probe/h_146_saved.jpeg`、`h_146_restarted.jpeg`、`.probe/a_146_saved.png`、`a_146_restarted.png`，档位 `模拟器`）：
   在 `我的` 页改成一个新名字并按保存，屏上三处（头像那行、`设备名` 行末的值、输入框里的草稿）一起换成它；从私有目录
   读回 `settings.json`，里面写的就是那一个值（改名前鸿蒙那边还没有这个文件）；PC 拨进来读 `GET /v1/hello`，`name`
   念的是新名字。然后杀进程重开、中途一个键都不按——那句「已保存…」活在内存里，重开后它自己消失了，而三处仍是新名字、
   没有回落成硬件那句（`Build.MODEL` / `marketName`），文件与 hello 都还是它，TLS 递出来的叶前后逐字节一致，最后
   **留空配对码**再配一次照样 `resumed=True`：改了名、杀过进程，旧钉仍认得这台 PC。这一趟在设备上读的是 hello 那一处；
   清单的 `from_name` 与配对回复由 §3.4 那五条 `浏览器` 腿证到"读的是同一个 `self`"，广播里的 `n=` 这一份副本则还没有
   设备上读数（鸿蒙只在 `discOpen` 时才顶掉 `discName`）。
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
   鸿蒙×广播里报的是（`.probe/a_153_harmony.txt`）。~~**没证到的那一格照实说**：鸿蒙×已固定（本机真有钉、对面换证书）
   没有纹身上去，`index.uts:1862` 里 `expected.length == 64 → 已固定` 那一支是照安卓同一条规则抄的，只过了编译门~~
   ——**这一格 2026-10-27 补上了**（`.probe/h_153_pin_leg.py`，原文 `.probe/h_153_pin.txt`，截图
   `.probe/h_153_real.jpeg` / `.probe/h_153_wrong.jpeg`，档位 `模拟器`，鸿蒙 `127.0.0.1:5557`）。钉不是这一趟摆的，
   是 #150 真前缀那一趟留在设备上的，`state` 只用 `hdc file recv` 把它读回来核对：`chuanshu-trusted.json` 上
   `10.0.2.2:43731` 那一条长 64、等于 `.probe/emu/id150/tls-leaf.pem` 那把 SPKI 的 sha256（`3b0108120c6000ee…`），
   所以走的确实是 `expected.length == 64` 那一支。然后同一个地址、同一个端口两趟，每趟两个证人（屏上那句话 + 那个端口上的
   监听自己说了什么）：对的证书 → 「已连接 PC-probe-receiver（沿用旧指纹）」且对端读到 `GET /v1/hello`、`POST /v1/pair`；
   换一把当场生成的 RSA-2048 自签 → 「对端证书与要核对的指纹不符，已中止 **已固定 3b0108120c6000ee…**，这台在 TLS 上递出来的是
   b2abfbfb23a2323a…」，而那一侧自己说「handshake ok, 0 字节应用数据：b''」（`.probe/h_153_foreign.txt`）——握完了手，
   请求头一个字节都没写，这句判死因此不是"没连上"蒙对的。判死之后 `state` 再读一次，钉表还是三行，那匹新马没被钉进去。
   这一趟顺手量出安卓发现腿的三条 harness 规则（`.probe/a_153.txt` 末尾）：控制台那条 UDP 转发会**静默失效**，每一趟都要
   先 `redir del` 再 `redir add`；guest 本机 `nc -u` 打自己的 43721 一个包都不到（`UdpNoPorts` +2、`UdpInDatagrams` 不动）；
   转发包以 `Inet4Address` 原样到达，所以「名单听不到外机」从来不是 `CsDiscovery.kt` 里那个 `is Inet4Address` 筛的——
   先前那句注释怀疑错了对象，已按实测改掉，`asIPv4OrNull` 留着只做 v4-mapped 归一化。
   鸿蒙这一边另量出三条（原因记在 `.probe/h_153_pin_leg.py` 里那几处注释）：手输那行的两个框要按"同一排的两个 TextInput"认，
   填过的框会在 `dumpLayout` 里丢掉 `hint`、端口框又预填着，按 `hint=端口` 找不到它那一趟就拨在默认的 43720 上；
   `dumpLayout` 不报软键盘底下的行，照"滚进可点带再点"的规矩按「连接」会打在数字键上（一趟跑完端口框写着 `43731888888`，
   屏上却还是上一趟的「已连接」），所以按下前后都要把两个框读回来比对；扫码卡片那句状态是进程内存里的，上一趟的会话会让
   这一趟根本不拨号却报「已连接」，`清除对端` 顶不掉它——每一趟先 `aa force-stop` 再起，钉表在磁盘上，跨得过这次重启。
15. **#162：合同逐条巡检第二轮——四处「只有一端照合同做」，四处都补了**（完整账在
    [docs/feature-matrix.md](../docs/feature-matrix.md) §6 第 19 条；手机端受影响的是前三个）。
    - **安卓的服务叶两处**（`ServedLeaf.kt`）：主题 `CN` 过去写 `Build.MANUFACTURER + Build.MODEL`，合同 §1 说的是
      `peer_id`，PC 与鸿蒙都照做——现在读 `CsIdentity.peerId()`（这次新导出），读不到才回落硬件那句。第二处更贵：
      `stored()` 在验完私钥还要 `checkValidity()`，一次时钟倒退就把这张叶判死、重铸出**一把新钥匙**，于是
      `served` 变了，每一台钉过这手机的机器在下一次重启时静默失去钉子——而 §1 的结尾说的是"换了叶要人工重新配对"。
      改前那一趟在旧包上读到过 `stored cert rejected by the clock: CertificateExpiredException` 与摘要换数（同类发作的
      设备旧原文是 `.probe/and_persist.txt` 152-155 那两行 1976 年的有效期，#109 那一回的年份编码）；改后同一趟
      `verdict: PASS`（`.probe/a_162_clock.txt`：一张被日期判死的叶留在架上也照样递出去，架上/套接字/hello 三个读数
      都是 `f693be2bb977…`，`cs-leaf` 一句话没说），`cn` 段另一条腿 `verdict: PASS`（清空架子重铸一次，
      `CN` 与本机 `peer_id` 相等、三处摘要仍是同一个数）。日期那一道现在**故意不读**，只留"DER 解析不出"与
      "证书里的公钥和架上的私钥不是一对"两种重建。设备档位 `模拟器`（`.probe/a_162_leaf.py` 三段：`clock`/`cn`/`restore`，
      改期是重写 TBS 里那两个 UTCTime 再用同一把私钥重签、按原长拼回 718 字节的 DER，`adb root` 推回私有目录后
      按 `stat -c %u:%g` 补属主再 `restorecon`，读回来确认过字节）。编译门 `.probe/c162_android.log`——那一趟打的是
      `uts插件[cs-transport]文件未发生变化，跳过编译` + `项目 chuanshu（模块 cs-transport）编译成功。`，所以它是
      **重跑确认**（盘上这两份就是上一趟真编译过的那一份），不是第一次过门。
    - **鸿蒙的 §3 锁**（`app-harmony/index.uts::dispatch`）：规则一直写在共用状态机里（`cs-receive.uts:44-45`
      的 5 次 / 60 秒，`failCount`/`pushFail` 按调用方交来的 `client` 分桶），缺的是这一端交出去的那个号——过去地址
      读不到就交**连接序号**，而这一端每条请求都开一条新连接，于是猜码的人每次尝试都分到一格新额度，那把锁在这条
      路上永远填不满，首页那句「配对码连错 5 次会锁 60 秒」于是在说一件不发生的事。现在交 `'?'`，和安卓
      （`CsServe.kt:233-236` 的 `?: "?"`）同一格：读不到地址就全落进同一个来源桶，宁可和陌生人同桶也不给它发新额度。
      编译门 `.probe/c162_harmony.log`；共用状态机这一轮没动，所以浏览器那三张自检没有重跑（跑它证不到这一格）。
      **这一格现在欠一条设备腿**：让同一个来源连错 5 次、第六次读到那句 429——造得出来（`hdc fport` 拨进来的来源
      在 guest 看就是同一个地址），下一轮补。
    - **PC 补的那半边不在手机端**，但它量出来的是手机早就做对了的事：`cs-client.uts:218-222` 早就在配对应答的
      `fingerprint` 与 hello 那个数不一致时中止，而 PC 过去把应答里说什么就照抄进信任表（那正是下一次查钉子的键）。
      现在 `app/net/send.py::pair()` 先比再动任何东西，抛本机的 `PeerIdentityMismatch`（不新增错误码：这一支对端
      从不应答），UI 两支与 CLI 一支说同一句话。判据在 `scripts/protocol_selftest.py`：
      `PASS  a pair reply naming another identity is refused`，全文件 `RESULT ALL PASS`。

16. **#163：合同逐条巡检第三轮——§5 后半句「同名文件加 ` (2)` 后缀而非覆盖」三端都没做，三端都补了**
    （完整账在 [docs/feature-matrix.md](../docs/feature-matrix.md) §6 第 20 条）。
    - **可达的触发**不是"两单同名"（#128 已经按单建目录隔开了），而是**同一份清单里两个条目清洗到同一个
      `relpath`**：`ChuanShu-cli send C:\a\report.txt D:\b\report.txt`。CLI 不带 `base` 时 `plan()` 只取
      `Path(entry.name)`（`app/net/send.py`），GUI 那条路被 `os.path.commonpath` 挡着（「这些文件不在同一个
      文件夹下」），所以这洞只有命令行走得进去。后果是数据损坏：两条共享同一个 `land`，分块写进同一批偏移，
      两个整文件摘要永远不可能同时过。
    - **手机端那一半**在共用状态机 `cs-receive.uts::uniqueName(name, used)`：一份清单一个 `used` 列表，第一个
      条目留原名，之后的在**最后一段**的扩展名之前插 ` (2)`/` (3)`（`dot > 0` 才算扩展名，`.bashrc` 这种点开头
      的不加后缀）。后缀打在 `land` 上、`relpath` 保持对端声明的原名——和 PC 同形，写块/摘要/回收/卡片/`state`
      回的 `path` 读的都是 `land`（§7 那条老规矩）。旧台账没有 `land` 的兜底（`landingOr`）没动。
    - **证据档位**：`浏览器`（H5 接收内核自检 71 → 76 项，原文 `.probe/c163_web_selftest.txt`；改前那一趟把
      `uniqueName` 桩成原样返回，红三条——`都过了整文件摘要`、`落在两个不同的名字上`、` (2)` 后缀；而
      `两条都收下了自己那一块` **改前也是绿的**，因为两条 PUT 打在同一个路径上照样各自 200，这一条证不到东西）；
      `编译门` 两道（`.probe/c163_android.log`、`.probe/c163_harmony.log`）；镜像守卫 `check_protocol.py` OK。
      **设备腿下一轮（#164）补上了，两台模拟器各一趟、两个方向都 PASS**：安卓原文 `.probe/a_163.txt`
      （`58cf0d1f23f9538b/twin.bin` 与 `…/twin (2).bin`，机上 `sha256sum` 各对各的源，卡片「已验证 2 个」→
      「已验证 4 个」，再杀进程重启两个落点与两份摘要都不改口、留空配对码 `resumed=true`，三条腿 YES）；
      鸿蒙原文 `.probe/h_163.txt`（同一条 CLI 命令发出的两个同名文件落成 `284b052ee76c7ec2/twin.bin` 与
      `twin (2).bin`，`hdc file recv` 回本机算 sha256 各对各的源，文件页两行都是 `twin.bin`、卡片
      「已验证 4 个」→「已验证 6 个」，四条 YES）。鸿蒙那一边多证到的平台段：**一个带空格和括号的名字在
      `@ohos.file.fs` 上写得下去、读得回来**——这一端此前的每一次落盘都没有过这种形状。
    - **顺带核到的两处**：限额/超时那一整组数字（4 MiB 分块、255 字节名、深度 16、2000 文件、900/3600/120 s、
      静态码 8 位、60 s 等待、节奏阶梯 `[0,15,40]`、单文件最多重写 3 次）三端**全都对**；`offer_wait_timeout_s`
      以前不在镜像守卫里，现在加了 `OFFER_WAIT_S`。剩下两个数反过来——合同写了 `X-File-Size` 与
      `transport.max_parallel_chunks: 2`，**三端都不发也不读**，是要用户点头的口径题（feature-matrix §6 结尾）。
      （`X-File-Size` 那一半已经在 #183 收掉：纸上不再把它列成分块请求头，并写明谁都不发、谁都不读，守卫四处负向
      不许它回到任何一端；桌上只剩 `max_parallel_chunks` 那一格。）
    - **harness 自己的一条坑**（已进 feature-matrix §7）：`web/index.uts` 的 `askOn()` 是八个参数，第一版把
      `token` 写在 `jsonBody` 的位置上（少一个 `''`），五条腿红四条；vite 对 UTS 参数个数只打
      `warning: Expected 8 arguments, but got 7`，**不拦编译**。自检头一趟是红的，先怀疑腿。

17. **#165：合同 §4「续传状态」那三句，纸面写的与手机上做的不是一件事**（这一轮改的是合同，两端的代码一行没
    动；完整账目在 `../docs/feature-matrix.md` §6 第 21 条）
    - **`root` 那个键谁都没发**：offer 应答的例子以前写着 `{"accepted": true, "root": "相册/"}`。三端的应答里都
      没有这个键（手机是 `cs-receive.uts::payloadOf`，PC 是 `app/net/receive.py:145` 的 `payload()`），发送端也
      谁都不读；每个文件最终写在哪儿，唯一走线的地方是 `finalize` 回复里那一项 `path`——屏幕上「落到 …」读的
      就是它。合同现在只写实际发得出去的字段。
    - **「按已落盘字节 / chunk_size 重算缺块」这条三端都量不出来**：用户在卡片上点「接受」的那一刻，两端就按
      清单里声明的长度把文件开好（鸿蒙 `app-harmony/index.uts:1049` 的 `truncateSync(fd, size)`、安卓
      `utssdk/app-android/CsStore.kt:52` 的 `setLength`——这是 #128 那手预分配，为的是 `STORAGE_FULL` 能在把
      4 GiB 写花之前回话），所以「一块没落」和「刚落一块」在盘上量出来都是整个文件的长度。**先开档留着，改的
      是那句话**：合同现在写的是「状态文件损坏或缺失时，接收方什么都不认领——发送方那份清单再投一次，就是按
      全缺登记的一单」。丢的只是那几块本来要重传的字节，分块偏移、幂等与整文件摘要都不受影响。
    - **台账不是 PC 那个文件名**：合同以前把「offer 目录下的 `.chuanshu.state.json`」当成了共同位置，那是 PC 的
      形状（一单一份）。两个手机端是**一份合并的** `chuanshu-receiver-offers.json`，未完成的单一条一行（安卓
      `CsIdentity.kt:46` 那个文件名 + `app-android/index.uts:444` 把 `stateAll()` 写回去、开机用
      `loadOfferStates()` → `adoptAll` 读回来；鸿蒙 `app-harmony/index.uts:46` 同一个文件名）。**这一条是设备腿
      自己撞出来的**：第一版腿照合同去删 offer 目录里那个文件，删完冷启动，手机照样认得那一单、`state` 照旧回
      缺第 1 块（`.probe/a_165.txt` 头一趟）——合同里不留只有一端成立的路径。
    - **证据三档**：`浏览器`（H5 `我的` 页 `接收内核自检` 76 → **87 项全部通过**，原文 `.probe/w_165.txt`；新增
      的 7c 组十一条腿打在一只新建的隔离收件箱上，逐条走的就是改过的那一句。**头一趟是「失败 1 项，通过 86 项」**，
      红的正是 `OFFER_UNKNOWN` 那一条——腿把那一问放在了重新配对**之前**，量到的是 §3 的 `NOT_PAIRED`
      （`restartLike` 把令牌清了），改的是腿的顺序，不是端的答复）；`模拟器`（安卓 emulator-5554 一趟四腿 PASS，
      原文 `.probe/a_165.txt`：只推第 0 块以后机上落点已经量成整个 5 242 880 字节而摘要是 `254f9ece0e81…` ≠ 源
      `875497330823…`，同一单里一块没落的小文件也量成自己的 3 072；杀掉进程并删掉台账里那一行以后冷启动，留空
      配对码仍然 `resumed=true`（身份记的是另一本账）、`reopen` 回 `OFFER_UNKNOWN`、同一份清单再投先在屏上重新问
      一次、`state` 改口大文件缺 `[0, 1]`，整单 3 s 送完两份落点摘要各对各的源，卡片「已验证 4 个」→「6 个」，
      verdict 六条 YES）；`门禁`（PC 新增 `phase_state_lost` 六条腿，`.probe/c165_selftest.txt` 122 条 PASS）。
      **鸿蒙那一趟也跑过了**（#166，原文 `.probe/h_165.txt`：127.0.0.1:5555 一台收、PC 命令行发，四腿 PASS、
      verdict 六条 YES）——只推第 0 块以后 `ls -l` 量到的落点已经是整个 5 242 880，而 `hdc file recv` 回本机算的
      摘要仍是 `254f9ece0e81…`，同一单里一块没推的小文件也量成自己的 3 072；删的是那份合并台账里属于这一单的
      那一行（删之前先把这一行数出来，否则测的是一份本来就没有它的文件），冷启动留空配对码仍 `resumed=true`、
      `reopen` 回 `OFFER_UNKNOWN`、同一份清单再投在屏上重新问一次、`state` 改口大文件缺 `[0, 1]` 小文件缺 `[0]`，
      整单 56 s 送完两份落点摘要各对各的源，卡片「已验证 0 个」→「2 个」。这一支至此在两台手机上各读到一次。
      **只有一格鸿蒙到不了**：这台 DevEco 模拟器的 shell 在应用沙箱里删得掉文件、建不出文件（`uid=2000(shell)`，
      `touch` 与 `hdc file send` 都是 Permission denied），所以「台账坏成半个 JSON」那一支仍然只有 `门禁` 与
      `浏览器` 两档——它不是没测，是在这条路上造不出那个状态。

18. **#167：§4 的零字节转义被三个端读成了三件事，§5 最后那道闸门安卓圈的是根目录**（这一轮合同一字未改——
    纸面那几句本来就是对的；完整账目在 `../docs/feature-matrix.md` §6 第 22 条）
    - **接收方判的是头的「值」，不是「头有没有来」**：`utssdk/app-android/CsServe.kt` 改前写
      `escape.isNotEmpty() && method == "PUT"`，`utssdk/app-harmony/index.uts` 改前写 `escape != '' && method == 'PUT'`。
      后果是 §4 明确不许的那一手：一个这一端不认识的编码（将来另一种、或者拼错的那一个）会被当成 `stu` 反解，
      字节在长度与摘要说话之前就被丢掉。两个 host 都 import 不了 `cs-protocol.uts`（和 `recvPath` 复述路径规则
      同一个理由），所以各自复述一个 `CHUNK_ESCAPE_STU` 再比值，而**复述由守卫盯**：
      `scripts/check_protocol.py` 新增 `check_chunk_escape()`，核 PC / 共用 / 两个 host 四处的同一个值、核两个
      host 都真拿值比过一次，并明令禁止 `escape.isNotEmpty()` 与 `escape != ''` 这两种写法本身——这个值写在合同的
      散文里、不在 `protocol.json` 里，没有这一格，谁都不会发现某一端哪天改了口径。
    - **「体里没有零就不转义」这句只有 PC 在做**：共用的 `escapeChunk` 过去把 0x1B 也计成"要转义"，于是一个零字节
      都没有、只有 0x1B 的分块从手机出来时是双倍长度还带着那个头，桌面却把同一块原样送出去。两支都能被解开了，
      所以这一支不会自己报警。现在 `zeros` 单独计，`zeros == 0` 直接交回原 buffer（不复制、不带头）。
    - **台账里那个 `land` 的边界**（§5 最后一条）也顺手量了一次：安卓宿主 `CsStore.kt::cleanPath` 把「resolve() 以后
      不在该 offer 目录内 → 拒绝」读成了"不在接收根目录内"，于是一条从 `<root>/<a>` 解析到 `<root>/<b>` 的链接被
      放行，写的字节属于**另一单**、而那一单的每一块都已经过了整文件摘要。改成按 `relpath` 的第一个成分圈（PC 比的
      就是 `state.directory`）；没有 offer 成分的那种落点是 #128 之前台账里还可能带的形状，对它，根目录是唯一可圈的边界。
    - **证据**：`门禁`（`../scripts/protocol_selftest.py` 新增 `phase_chunk_escape` 六条腿，全文件 **128 条 PASS、
      `RESULT ALL PASS`**，`.probe/p167.log`；心跳那条腿做了负向验证——`.probe/neg167.py` 临时把 `state.persist()`
      改成一句不落盘的空表达式，同一趟读出 `(1793215553.2003748, 1793215553.2003748)`（原文
      `.probe/neg167_fail.txt`），两个数一样就是盘上那个值一动没动；还原后重跑仍 128 条全过
      （`.probe/p167_final.log`））+ `浏览器`（H5 `接收内核自检` 87 → **96 项全部通过**，`.probe/c167_web.txt`，新增的 7d 组九条腿走的
      是三个 host 那一条管线：`unescapeChunk(body, head)` 在内核看到字节之前反解，判据是头的值）+ `编译门`
      （`项目 chuanshu 编译成功。` 两道，`.probe/c167_android.log`、`.probe/c167_harmony.log`）。
    - **设备腿补上了，两格都在活手机上读到，而且各留了一份对照**（原文 `.probe/a_167.txt`、`.probe/h_167.txt`，
      对照 `.probe/a_167_before.txt`、`.probe/h_167_before.txt`；脚本 `.probe/a_167.py`、`.probe/h_167.py`）。
      这一格原先按欠着记，欠的就是两样东西：一个**发陌生头值**的对端，和一条**从 `<a>` 解析到 `<b>`** 的软链接落进
      活手机。第一样是一个文件三块——块 0 配合同那个值 → `200`，块 1 那份**转义后的**体配 `stu2` → 两台都回
      `422 CHUNK_DIGEST_MISMATCH {'reason': 'length', 'got': 4227776, 'want': 4194304}`（字节按线上传的那样多，一个都没
      被解），同一块改对声明以后 `200`，尾巴那块没有零因此没有转头 → `200`，整单落完 `sha256sum` 等于源。第二样在安卓上
      是：第 2 单先把 `victim.bin` 送完并验过，第 3 单开出自己的 `link.bin` 后用 `run-as … sh -c 'rm -f && ln -s'` 把它
      换成一条指向**别人那一单目录**的软链接，再往第 3 单的块 0 写 → `507 STORAGE_FULL {'reason': '这个路径不在接收目录里'}`，
      受害者写前写后同一个摘要、一个字没动。**对照那两趟各自读到了改前的形状**：安卓装的是上一版同步过去的程序文件，
      `stu2` 回 `200 stored`、软链接那一写也回 `200`，受害者从 `8a07a97472a1…` 被写成 `7f12fcf5549e…`；鸿蒙装的是上一版
      hap，`stu2` 同样回 `200 stored`——而这两趟的「整文件摘要对上源」都仍是 True，**正腿在改前一样绿**，这就是这两格
      非要有对照不可的原因，也是 §4 第四条（`--compile true` 只编译不推设备、编译门过了不等于机上也是这样）在两端都
      留了一次现场。软链接那一格鸿蒙造不出来：`fs.symlink` 自 API 11 起只对系统应用开放，这台 DevEco 模拟器的 shell 是
      uid 2000、连那个沙箱都进不去，所以它只有安卓的 `模拟器` + `门禁` + `浏览器` 三档。
19. **#168：合同 §6「保活与后台」那一整段——四句话都有实现体，缺的是合同自己钉的那一次实测**（这一轮合同与产品代码
    都一字未改；完整账目在 `../docs/feature-matrix.md` §6 第 23 条）
    - **四句都对着一遍实现体找过**：PC「常驻托盘即可，监听随进程存活」落在 `../app/ui/main_window.py:402-459`
      （`tray_available()` 为假时不藏、把记住的"最小化到托盘"降级成一次询问——没有托盘的 Linux 桌面是同一个分支）；
      Android「接收中需前台服务 + 13+ 通知权限」落在 #143 那四处（`CsKeepAlive.kt` / 它的 `<service>` / `config.json`
      三项权限 / `app-android/index.uts::receiveHoldStart`）；鸿蒙那句文案落在 `store/session.uts::armHold`，
      `pages/files/files.uvue:53` 与 `pages/me/me.uvue:67` 两处渲染，重启由 `initReceivePanel()` 重新挂上。
    - **补的是量，不是代码**：合同给鸿蒙写的是「按真机实测结论写进 UI 文案」，而"退到后台 / 锁屏以后那条监听还答不
      答话"从来没人问过。三趟都在活设备上（`模拟器`，原文 `.probe/h_168.txt`、`.probe/h_168_lock.txt`、
      `.probe/a_168.txt`，都 `PASS`）：三相同形，A 相前台走完一单当控制格，B 相**由设备说它在后台**（鸿蒙
      `aa dump -a` 的 `app state #BACKGROUND`；安卓 `dumpsys window` 的 `mCurrentFocus` + `topResumedActivity`
      换成 launcher）以后才问，C 相回前台核同一个 pid、那份字节、那一行文案。四格（hello / PUT / state / finalize）
      在两台后台状态里全部当场答话，两份落点逐字节对上源。
    - **这三趟能读的只有一件事**：这一端自己不会因为退到后台就把监听收掉。它们**不能**读成"那句「可能被系统掐断」被
      推翻"——模拟器不进 doze，也没有真机那套省电冻结。所以合同那句「按**真机**实测结论」照旧欠着（真机是用户的
      私人机，锁着，未经同意不动），文案里那个「可能」一个字不改；安卓那一趟跑的是**挂不上保活**的标准调试基座，
      它量的是没有保活时这一端会不会停，保活本身那一支仍要 `pack --iscustom`（等点头）。
    - **顺手立的 harness 规则**（细节 §6 第 23 条末）：发送方本来就每条请求各开一条 TLS 连接，所以"不再接受**新**
      连接"这一句不用造手——每一格读数本身就是一次新连接；块体做成不带零的 3 072 字节，"没答话"于是只能是天气之外
      的事实；`dataclasses.replace(conn.proto, offer_wait_timeout_s=N)` 才量得出一个不答话也不发 RST 的对端；鸿蒙
      的回复不能用 `Connection: close` 读；灭屏要 `hidumper -s PowerManagerService -a -a` 那两枚表记动过才算，
      `power-shell suspend` 打印那句「SuspendDevice is called」不算。
20. **#171：合同 §2「发现」与 §3「配对」逐句过了一遍——两边都有体，缺的那一格在 PC 自己的 mDNS 公告上**（合同一字未改，
    产品代码只动 `../app/net/discovery.py`；完整账目在 `../docs/feature-matrix.md` §6 第 24 条）
    - **手机端这一轮没有要补的腿**：§3「端口/地址变了画面要重画」那句里"公告"那一半，两端本来就不归自己管——安卓宿主
      `CsDiscovery.kt` 造的 `NsdServiceInfo` 只设 `serviceName`/`serviceType`/`port`，本机地址由 `NsdManager` 填；鸿蒙宿主
      `app-harmony/index.uts::discLocalInfo()` 传的是 `host: {family: 1, port: …, address: '0.0.0.0'}`，同样由系统填。
      只有 PC 在注册那一次把 `local_ipv4()` 抄进 `socket.inet_aton(host)` 之后再没动过，所以换网、重连、DHCP 续租以后，
      三条通道里 UDP 每 3 秒现算的那条是对的、mDNS 那条还在答旧地址——而名单合并的规则是「地址取最新」（`_learn` 与
      共用 `cs-discovery.uts::learn` 同一条），于是**那条死地址会盖掉对的那个**，这台 PC 在对面名单里被钉在拨不通的地方。
    - **修的是 PC**：`_mdns_host` 记"公告上现在写的是哪个地址"，3 秒的 announce tick 比一次，变了就**先注销（发 ttl=0
      goodbye）、再改 `info.addresses`、然后重新注册**。这里有一条容易踩的：`Zeroconf.update_service(info)` 只做
      "换进注册表 + 重播"，**不发撤播**，对面 DNS 缓存里新旧两个 A 会并列被解析出来——第一版那么写，新加的腿当场读到
      `['198.51.100.7', '192.168.2.233']` 两个数。改成撤—改—登以后 `answered=['198.51.100.7']`，挪回本机真地址也跟着回来。
    - **档位要说清**：这条只有 `门禁`（`protocol_selftest.py` 新增两条腿，全文件 130 项 `RESULT ALL PASS`，另三道 PC
      门禁与镜像守卫同轮重跑全绿）。**真局域网里跨设备的多播没有量过**——手机名单里那台 PC 换网以后地址跟不跟，仍属
      第 1 条那一台私人机的门；这一轮证的是"我们这侧发出去了、对面那份 resolver 只答新地址"，跑在 127.0.0.1 的进程内 mDNS。
21. **#172：合同 §4「待决应答」那句——轮询 loop 只有两种结束，共用发送方把"没读到应答"当成了第三种**（合同一字未改，
    产品代码动 `uni_modules/cs-transport/utssdk/cs-client.uts` 与 `…/web/index.uts`；完整账目在 `../docs/feature-matrix.md` §6 第 25 条）
    - **PC 从 #96 起就有这一支**：`app/net/send.py:418-439` 里清单那一问读不到 socket 答案时按同一个 `offer_id` 再问一遍，
      等满 `offer_wait_timeout_s` 才判死；判死前先 `_withdraw`（`:442`）把 `DELETE /v1/offer/{id}` 发出去。手机这一侧没有：
      共用 `cs-client.uts::offerAll::ask` 只分「200」和「不是 200」两路，而 `status == 0`（两端宿主给"连接上没读到应答"
      的那个形状，#132 教过 `putChunk` 认它）会落到「不是 200」那一支，于是**一份没人答过、也没人拒绝过的清单在屏幕上被
      报成「被拒绝」**——用户按了同意也来不及，这一单已经死了。
    - **修法在共用状态机里，一处加一条分支、一处补一句撤回**：`status == 0` 且 `codeOf(body) != 'CANCELLED'` 时不判死，
      一秒后按同一个 `offer_id` 原样再问（`setTimeout`，`waited` 记秒数）；`CANCELLED` 是我们自己那一下「取消」
      （`CsWire.kt:332`），是本机的事实、不是对方的答案，仍旧当拒绝。等满预算才走新的 `giveUp()`：**先 `DELETE` 再报**，
      因为登记好的那一份清单会在对面占着位置——没人决定的占住对面那条 pending 记录，有人答过的还占住它预先开好的
      稀疏文件与台账，都要等对面自己的闲置闸门（`offer_idle_timeout_s`，§4「闲置 offer 回收」`spec.md:238-243`）才放开；
      PC 走开时做的就是同一句（`app/net/send.py:442-449` 的 `_withdraw`）。先放开它再说"这单我判死了"；对面若已经自己
      收回去，那句 `DELETE` 只会答 `OFFER_UNKNOWN`，这时屏上补一行「对方没有收下这句撤回」。
    - **档位要说清**：新增的是 H5 发送自检的第七条腿 G（`ChunkSwallow.muteOffer = 1` 吞掉清单那一问的回复），`发送内核自检`
      从 28 项涨到 **29 项全部通过**；改前同一腿红在判别那一条（`发送自检失败 1 项，通过 28 项`）。两道手机编译门同轮重跑
      rc=0、镜像守卫与 130 项 PC 门禁也重跑绿。**「再问一次、第二次拿到答案把这单走完」那一半已经在活手机上量到**（#173，
      `.probe/a_172.py`，emulator-5556，run-mode 部署）：对端把清单第一问的回复吞掉并掐断连接，一秒后收到**同一个
      `offer_id`** 的再一次出示，账本 `清单出示 2 次（吞掉 1 次）/ 写块 2 次 / 真正收下 2 块 / finalize 1 次`，落盘
      `5242880` 字节、摘要 `6f25483fb457…` 与源逐字节一致；屏上传输页同时有「这一问没读到对方的应答，一秒后再问：对端没答话」
      和「完成：对方已收下 1 个文件 / 5.00 MB」，且没有「被拒绝」。八条判据全 YES，`verdict: PASS`
      （原文 `.probe/a_172_run2.log`，屏幕读数 `.probe/a_172_logbox.txt`；第一趟 `.probe/a_172_run.log` 只红在探针自己把
      外页滑反了方向、那一行没被收集到，与传输无关）。**这一支在鸿蒙模拟器上还欠同样一次注入**——理由与安卓改口前不同：
      那边是取证工具等不到 `setTimeout`，这边是这一端宿主给不给 `status == 0` 这个形状没人量过（它自己的读通道另有
      `0x00` 截断与记录乱序两段）。
22. **#174：合同 §5「路径清洗」那三道数字闸门——三端都在拦，纸上只写了一道；另外两句的范围比实现窄**（动的是合同与
    取证，**手机侧只动了 `…/web/index.uts` 那一组自检腿**，`cs-protocol.uts` / `cs-receive.uts` / `cs-client.uts` 与两个
    宿主一行未改，所以这一轮**没有跑两道手机编译门——没有东西需要过**；完整账目在 `../docs/feature-matrix.md` §6 第 26 条）
    - **纸面落后于线上**：`protocol.json:141-144` 那三个数里，改前只有 `max_name_bytes` 在 §5 有一句；`max_path_depth` 16
      与 `max_files_per_offer` 2000 三端都读了（PC `receive.py:80/679`、手机 `cs-protocol.uts:137` 与
      `cs-receive.uts:924`），纸上没有，而且**一条行为腿都没有**。另外两句的范围比实现窄：合同写「以 `.` 开头的**保留**段
      （`.git`、`.chuanshu`）」，两端代码写的都是 `startsWith(".")`——`.env` 也拒；合同写「**Windows 额外**拒绝保留名」，
      两端代码都不看自己跑在什么系统上。修法按 #165 那口径：**数字一个不改，纸面追上代码**（改数字会撞 §7 兼容决定，
      改描述不会）。
    - **三道闸门现在各有一对"卡在边界上"的腿**：16 段收 / 17 段拒、255 字节收 / 256 拒、2000 个收 / 2001 拒。每一道都量
      两个方向，因为 `>` 写成 `>=` 红前一条、写成 `<` 红后一条。超规模那一道还多判一件事：**拒的时候一个用户都没被问过**
      （那单没登记成 pending），否则对面会挂一条永远没人答的清单。档位：PC `门禁` 141 条 PASS、`RESULT ALL PASS`
      （`.probe/r9_pc_selftest.log`），H5 `接收内核自检` 96 → **105 项全部通过**（`.probe/r9_web_after.txt`，新那九条打在
      三个 host 共用的 `handle` + `pathReject` 上）。镜像守卫新加一条 `check_limits_in_prose()`：§5 不写出这三个名字就红，
      负向照 #167 的做法量过一次（抹掉上游那一句 → 重新 vendor → 守卫红 → 还原）。
    - **只记下、没有改**：超规模那份清单回的错误码是 `UNSUPPORTED_PROTOCOL`（v1 码表没有"太大"这一格），到了发送方屏幕上
      是「对端版本不兼容」（`cs-protocol.uts:390`）——说错的是清单，不是版本。手机的发送方在本地就按同一个数拦下
      （`cs-client.uts:131`），PC 的发送方没有这道预检，所以 PC 一次挂 2001 个文件会真把这问发到线上。换码是 §7 的兼容
      决定、补预检是产品口径，两条都留给用户点头（`../docs/feature-matrix.md` §6「需要用户点头」第四半）。
    - **还欠的那格**：这三道闸门在活机上没量过。判据不必重复装一遍——读这三个数的地方只有 `pathReject` 与 `handle` 两处，
      都在共用文件里，两个宿主没有自己的一份；所以默认不补设备腿。如果下一步给 PC 补那半本地预检，那时再一起上机。
23. **#176：合同 §7「版本与兼容」与 §8「云中转」逐句过了一遍——`hello` 里那个 `features` 三端各自手抄，错误码表的号在手机上从来没有腿读过**（动的是合同与
    取证；**手机侧 `cs-protocol.uts` / `cs-receive.uts` 各只改一行**（一份 `HELLO_FEATURES` 常量 + hello 用它），`web/index.uts` 加了
    一组自检腿，`cs-client.uts` 与两个宿主一行未改——所以两道编译门**本轮都跑了**（有东西要过）：`app-android` 与 `app-harmony` 都
    `rc=0`（`.probe/r10_compile.txt`）；完整账目在 `../docs/feature-matrix.md` §6 第 27 条）
    - **`hello` 的 `features` 现在只有一份**：合同里多了 `transport.hello_features: ["resume","chunk-hash","directory"]`
      （`protocol.json:38`）与 §7 那一段（「别把它读成第二套兼容规则……**v1 没有任何一端拿它做决定**」）。手机这边
      `cs-protocol.uts:11` 一份 `HELLO_FEATURES`，`cs-receive.uts:1218` 与浏览器替身 `web/index.uts:817` 都从它发，PC
      从 `spec.py` 读合同再发（`receive.py:651`）。**三个词一个没改，所以 §7 的兼容决定没被触发**——这一格缺的不是行为，是名分：
      改前全仓库唯一读过它的地方是 `"resume" in hello["features"]`，抹掉 `directory` 它也不红。
    - **码表的号现在有腿了**（`web/index.uts:1581-1655` 的 5e 组六条）：`NOT_PAIRED` 403、`OFFER_UNKNOWN` 404、`PEER_BUSY` 429、
      `BAD_PAIR_CODE` 403 各一条按号判，外加两条 hello 腿（名单逐词相等 + 版本集合仍是那一个数）。`cs-receive.uts:279-296` 的
      `statusOf` 是合同表的**第三份抄本**（号）而 `cs-protocol.uts:393-440` 的 `errorText` 是第四份（话术），改前所有腿只比码名——
      把 403 改成 400 一条都不红，可宿主是把 `reply.status` 原样写上线的（安卓 `index.uts:549` 的 `replyJson`），对面 PC 按号读它。
      档位：H5 `接收内核自检` 105 → **111 项全部通过**（`.probe/r10_web_after.txt`）；**负向**改 `statusOf` 那一格 →
      `接收自检失败 3 项，通过 108 项`（`.probe/r10_web_negative_status400.txt`）。镜像守卫加了三道 `check_error_table()` /
      `check_hello_features()` / `check_endpoint_count()`，六次负向全红（`.probe/r10_guard_negatives.txt`）；PC 侧
      `门禁` 141 → **143 条 PASS、`RESULT ALL PASS`**（`.probe/r10_pc_selftest.log`，含十一格全表的号）。
    - **取证工具自己的一个哑点顺手修了**：`receiveSelfReport()` 里的 `check` 只有两个形参（:1354），而这批腿从 #163/#174 起
      就一直传第三个 `extra` 当读数——第三段被静吞，屏上看不到「实际回的是 400」。补上默认形参并拼在失败行尾巴以后，上面那次
      负向才在屏上自己说出为什么红。凡是读屏判成败的探针，"报了名却没报数"都值得回头查一遍。
    - **只记下、没有改**：§9 那条冻结标准写「错误码表两端各能渲染出**中英文**文案」，手机这边只有中文（`errorText` 一份，
      手机上也没有语言切换）。要么给手机补一份英文码表，要么把 §9 那句改成「按本机语言」——后者是收窄冻结标准，不该由巡检自己
      签字，记在 `../docs/feature-matrix.md` §6「需要用户点头」第五半。§8 那三句（session id、多一层账号、"共用同一份 fixture
      做回归"）是分支本身没做，不是手机端没照合同做；唯一能核的是那句里的端点数，现在由 `check_endpoint_count()` 核着。
    - **还欠的那格**：5e 那六条只到 `浏览器` 档。`statusOf` / `errorText` 都在共用文件里，两个宿主读的是同一份，没有第二份
      实现可以骗过这些腿，所以默认不补设备腿；两个宿主唯一自己写的东西是状态行里那个短语（`app-android/CsServe.kt:163-172`、
      `app-harmony/index.uts:2262-2285` 两份 `reasonOf`），合同没规定它、对面也不读它，本轮判它属于外观。若哪天要给 #175
      那半（PC 发送方的本地预检）上机，届时一起把设备腿补上。
24. **#177：合同 §1「身份」那三行逐句过了一遍——「存放」「生成」「摘要来源」写的是其中一端的实现，表里点名的那个文件三端都不存在**（动的是合同与
    取证；**手机侧一行未改**（`cs-receive.uts` / `cs-protocol.uts` / `cs-client.uts` / 两个宿主都不动），只有浏览器替身
    `web/index.uts` 给自己起的 `peer_id` 换了形状——所以两道编译门**本轮仍都跑了**（合同重搬后要确认还是编得过）：
    `app-android` 与 `app-harmony` 都 `rc=0`（`.probe/r11_compile.txt`）；完整账目在 `../docs/feature-matrix.md` §6 第 28 条）
    - **手机上没有 `identity.json`，也从来没有过**。§1 那一栏原来写的是 PC 的存法（PC 落 `peer-key.pem` + `peer-cert.pem`，
      装载时从证书的 CN 把 `peer_id` 读回来），而手机存的是私钥种子 + 44 字节 SPKI + 一份自己的 id 文件。现在那一栏说的是
      「本机身份目录里自己的文件，文件名不属协议」——与同表 leaf 行早就写过的口径一致；第四位读者（下一个平台）照句子去找文件
      不会再扑空。守卫 `check_identity_files()` 把 §1 里点名的每个 `*.json|pem|txt` 拿去两端源码里找有没有真被打开。
    - **「Ed25519，自签 X.509（CN=`peer_id`，10 年）」也只说了 PC**：手机上纸面就没有那张身份证书，线上也没有——pair 请求
      带出去的是 32 字节裸公钥，对面自己拼 SPKI 再取摘要（#106 逐字节核过，三端同一个数）。那句从表里挪进表下面新的一段，
      「10 年」这个谁都没有比较过的数删了；`fingerprint` 那一行的「证书」二字也去掉了，摘要算的是**密钥的** SPKI，
      那 12 个字节的前缀是三端各自手抄的（安卓 `CsIdentity.kt:367`、鸿蒙 `index.uts:58`、替身 `web/index.uts:284`），
      现在由 `check_spki_head()` 逐字节比着——PC 侧那五条新腿就是我抄错一个字节时被它们抓出来的。
    - **替身那个 `peer_id` 是唯一一处真改的代码**：原来是 `'android-web-' + 8 字节 hex`，既不是「随机 16 字节」也不是 32 个
      hex 字符，而鸿蒙装载时会按 32 个 hex 拒绝它；线上没有任何一端把 `peer_id` 当标签读，所以它一直"能用"。
      现在与另外三端同形（`web/index.uts:211`），四处生成点由 `check_peer_id_shape()` 一起核（9 → 13 行 OK，六次负向全红
      `.probe/r11_guard_negatives.txt`）；`protocol.json` 里那句「4-digit code」也改成 6，与它上面两行的
      `pair_code_digits: 6` 对齐（`check_pair_code_digits()` 盯着合同两份文件里每一个「N 位码」）。
    - **档位**：`门禁` PC 侧 143 → **148 条 PASS、`RESULT ALL PASS`**（`.probe/r11_pc_selftest.log`，§1 那五条在 :83-87）；
      `浏览器` 档是 111 条腿的整体回归门，**接收自检 111 项全部通过**（`.probe/r11_web_after.txt`）。这轮取屏上读数的路子换了：
      in-app 浏览器页签在 `visibilityState=hidden` 时 `evaluate_script` 必然超时（页签不渲染，DOM 读不到），所以临时在
      `runRecvSelf` 里加一行 `console.log` 把整份读数打到控制台再取回，取完即还原——`store/session.uts` 现在与 HEAD 一个字节不差。
    - **还欠的那格**：§1 这几条**没有设备腿**，这是本轮的决策不是遗漏——四处 `peer_id` 生成点里只有浏览器替身会写歪，而它本身就是
      那份源码，升到设备档没有第二份实现可骗过；两个宿主本轮一行未改，共用状态机也没动，设备腿在这轮只能重复源码守卫已经钉住的东西。
      「私钥文件权限按平台收紧」那句是三端各自成立、长三种样子（PC `chmod(0o600)`，手机落在应用私有目录），记下没改也不上腿。
25. **#178：合同 §9「冻结标准」那五句逐句过了一遍——三句指着仓库里不存在的东西，而它承诺的那条链这一端缺一格**（动的是合同、
    取证与浏览器替身；**手机侧共用文件一行未改**（`cs-receive.uts` 只为负向验证临时改过一次，已按字节还原，`git status`
    里没有它），新增的腿全在 `web/index.uts` 的自检里——所以两道编译门**本轮没跑**：动的只有 web 档编译的那个文件与合同散文，
    两个宿主的源码一个字节没变，编了也是编同一份；完整账目在 `../docs/feature-matrix.md` §6 第 29 条）
    - **「多文件含目录」这一格，这一端从来没有腿**。§9 把冻结条件写成一条链：配对 → 多文件含目录 → 中途断开 → 续传 → finalize。
      PC 那一份每一环都有腿（含 `nested chinese path preserved`：落点真的带着 `相册/2026/` 两级），这一端只量过「清单能不能收到
      这么深」（5d 那道 16/17 段的闸门），却没真的成一单带目录的文件、也没读过回执里的落点。新增的 5f 五条腿
      （`web/index.uts:1659-1721`）把这条链在这一端走一遍：配对 → 一份两条的清单（`传书/备忘/甲.txt` 与 `乙.txt`）→ 逐块 PUT →
      finalize → 读数。档位 `浏览器`：**接收自检 111 → 116 项全部通过**（`.probe/r12_web_after.txt`）。
    - **这条腿判的是落点，不是清单念了什么**——负向跑过：临时把共用内核 `landingOf()` 改成只取 basename，那一趟
      `接收自检失败 1 项，通过 115 项`，红的正是「嵌两层的那条落点带着两个目录段，没被摊平成文件名」，屏上把读数一起带出来
      （`/模拟接收目录/<offer_id>/甲.txt`）。改的是共用的那一份，安卓与鸿蒙一起受益，也一起被这条腿看着。
    - **合同那三句纸面追线上**：①「见 `.probe/protocol_report.txt`」——`.gitignore:12` 把 `.probe/` 整个排除，那份读数读者
      从来打不开，现在句子说清它是跑出来的本地产物、不入库；②「`py scripts/protocol_selftest.py`」——`py` 是 Windows 的
      启动器，而 PC 已经有 Linux 这一端。本轮先量再改：WSL Ubuntu-24.04 / Python 3.12.3 上 `python3 scripts/protocol_selftest.py`
      **rc=0、145 条 PASS、`RESULT ALL PASS`**（`.probe/r12_linux_selftest.log`），比 Windows 少的正是 mDNS 那三条——通道给不出来时
      脚本自己跳过、不拿跳过冒充通过；Windows 同轮重跑 **148 条 PASS**（`.probe/r12_pc_selftest.log`）。合同补上 Linux 写法，
      脚本自己的 `Run:` 行也两行各写一种（`scripts/protocol_selftest.py:7-8`）；③「同一组 fixture」——仓库里没有这么一件工件，
      真正共享的是 `mobile/shared/protocol/` 那份逐字节 `protocol.json`（戳由守卫核）和 §9 那条五步序列本身，句子现在这么说。
    - **守卫 `check_freeze_gate()`（`mobile/scripts/check_protocol.py:391-425`）与它的六次负向**（`.probe/r12_guard_negatives.txt`，
      驱动 `.probe/r12_negatives.py`）：§9 点名的脚本得在树里、点名的 `.probe/<file>` 得真有脚本写它、§9 说到的启动器脚本自己也
      得提供、PC 那格必须锚在 `check("nested…" … is_file())` 这个形状上、这一端那五条腿得还挂着 `§9` 的名分。前两次跑出来是绿的，
      两个原因记下来：反引号正则匹配不到 `` `py scripts/…` ``（一整对反引号里两个 token），整个循环空转；「文件里有没有 nested
      这个词」不是判据，注释里也有它。改完六次才全红。守卫 OK 行 13 → **14 行**。
    - **只记下、没有改**：§9 那句「错误码表两端各能渲染出**中英文**文案」还是 #176 第五半那道口径题——手机上只有一份中文
      `errorText`，也没有语言切换；本轮不动句子，也不假装它绿。句里那个「51 条断言」是带日期的历史读数，同一份代码现在 148 条。
    - **还欠的那格**：5f 那五条只到 `浏览器` 档，理由与 #176/#177 同形——`landingOf` 与整条接收状态机都在共用文件里，两个宿主读
      的就是同一份，**没有第二份实现可以骗过这些腿**，所以本轮不上设备腿、也不跑编译门。另外 §9 那句「手机端必须重跑一遍，
      **只认它自己那端的绿色结果**」还欠一个口径（记在 `../docs/feature-matrix.md` §6「需要用户点头」第六半）：手机端今天这份绿色
      是浏览器档 116 条 + 各条功能腿的模拟器/真机读数**拼**出来的，从来没有一台活手机把五步链整条跑一遍——分档凑起来算不算
      §9 要的那次重跑，是产品口径，不由巡检自己签字。
26. **#179：合同 §5 的发送方那一半——这一端本来就拦，缺的是另外两端；句子改口，这一端的身体第一次有了守卫**（动的是合同、PC 三处与
    取证；**手机侧共用文件一行未改**（`cs-client.uts:131` 那句 `opts.paths.length > MAX_FILES_PER_OFFER` 是 #174 就立在原地的），
    两个宿主也没动——所以两道编译门**本轮没跑**：这一端的源码一个字节没变，变的只有合同散文、PC 的实现与守卫里指着这一端的那条判据；
    完整账目在 `../docs/feature-matrix.md` §6 第 30 条）
    - **§5 那句原来只点名手机**：「手机的发送方在本地就按同一个数拦下」——照着这句话写的 PC 两个发送口（GUI 与 CLI）都没拦：
      2001 个文件先全量哈希一遍（探针 1.4 s），`POST /v1/offer` 真的上了线，对面回 `400 UNSUPPORTED_PROTOCOL`，而屏上说的是
      「对端版本不兼容」——发送方自己的错，话却指向对面。本轮先量（`.probe/r13_sender_probe.py`）再补：PC 现在在目录摊开之后、
      第一个字节读进来之前就数（`app/net/send.py` 的 `plan()`），并在 `offer()` 这个咽喉上再数一次；GUI 与 CLI 各自接住
      `TooManyFilesForOffer`，说的是这一单自己的话（「一次最多 {n} 个文件。」，七语言词条本轮第一次走完整 i18n 流程，
      `i18n_sync` rc=0）。
    - **合同改口，数字没动**：那句从「手机的发送方」改成「发送方（PC 与手机）都在本地按同一个数拦下」——线上一格没改，接收方
      照旧拿 `UNSUPPORTED_PROTOCOL` 回陌生人的超量清单（这一端 5c 那两条规模腿 `多一个文件就被拒（400）` / `正好 2000 个文件的清单收下`
      原样还绿）。#174 那个口径题的分岔这次走的是不要点头的那支：给 v1 错误码表加一格「太大」要 §7 的兼容决定，不由巡检签字；
      纯实现让所有发送方本地预检不需要。
    - **这一端的身体第一次被守卫看着**：`check_sender_limit()`（`mobile/scripts/check_protocol.py:428-456`）除合同那句与 PC 两处
      `raise` 外，还拿 `opts\.paths\.length > MAX_FILES_PER_OFFER` 核这一端发送方那个比较还在不在——它以前只是"合同说手机做了"，
      没有一条判据真的读过 `cs-client.uts`。守卫 OK 行 14 → **15 行**；五次负向各自单独变红（`.probe/r13_guard_negatives.txt`、
      `.probe/r13_neg5.txt`）。第一次跑出来有一条负向是绿的，原因记下来：散文判据 `发送方[^→\n]*本地` 匹配得到旧的「手机的发送方在本地」
      那句——句子改了但形状没被钉住。改判 `发送方（[^）]*）都在本地` 后才分得开。与 #178「文件里有没有 nested 这个词」同一族教训：
      散文守卫要钉句子的形状，不是词的存在。
    - **档位**：`门禁` PC 侧 148 → **152 条 PASS、`RESULT ALL PASS`**（`.probe/r13_pc_selftest.log`；新四条 :337-380，
      其中「`offer()` 把同一个数写在咽喉上」那条读数是 `ok | wire calls: []`——一个字节都没上线）；`浏览器` 档本轮没重跑接收自检，
      因为这一端一个字节的源码都没变，116 条腿读的还是 #178 那一份。
    - **还欠的那格**：这一端没有新的设备腿，理由同 #177/#178——`cs-client.uts` 本轮一行未改，设备腿只能重复源码守卫已经钉住的东西。
      PC 侧也没有真窗口读数：`_send_worker` 离屏到不了真文件选择器，与 §6 第 12 条记过的是同一形状；那两条 GUI/CLI 屏上的话本轮由
      词条与 catch 点钉着，档位只到 `门禁`。

27. **#180：合同 §4 那张清单摊开只有四个键，这一端线上早就发六个——本轮把块补齐、把三个没人读的数说清，并第一次让守卫读这一端发送方的字面量**（动的是合同、
    PC 门禁与这一端浏览器替身的自检；**手机共用状态机与两个宿主一个字节没改**（`cs-receive.uts` / 两个宿主都不动，`cs-protocol.uts` 也照原样发那六个键）——
    所以两道编译门**本轮没跑**：宿主的源码没变，变的只有合同散文、这一端的自检腿与守卫里指着这一端的那几条判据；完整账目在 `../docs/feature-matrix.md` §6 第 31 条）
    - **合同那块比线上窄**：`manifest` 的 JSON 块写四个顶键（`offer_id`/`protocol_version`/`total_size`/`files`）、五个条目字段，而
      `offerJson()`（`cs-protocol.uts:317-326`）与 PC 的 `offer()`（`app/net/send.py:422-430`）早就各发六个顶键——多 §7 的
      `compatible_versions` 和 `from`——条目也多一个 `type`（`manifestOf()` `:298-305`）。第四位读者照那块去发，发出来的清单两端都不认；
      照那块去核一次真捕获，会把三个在场的键判成"多发的"。这一端不改：那几个字节是 v1 已上线的形状，拿掉任何一个是 §7 的兼容决定。
    - **三个数各自换来了什么**（本轮先量再说）：`total_size` 只有 PC 的命令行应答读它（`app/cli.py:305`，还带一份按条目求和的兜底），
      `app/net/receive.py:729` 只把它写进日志，这一端的共用内核读 **0** 次；`mtime`/`type` 三端都发，这一端逐字段记进台账
      （`cs-receive.uts:965-966`），PC 把整份条目原样存进台账，两端的 `state` 应答都只回 `id`/`received`/`missing`——没有哪一端把
      `mtime` 写回磁盘时间，没有哪一处屏读 `type`；`from` 三端都发、谁都不读（PC 给用户看的名字来自钉子表）。合同新写的那段说的就是这句：
      **在场，但都不是判据**。
    - **这一端补的三条腿**（`web/index.uts:1723-1757`，5g）：一份 `total_size` 谎报 987654321、条目自己说 7 字节的清单 → 照样登记、照样等人决定
      → 点接受以后**开档的字节是条目自己那个 `size`**（不是九亿多）→ 那一块照常收下、整单照常过摘要。档位 `浏览器`：
      **接收自检 116 → 119 项全部通过**（`.probe/r14_web_after.txt`）。第一趟开档那条是红的：`不符 …：没有这份开档`——
      `recvStore` 的键是 `landingOf(offer_id, relpath)`，我读的是 `/模拟接收目录/<offer_id>/<relpath>` 那个给用户看的落点字符串；
      **红的是量法，不是端上有病**，两处都记进取证。
    - **守卫 15 → 16 行**（`check_manifest_fields()`，`mobile/scripts/check_protocol.py:459-529`）：这是第一次有判据去读这一端
      **发送方**的字面量——`offerJson()` 与 `manifestOf()` 的键集合必须与合同那块逐键相等（少一个键、多一个键都红），条目的六个字段同样逐个核；
      另外钉住那句「`total_size`…接收方不拿它判任何事」的句式、`cs-receive.uts` 里这个字段名一次都不许出现、PC 接收方凡碰它的行必须是日志行、
      以及这一端那三条腿还挂在 `§4 total_size` 名下。**八处负向每一处单独红**（`.probe/r14_guard_negatives.txt`，驱动 `.probe/r14_negatives.py`），
      还原后六个文件逐个字节等于改动前（含临时改坏的 `cs-receive.uts`）。第七处第一次跑是绿的：判据写成子串，把 PC 门禁的注册行**注释掉**以后子串还在——
      改成行形状 `^\s+phase_manifest_fields\(proto, workspace\)$` 才分开。#178/#179 那条教训的第三次命中，本轮又多学到一半：子串判据连最普通的作废方式都挡不住。
    - **档位**：`门禁` PC 侧 152 → **158 条 PASS、`RESULT ALL PASS`**（`.probe/r14_pc_final.txt`，新六条在 `scripts/protocol_selftest.py:1027` 那一相，
      注册在 `:1392`）；`浏览器` 档 119 条腿整体回归门全绿。取屏上读数仍走 #177 那套路子：页签 `visibilityState=hidden`，
      `runRecvSelf` 里临时加一行 `console.log` 把整份读数打进控制台再取回，取完 `git checkout` 还原——`store/session.uts` 现在与 HEAD 一个字节不差。
    - **还欠的那格**：这一端没有新的设备腿，理由与 #177/#178/#179 同形——共用状态机与两个宿主本轮一行未改，而合同那块说的六个键，
      守卫已经直接读过这一端发送方的源码。要说欠：**没有一条腿真的把手机发出去的那份清单摊开看过键名**（设备上是屏上读结论，不看 JSON），
      那要一次设备腿；本轮判它属于合同散文的形状题，不上机。另外 `mtime`/`type`/`from` 要不要真去做点什么、还是干脆下线，
      记在 `../docs/feature-matrix.md` §6「需要用户点头」第七半——下线那一支动的是 v1 已上线的字节，是 §7 的决定，不由巡检签字。

28. **#181：合同 §4 那条 `finalize` 应答纸上只画了 `{"id","ok"}`，这一端线上回的是四个键；那句「只补传该文件的问题分块」从来没说块号从哪儿来**（动的是合同、
    这一端浏览器替身的两组自检腿与守卫；**手机共用状态机与两个宿主一个字节没改**（`cs-receive.uts` 那条答复、`cs-client.uts` 那处读键都照原样）——
    所以两道编译门**本轮没跑**：宿主的源码没变，变的只有合同散文、这一端的腿与守卫里指着这一端的那几条判据；完整账目在 `../docs/feature-matrix.md` §6 第 32 条）
    - **纸缺的那半正是这句话的支点**：§4 写「任一项 `ok: false` 时发送方可只补传该文件的问题分块再 finalize 一次」，可那块示例里
      既没有块号来自哪个键，也没有顶层 `offer_id` 和落点 `path`——而**同一节**上面讲落点时已经把 `path` 算进合同了，一节里两处对同一条
      应答各说各话。这一端线上回的是 `{offer_id, verified:[{id, ok, missing, path}]}`（`cs-receive.uts:1130`、`:1140`），发送方读的
      就是 `broken[i].missing`（`cs-client.uts:528`）与那条 `path`（`:502-508`，屏上那句「落到」）。本轮把块补成线上真发的形状、
      把两个字段各被谁读写清，**一个键都没动**。
    - **这一端补的接收四条腿**（`web/index.uts:1774-1829`，5h）：手写一份 `size: 0` 的清单投进去 → 一块不推也照样按 §4 的开档规则
      开出 0 字节 → finalize 回的正是顶层两个键、条目四个键（`sameKeys` 逐键比，不看子串）→ 那块 0 字节的落点就是它的全部内容，
      `ok: true` 且 `path` 报回文件名；再投一份、把那份 0 字节的落点从盘上拿掉 → `ok: false` + **空的** `missing` + `path: null`。
      档位 `浏览器`：**接收自检 119 → 123 项全部通过**。
    - **发送那三条腿**（`web/index.uts:2564-2575`，H；走的是共用的 `cs-client`，不是浏览器替身实现）：`ChunkSwallow` 加了两个旋钮
      （`eraseAfter`/`eraseRel`——第 2 块写完以后把那份大文件的落点从盘上删掉，同时把 offer id 记下来才删得准）。整单跑完是绿的、
      对端一共收到**四次**写块（前两块 + 补传那两块）、`state` **一次都没问过**——那几个块号是 finalize 那条答复给的。
      **发送自检 29 → 32 项全部通过**（`.probe/r15_web_after.txt`）。
    - **第一趟整页白屏，两个自检都点不出**：新块的 `const lostDone` 与 5g 里已有的同名变量撞了，vite 把模块炸成
      `Identifier 'lostDone' has already been declared`——这一端的自检是同一个函数里的直白语句，**加块先查重名**。改名 `gone*` 以后全绿；
      取屏上读数仍走 #177 那套路子（`runRecvSelf`/`runSendSelf` 各临时加一行 `console.log`，取完 `git checkout` 还原，
      `store/session.uts` 现在与 HEAD 一个字节不差）。
    - **守卫 16 → 17 行**（`check_finalize_reply()`，`mobile/scripts/check_protocol.py:532-622`）：钉的是形状不是词在不在——§4 里提到
      `verified` 的 json 块必须**只有一个**、顶键集合与条目键集合分别等于 `{offer_id, verified}` 和 `{id, ok, missing, path}`，
      并且等于两端接收内核各自那处**字面量**（这一端读 `finalizeReply()` 里那个 `const entry`，PC 读 `receive.py:796` 那个 `results.append({...})`——
      都得先按函数切开：`state` 应答在 `cs-receive.uts:760` 也建条目，不切开就抓到 `['name','ok','received']`）；两端发送方必须还在读
      `missing`；那句「问题分块」必须还点名两个发送方的文件与行段；`size: 0` 那一格与那句「不由巡检签字」必须在纸上；PC 门禁那一相
      必须存在**且被调用**；这一端两组的腿数有下限。**21 处负向每一处单独红**（`.probe/r15_negatives.py`），还原后守卫重跑全绿。
      两处第一次跑不对：合同里 `  "offer_id": "9f1c…",` 那段锚点先撞上 §4 上面那张 manifest 块（两块同形），改成两行锚才对准；
      另一处只改了 vendored `spec.md` 没同步 `SOURCE.json` 摘要，守卫在摘校验那一关就红了——红是红了，但说的不是这条谓词。
    - **档位**：`门禁` PC 侧 158 → **165 条 PASS、`RESULT ALL PASS`**（`.probe/r15_pc_selftest3.log`，新七条在
      `scripts/protocol_selftest.py:1108` 那一相，注册在 `:1497`）；`浏览器` 档接收 123 / 发送 32 两条整体回归门全绿。
    - **还欠的那格**：这一端没有新的设备腿，理由与 #177/#178/#179/#180 同形——共用状态机与两个宿主本轮一行未改，而那条应答的四个键
      守卫已经直接读过这一端的字面量。要说欠：`size: 0` 那一格**三端今天都救不回来**（一块都没有，答复给不出块号，"整文件重推"
      写不出一个字节，这一单以 `FILE_DIGEST_MISMATCH` 收尾）——本轮只把它的死法量清、写进 §4；要不要给接收方加一条
      「finalize 时按开档规则把零字节的重新开一遍」的义务，那是三端同改的新行为条款，记在 `../docs/feature-matrix.md`
      §6「需要用户点头」第八半，不由巡检签字。

29. **#182：合同 §4 那三条应答——纸上把清单那条画成只有一个 `accepted` 键、把「中止并清理」写成这件事的全部，还没人回答的那一问在 PC 上回的是「不认识的 id」**
    （动的是合同、这一端浏览器替身的十条接收腿与守卫；**手机共用状态机与两个宿主一个字节没改**（`cs-receive.uts::abortReply`、
    `app-android/index.uts:632`、`store/session.uts:683` 都照原样）——所以两道编译门**本轮没跑**；完整账目在 `../docs/feature-matrix.md` §6 第 33 条）
    - **这一端量到的是"三端本来就一致、只有纸上缺"**：待决那条回的两个键（`200 {'accepted','offer_id'}`，`files[]` 一个都不摊）、接受那条
      三个顶层键 + 条目三个数、`DELETE` 那两条键 `{offer_id, dropped}`，这一端线上全都发对了（`cs-receive.uts:749` 的 `payloadOf`、`:1143` 的
      `abortReply`）；合同里画的是 `200 {"accepted": true}` 一个键，而 `DELETE` 一条应答都没写过。本轮把三块补成线上真发的形状，
      并把那句「与 `GET state` 同一份 `files[]`」按量到的写成**逐字节相同**、点名两个生产者。**一个键都没动。**
    - **这一端补的接收十条腿**（`web/index.uts:2265-2323`）：待决那一问不给落点 → 撤一单**还没人答**的，回的就是那两个键且卡片当场下台 →
      撤走之后才点下的「接受」不登记这一单、也不替它开一个文件 → 撤走之后重投拿的还是 `OFFER_UNKNOWN` → 接受那条摊开等于纸上那块 →
      那句「同一份」在这一端也是逐字节的同一份（发送端因此一条 GET 都不补，`cs-client.uts:610` 把那份体直接交给 `statePlans`）→
      落齐之后同一形状、三个数换成完成后的值 → 填完的一单撤掉回的仍是那两个键 → 撤掉之后 state 与续传台账都不再留着它 →
      撤掉之后重投也是 `OFFER_UNKNOWN`。档位 `浏览器`：**接收自检 123 → 133 项全部通过**、发送自检 32 项照旧全绿
      （`.probe/r16_web_after.txt`，读数直接从「传输」页那份日志逐条读，没有再动 `store/session.uts`）。
    - **守卫 17 → 18 行**（`check_offer_reply_shapes()`，`mobile/scripts/check_protocol.py:625`，`main()` 在 `:828` 调用）：合同那块 json 的顶键
      与条目键集合必须等于 PC `payload()` 与这一端 `payloadOf` 那两处字面量；PC 的两条应答必须出自**同一个函数**（`handle_offer` 与
      `handle_state` 都得是 `return state.payload()`，不然「同一份」又是两个实现）；`handle_abort` 两处都回那两个键、认得 `_asking`、记成 `withdrawn`；
      两个宿主那一行**各且只有一处**写 `accepted:false`，且那一行不许提前摊开 `files[]`；两端发送方不许改成拿 `received` 判事；
      「逐字节相同」「就只有这两个键」「不登记、不开档」「没人拿它判事」四句必须在纸上。**36 处负向每一处单独红**
      （`.probe/r16_negatives.py` → `.probe/r16_guard_negatives.txt`），还原后 `rc=0` 全绿、九个看住的文件字节不差。两处第一次跑不对：
      合同的散文会在任意宽度处换行，子串判据读的是原文——纸上的句子明明在、守卫却红，改成把 §4 折掉空白再比（`said()`）才叫读句子；
      另一处是 PC 内核里 `restored.payload()` 也满足「走 payload()」那句子串，负向拧红后守卫照样 OK，判据收成 `return state.payload()` 才分得开。
    - **还欠的那格**：这一端没有新的设备腿——共用状态机与两个宿主本轮一行未改，而 PC 那一半（待决那一问也归 `DELETE` 管）本来就没有手机的份：
      手机从 #59 起就把待决的 offer 登记在 `inbox.offers` 里，`abortReply` 一直丢的是卡片。要说欠：**没有一条腿在活手机上按下过发送方那个"等满窗口"的取消**
      （屏上今天只有 B 级取消会走那条 `DELETE`），那是 #127/#133 同一族的一次设备腿；另外撤一单**已经填完**的，PC 逐文件 unlink、
      那个空的 offer 目录留在原地——这句写在 §4 的括号里、注明"不在合同里，也没人读它"，与 #147 那道按单/按文件的口径题是同一族。

30. **#183：合同 §4 分块那三句——一块写成 200 的体纸上从没画过、「最多 3 次」纸上是次数而三端做的是三次写、`X-Sha256` 没发也照样收**
    （动的是合同、这一端浏览器替身的一处接收分支加一处发送替身、九条接收腿与四条发送腿、一道守卫；**共用状态机 `cs-receive.uts`、两个宿主
    与两端发送方一个字节没改**——它们本来就是对的，所以两道编译门**本轮没跑**；完整账目在 `../docs/feature-matrix.md` §6 第 34 条）
    - **这一端量到的还是"三端本来就一致、只有纸上缺"，只是这回多了一个跟不上的替身**：`cs-receive.uts:999-1024` 线上回的正是
      `{index, stored}`、重发多带 `idempotent`、两副 detail（`{reason,got,want}` 与 `{index,expected}`）、越界 `{index,count}`，合同一块都没画；
      `:1009` 那句 `sha != '' && sha != digest` 说的是**头缺了就照收、不校验**，而纸上把 `X-Sha256` 和一个谁都不发的 `X-File-Size` 并列成两个分块请求头。
      把 `idempotent` 补上纸面以后，**唯一没照做的变成了这一端的替身**：`web/index.uts:652` 的 `routeChunk` 对同一块的重发又写一遍并回 `{index, stored}`。
      本轮给它补的是逐字节那一句（`sameBytes`，新 helper 在 `:640`）和一个贴着落盘口子的计数器 `recvWrites`（`:968`）——浏览器档位没有第二处证词
      能说「省掉一次重写」真的没重写。PC 那一支（`receive.py:770-777`）本来就跳过重写。
    - **这一端九条接收腿**（`web/index.uts:2350` 起）：一块写成的两个键 → 重复那一支多带的那一个 → 那一个键换来的**落盘口子压根没开** →
      摘要与体不符那副 detail（`expected` 是发送方自己声明的那一份，不是接收方算出来的）→ 长度那副三个键 → 越界那格两个键 →
      不带 `X-Sha256` 的 PUT 照样 200 → 那一片 `Z` 真的落进第 4 MiB 那个偏移 → 这一单最后的防线是整文件摘要，它一判不过台账就作废、按全缺重报。
      **四条发送腿**（替身新增 `rejectChunks`：`web/index.uts:2479`、`:2516`，那一组从 `:2795` 起）：逢分块必拒的对端上这一单判死、
      那一块**一共写三次**、三次之间一次 `state` 都没问、报出去的就是对方那一句。档位 `浏览器`：**接收自检 133 → 142 项全部通过**、
      **发送自检 32 → 36 项全部通过**（`.probe/r17_web_after.txt`）。那四条把"手机发送方也写三次"从**读源码读出来的**升成**屏上读出来的**——
      H5 那台发送方跑的就是手机上那份 `cs-client.uts`。头一趟红的三条全是腿自己的前提：照 PC 那份探针发七个 `Z`，而这一端清单里那个尾块
      该有一千字节，长度关把摘要关挡在前面；于是第三条只回 `missing:[1]`——`missing` 非空就不触发作废那支（PC `receive.py:801` 的
      `if not ok and not missing`，共用内核同一句）。按这一端尾块的长度发一整块 `Z` 以后三条都过。
    - **守卫 18 → 19 行**（`check_chunk_reply()`，`mobile/scripts/check_protocol.py:765`，`main()` 在 `:960` 调用）：§4 里提到 `stored` 的 json 块
      必须正好两块、键集合等于三个接收端各自那处字面量，两副 detail 同理；三个接收端必须都还在头缺失时跳过块级校验；这一端那一支必须**逐字节比**
      且旁边有个落盘计数器；`X-File-Size` 不许回到四个文件里的任何一个；两个发送方各按自己的名字写那三次（`retries=3` / `CHUNK_RESEND_MAX = 2`）；
      门禁那一相必须存在且被调用；两头的腿数各有下限；那七句话必须在纸上。**49 处负向每一处单独红**（`.probe/r17_negatives.py` →
      `.probe/r17_guard_negatives.txt`），还原后 `rc=0` 全绿。两处第一次跑不对：一条散文句子在 §4 出现了两次（本轮自己引那一条腿的名字里也含
      「一共写三次」），子串判据拧不红，判据收成那一整句才分得开；另一处是 FAIL 消息里那句 needle 带着 Python 引号，负向脚本按裸子串比期望。
    - **收了 #163 那道题的一半**：`X-File-Size` 从今天起不在合同的分块请求头那一列里，纸面写明"没有任何一端发、也没有任何一端读"，守卫盯着它
      不许回来；桌上只剩 `transport.max_parallel_chunks: 2` 那一格。**这一端还欠的**：`idempotent` 那一支在活手机上今天仍只有 #127/#165 那一族的
      间接证词（共用状态机本轮一行未改，两道编译门没跑）；"不带 `X-Sha256` 的 PUT"在真机上没人试过——量它要的是**改发送方**，而合同说的恰好是
      发送方必发，所以本轮把这句话记在纸上、各端量了一次，没有替它造一条设备腿。

31. **#184：合同 §4 保活陷阱那句「发送方看到连接被关要重连重发一次」——手机这一问的 `finalize` 改前没有第二趟，而补出来的第二趟会把同一个文件报两遍**
    （动的是合同、手机共用发送方 `cs-client.uts` 里 `finalize` 那一支、这一端浏览器替身的一处注入加五条腿、PC 接收侧三行、PC 门禁一个新相、一道守卫；
    **两个宿主（`app-android`、`app-harmony`）与共用接收内核 `cs-receive.uts` 一个字节没改**，所以两道编译门**本轮没跑**；完整账目在
    `../docs/feature-matrix.md` §6 第 35 条）
    - **手机端缺的是那一趟**：`cs-client.uts:482` 发完 `finalize` 以后，`status == 0`（读不到应答）从前直接落进 `status != 200` 那一支，
      整单被报成失败——而对面**很可能已经验完收下**，这一端只是没读到那句回答。合同 §4 那句「发送方看到连接被关要重连重发一次」在 PC 是
      传输层的 `for attempt in (0, 1)`（每条请求都有第二趟），在手机是路由层的各条规矩：清单那一问一秒后再问、分块那一问先问一次 `state`，
      `finalize` 这一问两样都没有。补的是 `cs-client.uts:488-491`：`finalize(offerId, isRetry, reasked)` 多带一个"这是第几趟"，
      `status == 0 && codeOf(body) != 'CANCELLED' && !reasked` 时 `setTimeout((): void => { finalize(offerId, isRetry, true) }, 1000)` ——
      一秒后**再问一次，只一次**。这一端每条请求本来就重拨一条新连接，所以第二趟落在手机上就是重新拨、原样再问。
    - **重投带来一条新的义务**：接收方验完删的是那份续传台账、不是这一单（PC 只删 `.chuanshu.state.json`，`finalizeReply` 只写 `complete`），
      所以重投拿到的是**同一份字节**——于是"同一个文件到了"这件事只能报一次。手机共用内核从 #35 起就有这道闸（`cs-receive.uts:1042-1052`
      的 `hasArrival`，登记那一支在 `:1060` 先问一次），**PC 改前没有**：改前探针（`.probe/r18_before_probe.txt`，那一趟是把 `app/net/receive.py`
      换成 `HEAD` 那份跑的）量到 `finalize#2` 把整表又报一遍、第三与第四趟各报一遍（`on_received` 一共四次）；补完三行按落点筛的闸以后同一份
      探针是 `['好的一份.txt', '相册/两块.bin']` 两次、不多不少（`.probe/r18_after_probe.txt`）。
    - **这一端两条接收腿加三条发送腿**（`web/index.uts:2458` 起、`:2852` 起；替身新增 `ChunkSwallow.muteFinalize` / `finalizeAsks`，
      注入在 `:2614`、计数在 `:2572`），档位 `浏览器`：**接收自检 142 → 144 项全部通过**、**发送自检 36 → 39 项全部通过**
      （`.probe/r18_browser.txt`，屏上逐条读到）。发送侧那三条是「`finalize` 那一问读不到应答时这一单**没被判死**」「它没有把已经落齐的字节
      重写一遍：这一单只写过一次块」「此刻对方只被出示过一次 `finalize`：第二趟在那一秒之后」。**这一档证到这儿为止**——那一秒之后的第二趟
      是不是真的把已经收下的一单救回来，浏览器里问的是替身自己，活手机上要造一个"第一趟吞掉 `finalize` 应答"的对端才算数
      （形状同 #173 那条清单腿：安卓 `adb forward` + 一个会吞回复的桩，鸿蒙 `hdc fport` 同一条）。**这一端还欠的设备腿**：
      `pack --iscustom` 出来的自定义基座上跑一次「手机发 → 桩吞掉 finalize 第一趟 → 屏上日志先说『这一问没读到对方的应答，一秒后再问一次』、
      最后说『对方已收下 N 个文件』」；`cs-client.uts` 这一支改的是共用发送方，安卓与鸿蒙都跑它，两道编译门本轮没跑（改的都是脚本层，
      没动原生半边），下一轮上机前先过 `HBuilderX cli compile` 那道门。
    - **守卫 19 → 20 行**（`check_finalize_replay()`，`mobile/scripts/check_protocol.py:896`，`main()` 在 `:1042` 调用）：那五句话必须在 §4 纸上；
      PC 发送方必须有 `for attempt in (0, 1)`；`cs-client.uts` 必须有那三处字面量（带 `reasked` 的签名、`!reasked` 那一支、那一秒后的重问）；
      PC 接收侧必须有 `_reported`、必须按落点筛、`handle_finalize` 里不许再出现"把整表报出去"那一句；共用内核必须有 `hasArrival` 的定义
      **并且登记那一支真的在问它**；这一端替身必须还能注入并计数；两头的腿数各有下限；门禁那一相必须存在且被调用。
      **23 处守卫负向每一处单独红**（`.probe/r18_negatives.py` → `.probe/r18_guard_negatives.txt`），还原后 `rc=0` 全绿；**另有 4 处门禁负向**
      （`.probe/r18_phase_negatives.py` → `.probe/r18_phase_negatives.txt`）把 PC 那道闸真拆掉再跑那一相，四条分别红在
      「重投的那一问不再把同一个文件报第二遍」（两处）、`补好之后这一单全过…只出现一次`、「另一单的同名文件是新的一行」，还原再跑 `RESULT ALL PASS`。

32. **#185：合同 §4 那句「同一份字节只报一次」——PC 的闸写在进程里，而它守的那两笔账写在磁盘上**
    （动的是合同、PC 接收侧（`app/net/receive.py`）、PC 门禁那一相的五条腿、一道守卫；**两个宿主（`app-android`、`app-harmony`）、共用接收内核
    `cs-receive.uts`、共用发送方与这一端浏览器替身一个字节没改**，所以两道编译门与浏览器自检**本轮没跑**；完整账目在
    `../docs/feature-matrix.md` §6 第 36 条）
    - **第十八轮补的那三行按落点记在 `ReceiveService` 的一个集合里**，进程一停就空。它守的东西不跟着停：续传台账 `.chuanshu.state.json`
      与 §6 那份接收记录都在磁盘上。于是合同那句「只报一次」在一场之内成立、跨一次重启不成立。改前探针（`.probe/r19_before_probe.py` →
      `.probe/r19_before_probe.txt`，档位 `门禁`）量到的就是这一趟：一单两个文件，第一个先齐、`finalize#1` 报过一次，把接收方停掉再用
      同一个根目录重开（`adopt_interrupted_offers()` 认领下这一单），补齐第二个再 `finalize`——第一个文件**被报第二遍**，同一个落点在
      收到的文件里两行，而它磁盘上的字节一个没动。补好以后同一支探针是 `[['好的一份.txt'], ['相册/两块.bin']]`、重复落点
      `[]`、`出现 1 次`（`.probe/r19_after_probe.txt` 同一行）。
    - **修法是把名单挪进这一单自己的台账**：`OfferState.announced` 随 `.chuanshu.state.json` 一起写、一起认领，`handle_finalize` 按它筛
      （先落笔再播报；只有还欠着文件的这一单才落笔，全成那一单的台账随即作废，名单留在内存对象上给同进程的重投用）。
    - **手机那一半是结构给的，本轮没有量**：`hasArrival` 问的是持久化的收件台账（`cs-receive.uts:1042-1052`），而那份台账开机读回
      （`adoptArrivals`，浏览器自检里「开机读回收到清单」「重启后卡片仍列这两个文件」两条量过它自己那一半）。**两端的播报时机也不同**：
      手机只在整单齐了才落笔（`cs-receive.uts:1133-1139` 的 `recordArrivals` 在 `whole` 里面），所以 PC 那句"第一个先齐并报过"在手机上
      是"第一个要等整单才报"——同一趟探针因此跑不出 PC 那一行的形状，这不是违约（合同没规定何时播报），但也**没在手机上验过**。
      **这一端欠的设备腿**：杀掉正在接收的手机（`adb shell am force-stop` / `hdc shell aa force-stop`），让对面把剩下那一单续完，
      再看「收到的文件」——每一个落点只许一行，且那一行的时间还是第一次落盘的那个。这一条要在安卓与鸿蒙各跑一次才算数。
    - **守卫还是那 20 行，判据换了三处**（`check_finalize_replay()`，`mobile/scripts/check_protocol.py:896`）：纸上多钉两句
      （「活得比这一场久」「先落笔再播报」）；PC 接收侧从"必须有那个集合"改成"必须有 `OfferState.announced`，且 `persist()`/`load()`
      各带它一行，`handle_finalize` 按它筛"，并反过来**禁止** `self._reported` 回到服务里；门禁那一相必须含 `adopt_interrupted_offers()`
      与读回台账那两处字面量。**15 处守卫负向每一处单独红**（`.probe/r19_guard_negatives.py` → `.probe/r19_guard_negatives.txt`），
      还原后 `rc=0` 全绿；**另有 3 处门禁负向**（`.probe/r19_phase_negatives.py` → `.probe/r19_phase_negatives.txt`）：台账不写这份名单
      → 红在「已经报过的那一笔写在续传台账里」加「接收方重启之后，第一份字节不再报第二遍」；认领时不读回 → 只红在后一条；闸不照名单筛
      → 红在第十八轮那三条（同进程那一趟本来就被它们看着）。三处红完，还原再跑 `RESULT ALL PASS`。

33. **#186：合同 §5 那句「发送方也拦点开头的名字」——接收方按段判，PC 的发送方按叶子名判，于是一单里一个 `.git` 的名字让整单陪葬**
    （动的是合同、PC 发送侧（`app/net/send.py::plan()`）、PC 门禁新增一相七条腿、守卫新增一条判据（OK 行 20 → 21）；
    **两个宿主、共用接收内核 `cs-receive.uts`、共用发送方 `cs-client.uts` 与这一端的浏览器替身一个字节没改**，所以两道编译门与
    浏览器自检**本轮没跑**；完整账目在 `../docs/feature-matrix.md` §6 第 37 条）
    - **改前量到的**（`.probe/r20_before_probe.py` → `.probe/r20_before_probe.txt`，档位 `门禁`）：磁盘上 `工程/读我.txt`、
      `工程/.git/config`、`工程/相册/照片.bin` 三个文件，`plan()` 带 base 报出去的是三条 relpath，**其中一条带着 `.git` 那一段**；
      递给接收方以后整单 `400 PATH_REJECTED detail={'segment': '.git'}`，播报批次 `[]`、那两份无辜的在磁盘上也 `[]`。把 base 摘掉
      （命令行默认的平铺形状）反倒传成，而 `.git/config` 被拍平成 `config` 落在对面。改后两条都不再出现：清单只剩两份、那一单被收下、
      `config` 那个落点读 `False`（`.probe/r20_after_probe.txt`）。
    - **手机这一端为什么没有这个洞**：它压根不做目录遍历——`uni.chooseFile` 交出来的是平铺的叶子名，而 `cs-client.uts:127-141` 的
      `pathCheck` 在发送之前**逐条**问 `pathReject(opts.relpaths[i])`，用的就是接收方那一份按段判的规则，违规整单不发（屏上那句
      「本地就拦下」）。这条判据本轮被钉进了守卫（`check_hidden_segments()`），钉的是那一行字面量还在、问的是 `relpaths` 而不是 `paths`。
    - **手机这一半本轮没有升档去量**：`pathReject` 的按段行为在浏览器档量过（第九轮那组 5d 里「点开头的段一律拒（`.env`）」与
      「嵌在中间那段也算（`sub/.git/config`）」两条，判的是同一个函数），**没量的是调用点**——一条 relpath 带点段的清单在手机发送时
      是不是真的在本地停住、一个请求都没打到对面。这一端欠的那条腿：`senderSelfReport()` 里加一条 `runSender(…, 'sub/.git/config', …)`，
      判 `!ok` 且 summary 含「本地就拦下」、并判那个假对端 `offerAsks == 0`（要跑 vite 5173 + 页面点「发送自检」才算 `浏览器` 档）；
      再在安卓或鸿蒙各挑一个点开头的目录，看屏上说的是「本地就拦下」而不是对面那句版本/路径不兼容，才算 `真机`/`模拟器` 档。
    - **守卫多一条判据、多一行 OK**（`check_hidden_segments()`，`mobile/scripts/check_protocol.py:459`）：纸上五句（「也按段拦」
      「只在叶子名上成立」「`_has_dot_segment`」「被拍平成 `config`」「问的就是整条 relpath」）、PC 侧三条（`_has_dot_segment(` 三次、
      那条两段的 `if` 逐字在、**禁止** `entry.name.startswith(".")` 回到 `send.py`）、手机侧一行、门禁侧新相与两条腿的字面量。
      **13 处守卫负向每一处单独红**（`.probe/r20_guard_negatives.py` → `.probe/r20_guard_negatives.txt`），还原后 `rc=0`、21 行全绿；
      **另有 3 处门禁负向**（`.probe/r20_phase_negatives.py` → `.probe/r20_phase_negatives.txt`，每处只跑 `phase_hidden_segments` 那一相）：
      改回只判叶子名 → 红 4 条腿且那一相随后跑不完（`offer` 抛的就是线上那句 `PATH_REJECTED`）；只判 relpath → 只红"拍平那一条"；
      只判摊开的路径 → 红两条（平铺的叶子名那一条 + 整目录自己叫 `.私有` 那一条）。三处红完，还原再跑 `FAILS=0`。

M2a 的最小切口是"手机发、PC 收"：扫（或粘贴）PC 的二维码拿到地址与完整指纹，用户只核对同屏的
一次性配对码——PC 侧接收端已经跑绿，手机只要把
`/v1/pair`、`/v1/offer`、`PUT chunk`、`/v1/finalize` 四条打出去就能有结论，发现层可以先不做。
这条切口在 #106 上撞到的不是网络：手机拨不进 PC，是因为 PC 当时把自己那把 Ed25519 身份密钥直接当 TLS
叶递出来，而 Android 的 TLS 客户端不接受这种服务器证书（同一个端口换成 RSA-2048 叶就握手成功）。
现在三端一致：身份密钥只签名，套接字只递独立签发的 RSA 叶。
