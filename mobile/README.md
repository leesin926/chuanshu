# 传书 ChuanShu — 手机端（uni-app x）

一套代码出 Android 与 HarmonyOS Next。iOS 自 2026-10-24 起终止：没有 Mac 就出不了可签名的包，
`utssdk/app-ios/` 那两半边代码留在树里不再推进（协议契约的 vendored 副本、它的校验器，以及一个已经
能用 HBuilderX CLI 编译的 uni-app x 工程（`chuanshu/`）都在仓库里）。

**证据口径**：本仓库对手机端的一切"已验证"说法只到 *Kotlin 编译通过* 这一层。UTS→Kotlin→dex
在没有真机的情况下可以本地跑完，运行时行为（Android 的 provider 是否暴露 Ed25519、平台解析器是
否接受我们手搓的 DER、TLS 握手能否成）必须等真机。跨语言的正确性则已经在桌面上验证过：同一套
Java/Python 实现在这台机器上和 PC 端 `app/net/identity.py` 双向通过。

## 现状

```
shared/protocol/protocol.json   唯一真相源（从 chuanshu-pc vendored，只读）
shared/protocol/spec.md         语义与理由
shared/protocol/SOURCE.json     来源戳：仓库、commit、protocol_version、两份文件的 sha256
scripts/check_protocol.py       校验 vendored 副本没被手改 + 契约自身没跑偏
chuanshu/                       uni-app x 工程（AppID __UNI__8DB2EF6，目标 APP-ANDROID）
chuanshu/uni_modules/cs-identity/   UTS 插件：能力探针、手搓自签 X.509、回路 TLS 自检
chuanshu/store/session.uts            跨页共用的会话：连接、发送、接收、日志都在这一份状态里
chuanshu/pages/home/home.uvue         首页：连接状态 + 连对端（扫码/粘贴/配对码）
chuanshu/pages/files/files.uvue       文件页：收到的文件与待发送的清单
chuanshu/pages/me/me.uvue             我的页：本机身份、配对信息、监听开关、探针入口
chuanshu/pages/send/send.uvue         发送文件页：选文件、发送、进度
chuanshu/pages/detail/detail.uvue     传输详情页：两个方向的任务 + 日志
chuanshu/pages/probe/probe.uvue       三个按钮的平台能力探针，真机上点
chuanshu/static/tabbar/               tabBar 图标，由 mobile/scripts/gen_tabbar.py 画
```

```powershell
python scripts/check_protocol.py
```

输出里的 commit 必须等于 `SOURCE.json` 的 `source_commit`（当前是 `754b863d…`），否则就是副本被手
改过。改协议的正确顺序：先改 PC 仓库 `protocol/`，跑 PC 自测，再重新 vendor 到本仓库并更新
`SOURCE.json` 的 commit 与摘要。

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

1. 身份：Ed25519 自签 X.509（CN=peer_id），信任锚是证书 SPKI 的 SHA-256，不是 peer_id。
2. 七个端点、`X-Chuanshu-Auth` token、`X-Sha256` 分块摘要、`X-File-Size`。
3. 路径清洗（`spec.md` §5）——手机当接收方时这条同样致命，不能因为"手机不跑 Windows 保留名"就省。
4. 断点续传：状态文件只是提示，结论只来自 `finalize` 的整文件摘要。

## 平台账（写代码前先认清成本在哪）

| 端 | 必须做 | 卡在哪 |
|---|---|---|
| Android | 接收中起前台服务（`dataTransfer` 类型）、13+ 通知权限、局域网权限 | 服务被杀 = 连接被掐 |
| ~~iOS~~ | **2026-10-24 终止**：出包要 Mac 与签名，这台机器没有。剩下两条事实记在这儿，别当待办 | Info.plist 里 `NSLocalNetworkUsageDescription` + `NSBonjourServices` 声明 `_chuanshu._tcp`；**退后台后监听 socket 不再接受新连接**，协议层绕不过 |
| HarmonyOS Next | uni-app x 走 ArkTS 通道；mDNS 用 `@kit.NetworkKit` 的 `mdns` | 卓易通这类 APK 兼容层发不了 UDP 广播，发现只剩扫码 |

鸿蒙（和被终止的 iOS）的后台限制属于产品事实，处理方式是在"接收中"界面直说"请保持传书在前台"，而不是
让用户以为还在收。这是 `spec.md` §6 的口径，Android 与鸿蒙一致。

## 探针在真机上要回答什么

`cs-identity` 的三个导出函数按"最后一行写到哪"读，而不是只看有没有报错：

| 函数 | 回答的问题 | 失败时最关心的那一行 |
|---|---|---|
| `identityProbe()` | Android 自带 provider 里有没有 `Ed25519`，`getEncoded()` 是不是 44 字节 SPKI，PKCS12 + KeyManagerFactory 能不能起来 | `stopped here:` |
| `certProbe(peerId)` | 平台 `CertificateFactory` 接不接受我们手搓的 DER，签名能不能被外人验过 | `parsed:` / `stranger rejected:` |
| `tlsSelfCheck(peerId, port)` | App 内的 HTTPS 服务能不能和"只信这一张证书"的客户端握手成功，且换一张证书就被拒 | `pinned match:` / `stranger REJECTED:` |

浏览器目标下走的是 `utssdk/web/index.uts`：它明说浏览器没有 `java.security`、也开不了 TCP，所以三个按钮在浏览器里的输出**不是证据**，只是界面与路由通了。这个文件存在的唯一理由是 `import ... from '@/uni_modules/cs-identity'` 在非 App 平台也要能解析——只有 `app-android` 目录时，web 端会直接 `Cannot find module`。

三个都不依赖第二台设备，`tlsSelfCheck` 走 127.0.0.1，PC 与手机的局域网互通留到 M2a。

不引 BouncyCastle 是刻意的：UTS 插件里的三方依赖要云打包时才从仓库拉，这台机器到那些仓库没有可
靠路线。证书改用手搓 DER（约 236 字节），只需要 JDK 自带的 `Signature`/`MessageDigest`/
`CertificateFactory`。桌面侧同一套构造已经跑通：`E:\wowo3\.probe\probeB\` 的 Java 实现与 PC 的
`app/net/identity.py` 双向 9 项全过，含"前缀不符要拒"和"陌生指纹要拒"两条负例。

## 待办（按依赖排序）

1. ~~HBuilderX 建 uni-app x 工程~~（已建，Android 与鸿蒙两个目标都开着）
2. UTS 侧实现身份与 TLS 指纹固定：Android 用 `java.security`（探针已覆盖），鸿蒙用
   `@kit.CryptoArchitectureKit`。这是唯一需要两套原生桥接的地方，其余都在 UTS 层（iOS 用
   CryptoKit 那条随 iOS 一起终止）。
3. 接收端服务：Android 前台服务、鸿蒙仅前台可用，UI 状态按 §6 显示。
4. 发现：mDNS 优先、UDP 广播补充、扫码/手输兜底（顺序不可颠倒，也不能只留 mDNS）。
5. 与 PC 端做真机互传回归：中文目录、多文件、中途杀进程续传、错误码中英文文案。

M2a 的最小切口是"手机发、PC 收"：扫（或粘贴）PC 的二维码拿到地址与完整指纹，用户只核对同屏的
一次性配对码——PC 侧接收端已经跑绿，手机只要把
`/v1/pair`、`/v1/offer`、`PUT chunk`、`/v1/finalize` 四条打出去就能有结论，发现层可以先不做。
