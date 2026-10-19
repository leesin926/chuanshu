# 传书 ChuanShu 传输协议 v1

机器可读契约在同目录 `protocol.json`（端口、分块大小、错误码、端点清单）。本文件解释
**为什么这么定**以及两端必须一致实现的语义。PC 端（`app/net/`）与手机端（`shared/protocol/`）
都以此为唯一真相源；改协议必须先改这两份文件，再动代码。

## 0. 角色：对等，不固定谁收谁发

每个运行中的实例同时是 server 和 client：监听一个端口、广播自己的存在、既能发也能收。
文件互传意味着手机和 PC 都要能发起，所以协议里没有"主控端"概念。

代价写在 §6「保活」——手机端当接收方时必须保持可连状态，这是各平台限制最集中的地方。

## 1. 身份

| 字段 | 生成 | 存放 |
|---|---|---|
| `peer_id` | 首次运行随机 16 字节 hex | 用户目录 `identity.json` |
| `keypair` | Ed25519，自签 X.509（CN=peer_id，10 年） | 同上，私钥文件权限按平台收紧 |
| `fingerprint` | 证书 SPKI 的 SHA-256 hex | 派生值，不落盘 |
| `name` | 用户可改的设备名 | 用户目录 `settings.json` |

`peer_id` 会随重装变化，**信任锚是 fingerprint，不是 peer_id**。同一 fingerprint 换了
peer_id 视为同一台设备。

## 2. 发现

三条路径，实现时按顺序尝试，任一可用即可配对：

1. **mDNS**：注册 `_chuanshu._tcp.local.`，TXT 带 `ver`、`name`、`fp`（fingerprint 前 16 位）、`ts`。
   iOS 必须在 Info.plist 的 `NSBonjourServices` 里声明 `_chuanshu._tcp`。
2. **UDP 广播 43721**：每 3s 发一次 `{peer_id, port, v, name, fp, ts}`，监听常驻。多播在部分
   环境（iOS 新版本、鸿蒙卓易通兼容层）会被拦，所以它是补充而非依赖。
3. **扫码/手输 IP**：二维码里带齐 §3 的全部字段，不依赖任何发现协议。发现失败时 UI 必须
   直接给出这条出口，不能只写日志。

前两条广播只带 **fingerprint 前缀**，不带完整摘要：广播本身不构成信任，前缀只用来排除
"地址撞错机器"。完整摘要由 `GET /v1/hello` 的 `fingerprint` 字段给出，收到候选后必须先核对
前缀再进入 §3 配对。"完整指纹 + 同屏 4 位码"两个条件同时成立才算配对成功——单靠广播谁都能
发一份，这一点不能骗自己。

## 3. 配对（TOFU + 带外确认）

接收方显示二维码：

```
chuanshu://p?h=<host>&p=<port>&v=<protocol_version>&f=<fingerprint_hex>&c=<4位配对码>
```

`c` 与二维码同时刷新，TTL 60s，同时在界面上以数字显示（无摄像头时可手输）。

发送方对 `https://h:p` 发起 `POST /v1/pair`，TLS 校验只认 `f` 的 SPKI 指纹（自建 CA 不存在）：

```json
{"peer_id": "...", "name": "...", "code": "4173", "protocol_version": 1}
```

成功后接收方持久化该 fingerprint 为已配对，并返回随机会话 `token`（32 字节）。后续请求带
`X-Chuanshu-Auth: <token>`。**已配对指纹再次连入时跳过配对码**，但仍会弹一次"是否接收"
确认（见 §4）。

token 与信任是两件事：token 丢了（接收方重启）请求照样回 `403 NOT_PAIRED`，发送方此时用
已有的 key 做一次**只靠签名、不靠配对码**的重配对补回来，用户看不到这个过程。反过来，
一个从未配对的设备即使用同一个 key 签名，也拿不到 token。

安全边界：4 位码只有 10⁴ 空间，必须限流（同一来源 5 次失败锁 60s），且只在局域网内可达时
开放。二维码 + 同屏可见是这道码的实际强度来源，不是码本身。

## 4. 传输

一个 offer = 一次用户可见的传输请求，可含多文件与目录。

```
POST /v1/offer            发送 manifest，长轮询等待对方作答（默认 60s）
GET  /v1/offer/{id}/state 查询已落盘的分块，用于续传
PUT  /v1/offer/{id}/chunk/{file_id}/{index}   写一个分块，幂等
POST /v1/offer/{id}/finalize                 整文件校验
DELETE /v1/offer/{id}                        中止并清理
```

manifest：

```json
{
  "offer_id": "9f1c…",
  "protocol_version": 1,
  "total_size": 3145728,
  "files": [
    {"id": "a2b0…", "relpath": "相册/IMG_0001.jpg", "size": 3145728,
     "sha256": "…", "mtime": 1730000000}
  ]
}
```

响应：`200 {"accepted": true, "root": "相册/"}` 或 `403 {"code": "DECLINED"}`。

分块：`chunk_size` 固定 4 MiB，`index = offset // chunk_size`，末块可短。请求头
`X-Sha256` 为本块摘要，`X-File-Size` 为文件总长。接收方按 `index*chunk_size` 定位写偏移，
因此**分块可乱序、可重复、可断点补齐**。重复写入同一 index 且摘要一致 → `200`；摘要不一致
→ `422 CHUNK_DIGEST_MISMATCH`，发送方须重传该块（最多 3 次）。

`finalize` 返回 `200 {"verified": [{"id": "a2b0…", "ok": true}]}`；任一项 `ok: false` 时
发送方可只补传该文件的问题分块再 finalize 一次。

**续传状态**：接收方每落一块就重写 offer 目录下的 `.chuanshu.state.json`
（`state_flush_chunks = 1`，攒到收尾才写会让中途崩溃白传）。进程重启后靠它认领未完成的
offer，但**它只是提示**：可信结论只来自 `finalize` 的整文件摘要。状态文件损坏或缺失时，
接收方按"已落盘字节 / chunk_size"重算缺块，绝不允许因为状态丢了就谎报已完成。

**HTTP 层保活陷阱**：接收方在*读完请求体之前*回错误，残留的 body 会被对端当成下一个请求行
解析，连接从此错乱。所以错误响应必须先吞掉未读的 body（≤64 KiB），吞不动就置
`Connection: close`；发送方看到连接被关要重连重发一次，这属于实现细节而不是错误码。

## 5. 路径清洗（接收方的安全底线）

`relpath` 是发送方给的字符串，接收方**必须**假定它是敌对的：

- 分隔符统一为 `/`；拒绝 `\`、`:`、盘符、前导 `/`
- 拒绝任何 `..` 段、以 `.` 开头的保留段（`.git`、`.chuanshu`）
- Windows 额外拒绝保留名 `CON PRN AUX NUL COM1-9 LPT1-9` 与尾随 `.`/空格
- 单段名字超过 `max_name_bytes` → `400 PATH_REJECTED`
- 落盘位置固定为 `<接收目录>/<offer_id>/<清洗后 relpath>`，每个 offer 一个隔离目录，
  绝不直接写入用户选定的根目录；同名文件加 ` (2)` 后缀而非覆盖
- 符号链接、重解析点：写出前 `resolve()` 一次，若结果不在该 offer 目录内 → 拒绝

这条清单两端都得实现，PC 与手机互为接收方。

## 6. 保活与后台（各端各自的坑，不在协议里却决定成败）

- PC：常驻托盘即可，监听随进程存活。
- Android：接收中需前台服务（`dataTransfer` 类型）+ 13+ 通知权限，否则系统会掐连接。
- iOS：**App 退后台后监听 socket 不再接受新连接**。协议层无法绕过，UI 必须在"接收中"
  状态显示"请保持传书在前台"，而不是让用户以为在收。
- 鸿蒙 Next：同 iOS 的后台限制口径，按真机实测结论写进 UI 文案。

这是把"手机当接收方"的成本从协议层挤到 UI 层的地方——不做隐藏，直接显示。

## 7. 版本与兼容

`compatible_versions` 列出双方都能跑的版本集合，取交集非空才继续；否则
`400 UNSUPPORTED_PROTOCOL`。字段只增不改语义；要改语义就升 `protocol_version`。

## 8. 云中转分支

`cloud-relay` 分支不复制本契约，只替换寻址：peer 把七个端点当成对中继的调用，
`peer_id` 换成中继侧 session id，鉴权多一层账号。发现/配对语义保持一致，
因此 LAN 版和云版可以共用同一份 fixture 做回归。

## 9. 冻结标准

v1 视为冻结的条件：`py scripts/protocol_selftest.py` 用**同一份代码**跑通
配对 → 多文件含目录 → 中途断开 → 续传 → finalize 全绿，且错误码表两端各能渲染出
中英文文案。参考实现即验收工具，不接受只写在文档里的约定。

PC 端已于 2026-10-19 达成（51 条断言，含"杀掉接收进程再拉起"的真重启路径，以及 mDNS + UDP
两条通道各自真的发现了对端，见 `.probe/protocol_report.txt`）。手机端接入时必须用**同一份
`protocol.json` 和同一组 fixture**重跑一遍，只认它自己那端的绿色结果。
