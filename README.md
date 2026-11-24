# Sallyport

少数人用的 TCP 后备通道。对外是一个挂在 Cloudflare 后面的私人网盘站，只有用正确方式访问的客户端才能得到代理；其他任何人——包括主动探测者——看到的都只是一个普通网盘。

UDP 不在本项目范围内（UDP 用 Hysteria2 等方案）。这里只追求一件事：**在主通道不可用时，仍然稳定可用。**

```
你的设备 ── TLS (Chrome 指纹) ──▶ Cloudflare ── TLS ──▶ 服务器
  本地 SOCKS5/HTTP                 (橙色云朵)              │
  127.0.0.1:1080                                           ├─ 暗门路径 + 有效口令 + WebSocket → 隧道 → 目标网站
                                                           └─ 其他一切                        → 真网盘 (File Browser)
```

目录：

- [设计思路](#设计思路)
- [工作原理](#工作原理)
- [协议细节](#协议细节)
- [服务端部署](#服务端部署)
- [客户端使用](#客户端使用)
- [配置参考](#配置参考)
- [日常运维](#日常运维)
- [排错](#排错)
- [安全性与局限](#安全性与局限)
- [验证记录](#验证记录)
- [代码结构与构建](#代码结构与构建)

## 设计思路

1. **伪装优先，加密其次。** 防火墙不需要知道你传了什么，它只要认出"这是代理"就可以封。所以这里的核心不是更强的加密，而是让流量从外面看起来就是一个真实网站在被正常使用。
2. **只走 Cloudflare，不直连。** 客户端只和 Cloudflare 通信，服务器防火墙只放行 Cloudflare 的 IP 段。服务器 IP 被封不影响使用；直接扫描服务器 IP 什么也扫不到，也就无从把 IP 和域名对应起来。被封了只需换 IP，域名不变。
3. **背后是真网站，不是假页面。** 普通访问交给真实运行的 File Browser 处理，登录、列目录、下载都是真的，任何探测拿到的都是真网盘的真实响应。
4. **不模仿任何现成的代理协议。** 没有固定的握手字节、没有可识别的首包长度，也不复用 VMess/Trojan/VLESS 等协议的帧格式。TLS 和 WebSocket 是标准的，因为大量真实网站都在用。
5. **稳定优先于速度。** 连接池、自动重连、退避排队、多 IP 选优，宁可慢一点也不要断。
6. **小而独立。** 一个二进制，同时是服务端和客户端，不依赖 sing-box、mihomo 或任何面板。

## 工作原理

### 访问一次网页时发生了什么

1. 浏览器把请求交给本地 `127.0.0.1:1080`（SOCKS5 或 HTTP 代理）。
2. 客户端从连接池里取一条已经建好的隧道。没有就新建一条：
   1. 用 Chrome 的 TLS 指纹连接 Cloudflare。
   2. 如果是刚启动或者已经冷了 30 分钟，先像网盘网页那样**打开首页、登录、列出文件**（"前奏"）。
   3. 向 `wss://域名/api/sync/<口令>` 发起 WebSocket 升级。
3. Cloudflare 把请求转给服务器。服务器检查三件事：路径是否以暗门前缀开头、是否是 WebSocket 升级、口令是否有效。三者都满足才开隧道，**任何一项不满足都原样交给网盘处理**。
4. 隧道里每个网页连接是一个独立的流（多路复用），流的开头写目标地址，之后双向转发。

### 看起来像什么

| 外部观察到的 | 实际是 |
|---|---|
| 打开一个网盘站，登录，列出文件 | 客户端的前奏 |
| 请求一个 56 位十六进制命名的文件（像 SHA-224），升级成 WebSocket | 开隧道 |
| WebSocket 上传来传去大小不一的二进制块 | 加密后的代理流量，像在同步加密备份 |
| 偶尔一个心跳，间隔不固定 | 保活 |
| 连接用一阵就换一条 | 隧道到时轮换 |

### 暗门口令

口令由用户密钥和当前时间算出，**每两分钟换一次，并且只能用一次**：

- 服务器接受当前、前一个、后一个时间窗口（容忍 ±2 分钟左右的时钟误差）；
- 每个口令带一个随机数，服务器记住用过的随机数，重放会被拒绝（然后被当作普通访问交给网盘）；
- 口令里不含用户名，服务器用每个用户的密钥逐一验证，找到是谁。

所以抓到一个口令没有用：拿去重放只会看到网盘。

## 协议细节

以下是实现所用的格式，供审计或重新实现参考。

### 口令 (door token)

```
nonce  = 12 字节随机数
window = floor(unix 时间 / 120)，8 字节大端
mac    = HMAC-SHA256(key, "sallyport door v1" || window || nonce)[:16]
token  = hex(nonce || mac)            # 56 个十六进制字符
URL    = wss://<server>:<port><door><token>      # door 默认 /api/sync/
```

服务器对 `window-1, window, window+1` 都尝试验证；用过的 nonce 保留 4 个窗口后清除。

### 会话密钥

```
c2s_key = HKDF-SHA256(secret=key, salt=nonce, info="sallyport c2s")   # 32 字节
s2c_key = HKDF-SHA256(secret=key, salt=nonce, info="sallyport s2c")
```

每条隧道、每个方向一把独立的 AES-256-GCM 密钥。nonce 为 96 位，后 64 位是该方向的递增计数器，不会复用。

### 记录 (record)

每个 WebSocket 二进制消息是一条加密记录：

```
明文 = len (2 字节大端) || data (len 字节) || padding (随机字节)
消息 = AES-256-GCM-Seal(明文)
```

- `data` 最长 32 KB，更长的写入会拆成多条；
- 明文小于 1400 字节的记录会补随机长度的填充，填充后不超过 1400 字节，让小包长度不可预测；大块数据不填充，避免浪费；
- 解密失败、长度非法都会直接断开。

Cloudflare 在中间会终止 TLS，所以这一层加密保证 Cloudflare 也看不到内容。

### 多路复用与流

- 隧道上跑 smux v2（关闭 smux 自带的心跳，帧最大 16 KB，单流缓冲 4 MB，会话缓冲 16 MB）；
- 每个流的开头是目标地址，格式类似 SOCKS5：`atyp(1) || 地址 || 端口(2)`，`atyp` 为 1（IPv4）、3（域名，前面加 1 字节长度）、4（IPv6）；
- 客户端会把目标地址和最初的数据（例如 TLS ClientHello）攒在一起发出（最多等 25 ms），省掉一个往返；
- 服务器读地址最多等 30 秒，连接目标最多 10 秒；一端关闭写方向后，另一方向最多再等 1 分钟。

### 客户端连接池

| 行为 | 取值 |
|---|---|
| 每条隧道最多承载的流 | 24 |
| 同时打开的隧道 | 默认最多 2 条（`tunnels`） |
| 多余隧道空闲多久关闭 | 90 秒 |
| 最后一条隧道空闲保留 | 10 分钟 |
| 隧道寿命 | 随机 20–45 分钟，到期后不再接新流，旧流走完再关 |
| 心跳间隔 | 随机 20–64 秒（Cloudflare 免费版 100 秒无数据会断开 WebSocket） |
| 连接失败退避 | 1 秒起，翻倍到 30 秒；退避不超过 10 秒时新请求排队等待而不是报错 |
| 前奏 | 启动后第一次、或冷了 30 分钟后执行一次，失败不影响开隧道 |

### TLS 指纹

客户端用 uTLS 模拟 Chrome（`HelloChrome_Auto`）。真 Chrome 开 WebSocket 时 ALPN 只带 `http/1.1`，所以开隧道时也只带 `http/1.1`；前奏是普通页面请求，ALPN 带 `h2, http/1.1`，走 HTTP/2。请求头、顺序与 Chrome 一致。

### Cloudflare IP 选择

`endpoints` 里填了 IP 时，客户端测量到每个 IP 的 TCP 连接时间，优先用最快的；连接失败的 IP 冷却 10 秒起、翻倍到最多 5 分 20 秒；每 30 分钟重新测一次。不填则正常解析域名。

## 服务端部署

### 需要准备

- **一个新域名**，托管在 Cloudflare。不要和面板、机场、其他节点用同一个主域名，否则一个被盯上会牵连另一个。
- **一台 VPS**，Linux x86_64 或 arm64，512 MB 内存足够。可以和其他服务共用，只要端口不冲突。
- 本仓库编译出的 `sallyport`（见[构建](#代码结构与构建)）。

### 1. Cloudflare

1. DNS 添加 A 记录（例如 `drive`）指向 VPS，**开启橙色云朵**。不要另建指向真实 IP 的灰云记录。
2. 选端口：Cloudflare 只转发这些 HTTPS 端口：`443, 2053, 2083, 2087, 2096, 8443`。443 被占用时用其他任意一个，客户端 `port` 填同一个。
3. 证书与 SSL 模式（**SSL/TLS → 概述**）：
   - 推荐 **完全（严格）**：在 **SSL/TLS → 源服务器** 生成一张源站证书（有效期可选 15 年），保存为 `/etc/sallyport/origin.pem` 和 `origin.key`。
   - **完全**：可以用自签证书，Cloudflare 不校验。
   - **灵活**：Cloudflare 到源站本应是明文。实测发现，用 443 以外的端口时，Cloudflare 仍然用 TLS 连源站，可以正常工作；但不建议依赖这一点。
   - 如果同一个主域名下还有其他站点、不能改整个域名的模式，可以在 **规则 → 配置规则** 里只给这个主机名单独设 SSL 模式。
4. 不需要开任何额外功能。WebSocket 默认就是开启的。

### 2. 真网盘 (File Browser)

```sh
bash deploy/install-filebrowser.sh 18080 alice bob
```

这个脚本会：

- 从 GitHub 下载 File Browser v2.63.23，安装到 `/usr/local/bin/filebrowser`；
- 只监听 `127.0.0.1:18080`，关闭注册；
- 网盘根目录 `/srv/drive`，建好"文档、照片、备份"几个目录和几个"加密备份"文件；
- 创建管理员账号，并给每个隧道用户（这里是 alice、bob）各建一个普通账号，每人只能看到自己的文件夹，里面也放好备份文件；
- 账号密码写到 `/root/filebrowser-accounts.txt`（权限 600）；
- 注册并启动 `filebrowser.service`。

可以重复执行来追加用户，已有账号不会变。建议之后再往网盘里放一些真实文件，让它更像在用。

### 3. Sallyport

```sh
useradd -r -s /usr/sbin/nologin sallyport
install -m 755 sallyport /usr/local/bin/
mkdir -p /etc/sallyport

# 每个用户生成一把密钥
sallyport genkey
```

写 `/etc/sallyport/server.json`（参考 `deploy/server.example.json`，字段说明见[配置参考](#服务端-serverjson)）：

```json
{
  "listen": ":8443",
  "tls_cert": "/etc/sallyport/origin.pem",
  "tls_key": "/etc/sallyport/origin.key",
  "decoy": "http://127.0.0.1:18080",
  "users": [
    { "name": "alice", "key": "<genkey 的输出>" },
    { "name": "bob",   "key": "<genkey 的输出>" }
  ]
}
```

```sh
chown -R sallyport:sallyport /etc/sallyport
chmod 700 /etc/sallyport && chmod 600 /etc/sallyport/*
cp deploy/sallyport.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now sallyport
journalctl -u sallyport -f      # 应看到 serving on :8443 (tls=true, proxy=true, users=2)
```

现在用浏览器打开 `https://drive.你的域名:8443/`，应该看到网盘登录页。

### 4. 防火墙：只放行 Cloudflare

```sh
sh deploy/cloudflare-only.sh 8443
```

它会从 Cloudflare 官网拉取 IP 段，建一个 `SALLYPORT_CF` 链：这个端口只接受 Cloudflare 来的连接，其他来源直接丢弃（不回应）。只影响这一个端口。

iptables 规则重启后会丢失。可以装 `iptables-persistent` 保存，或者在 cron 里定期执行（顺便更新 IP 段）：

```sh
echo '@reboot root sleep 20 && sh /usr/local/sbin/cloudflare-only.sh 8443
0 4 * * 1 root sh /usr/local/sbin/cloudflare-only.sh 8443' > /etc/cron.d/sallyport-cf
cp deploy/cloudflare-only.sh /usr/local/sbin/
```

验证：从其他机器直连 `https://服务器IP:8443` 应该超时无响应；通过域名访问应该正常看到网盘。

## 客户端使用

客户端是命令行程序，在本地开一个同时支持 SOCKS5 和 HTTP 的代理端口。

`client.json`（参考 `deploy/client.example.json`）：

```json
{
  "listen": "127.0.0.1:1080",
  "server": "drive.你的域名",
  "port": 8443,
  "key": "<与服务端该用户相同的 key>",
  "drive_user": "alice",
  "drive_pass": "<该用户的网盘密码>"
}
```

运行：

```sh
sallyport client -c client.json        # Linux / macOS
sallyport.exe client -c client.json    # Windows，可写成一个 .bat 双击运行
```

看到 `tunnel up (1 open)` 就是连通了。然后任选一种用法：

- **浏览器 / 系统代理**：HTTP 代理 `127.0.0.1:1080`。Windows：设置 → 网络和 Internet → 代理 → 手动设置代理。
- **作为其他代理软件的上游**：在 Clash / mihomo / sing-box 里加一个 SOCKS5 出站指向 `127.0.0.1:1080`。
- **命令行**：`curl -x socks5h://127.0.0.1:1080 https://example.com`。

注意：

- **设备时间必须准确**，误差 2 分钟以内，否则口令会被当成过期。Windows 打开"自动设置时间"即可。
- `drive_user` / `drive_pass` 可以不填（不填就不做前奏），但填上更像真实用户。
- 只支持 TCP。SOCKS5 的 UDP ASSOCIATE 不支持。
- `client.json` 里有密钥，不要外传；每个人用自己的密钥，方便单独停用。

### 优选 IP

在国内，不同的 Cloudflare IP 速度差别很大。可以用测速工具找几个快的 IP 填进 `endpoints`：

```json
"endpoints": ["104.16.1.2", "172.67.3.4", "162.159.5.6:2053"]
```

不带端口时用 `port`。客户端会自动测速、选最快的、跳过失败的。

## 配置参考

### 服务端 `server.json`

| 字段 | 默认 | 说明 |
|---|---|---|
| `listen` | `:443` | 监听地址，端口需是 Cloudflare 支持的 HTTPS 端口 |
| `tls_cert` / `tls_key` | 空 | 证书和私钥路径。两者都留空则监听明文 HTTP（仅当前面另有 TLS 终止时） |
| `decoy` | 必填 | 真网盘地址，例如 `http://127.0.0.1:18080` |
| `door` | `/api/sync/` | 暗门路径前缀，必须以 `/` 开头和结尾，客户端要一致 |
| `proxy` | `true` | 关掉后站点只剩网盘，所有隧道请求都交给网盘 |
| `users` | 空 | `[{ "name": "...", "key": "..." }]`，名字唯一，key 来自 `sallyport genkey` |
| `allow_private` | `false` | 允许隧道访问内网、回环、CGNAT 等地址。默认拒绝，防止用户摸到网盘后台或云厂商元数据接口 |
| `log_targets` | `false` | 记录每个访问的目标地址。默认不记 |

### 客户端 `client.json`

| 字段 | 默认 | 说明 |
|---|---|---|
| `listen` | `127.0.0.1:1080` | 本地代理地址（SOCKS5 + HTTP 同一端口） |
| `server` | 必填 | 网盘域名 |
| `port` | `443` | 与服务端 `listen` 端口一致 |
| `door` | `/api/sync/` | 与服务端一致 |
| `key` | 必填 | 该用户的密钥 |
| `endpoints` | 空 | Cloudflare IP 列表，见[优选 IP](#优选-ip) |
| `tunnels` | `2` | 最多同时打开的隧道数 |
| `drive_user` / `drive_pass` | 空 | 网盘账号，用于前奏登录 |
| `ca_file` / `insecure` | 空 / `false` | 仅用于测试私有证书，正常使用不要设 |

### 命令

```
sallyport server -c server.json    运行服务端（收到 SIGHUP 时重新加载配置）
sallyport client -c client.json    运行客户端
sallyport genkey                   生成一把新密钥
sallyport version                  显示版本
```

## 日常运维

| 要做的事 | 操作 |
|---|---|
| 加用户 | `sallyport genkey` 生成 key → 写进 `users` → `bash install-filebrowser.sh 18080 新用户名` 建网盘账号 → `systemctl reload sallyport` |
| 停用某人 | 从 `users` 删掉 → `systemctl reload sallyport`，此人现有隧道会立刻断开，其他人不受影响 |
| 风声紧，暂停代理 | `"proxy": false` → `systemctl reload sallyport`，站点只剩网盘；改回 `true` 再 reload 即恢复 |
| 换证书 | 覆盖证书文件 → `systemctl reload sallyport` |
| 服务器 IP 被封 | 换一台 VPS 照做一遍，Cloudflare 里把 A 记录改成新 IP。客户端什么都不用改 |
| 看日志 | `journalctl -u sallyport -f`：隧道开关、用户、来源 IP（取自 `CF-Connecting-IP`）、流数、上下行流量 |

reload 失败（例如 JSON 写错）会在日志里报错并继续用旧配置，不会中断服务。`listen`、`decoy` 和 `door` 不能通过 reload 修改，需要 `systemctl restart sallyport`。

**保持网站活着。** 一个从不更新、只有一个人访问的网站本身就是一种特征。偶尔往网盘里传几个文件、改改目录，比任何技术手段都管用。

## 排错

客户端日志里的提示：

| 提示 | 原因 | 处理 |
|---|---|---|
| `door refused (HTTP 4xx): check key, door path and clock` | 口令没通过，服务器把请求当成普通访问 | 检查 key 是否与服务端一致、`door` 是否一致、设备时间是否准确 |
| `site unavailable (HTTP 5xx)` | Cloudflare 连不上源站，或网盘没运行 | 检查 `systemctl status sallyport filebrowser`、防火墙、Cloudflare SSL 模式 |
| `tunnel: ... timeout` / 连接被重置 | 本地网络到 Cloudflare 不通 | 换网络，或在 `endpoints` 填其他 Cloudflare IP |
| `tunnel unavailable, retrying shortly` | 正在退避重连 | 一般会自动恢复；持续出现就看上一条错误 |

服务端：

- 网盘页面显示 502：`decoy` 地址不对，或 File Browser 没运行。
- `x is not a public address`：目标是内网地址，被 `allow_private=false` 拒绝。
- 用浏览器打开 `https://域名:端口/` 能看到网盘，说明 Cloudflare、证书、网盘都正常，剩下的问题只在口令（key / door / 时间）。

## 安全性与局限

能做到的：

- 服务器 IP 不暴露给使用者所在的网络；直接扫描服务器 IP 无响应。
- 主动探测、乱发数据、重放口令，得到的都是真网盘的真实响应。
- 流量内容在 Cloudflare 那里也是加密的；单条隧道的密钥是一次性派生的。
- 每个用户独立密钥，可以单独停用；一键关闭代理只留网盘。

做不到或需要注意的：

- **Cloudflare 能看到元数据**：谁在什么时间连了你的域名、传了多少流量。内容看不到。
- **流量规模本身是特征**：一个"个人网盘"长期大流量、长连接，统计上和普通网盘不同。本项目用多隧道轮换、随机心跳、小包填充来淡化，但不能消除。所以它适合少数人做后备，不适合大量用户长期当主力。
- **代码公开时**，别人可以照着代码写识别规则（例如暗门路径的形状）。可以改 `door` 前缀来规避这一类规则；长期使用建议把仓库设为私有。
- **只有 TCP**，没有 UDP。
- **依赖 Cloudflare**：如果整个 Cloudflare 在某地不可用，这条通道也不可用。
- **设备时间要准**。

## 验证记录

2026-11-23 在测试环境（美国 VPS，File Browser v2.63.23，Cloudflare 免费版，端口 8443）验证过：

| 项目 | 结果 |
|---|---|
| 经 Cloudflare 打开站点 | 200，File Browser 登录页 |
| 网盘错误密码登录 | 403，和正常网盘一致 |
| 伪造口令访问暗门路径 | 返回网盘自己的页面，不暴露隧道 |
| 客户端前奏 | 网盘对 `GET /`、`POST /api/login`、`GET /api/resources/` 均返回 200（源站抓包确认） |
| 建隧道 | 启动后约 2 秒建好，出口 IP 为 VPS |
| 网页请求 | 每次约 0.16–0.17 秒（generate_204） |
| 下载速度 | 约 8–19 MB/s（从另一台美国服务器测，受两端带宽限制） |
| 防火墙 | 直连源站 IP 无响应；经 Cloudflare 正常 |
| Cloudflare 灵活模式 | 8443 端口下 Cloudflare 仍以 TLS 连源站，可用 |

本地（单机）测试另外验证了：重放口令被拒、`proxy: false` 热切换、删除用户后其隧道立即断开、服务端重启后客户端自动恢复、连接池的扩缩与轮换。单元测试覆盖口令、记录加解密、服务端分流、客户端 ALPN 和连接池，`go test -race ./...` 全部通过。

尚未验证：在中国大陆网络下长时间运行的稳定性和速度。

## 代码结构与构建

| 路径 | 内容 |
|---|---|
| `cmd/sallyport` | 命令行入口；Unix 下 SIGHUP 重载 |
| `internal/door` | 暗门口令：生成、验证、时间窗、防重放 |
| `internal/wire` | WebSocket 上的加密记录：AES-GCM、计数器 nonce、小包填充、心跳 |
| `internal/proto` | 流头（目标地址）、smux 参数、双向转发 |
| `internal/server` | 网站入口：分流到网盘或隧道、用户、热重载、拒绝内网目标 |
| `internal/client` | 本地 SOCKS5/HTTP 入口、Chrome TLS、连接池、Cloudflare IP 选择、前奏 |
| `deploy/` | systemd 服务、Cloudflare 防火墙脚本、File Browser 安装脚本、示例配置 |

依赖：`refraction-networking/utls`、`gorilla/websocket`、`xtaci/smux`、`golang.org/x/net`、`golang.org/x/crypto`。

需要 Go 1.26 或更新版本：

```sh
go build -trimpath -ldflags "-s -w" -o sallyport ./cmd/sallyport
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o sallyport.exe ./cmd/sallyport
GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o sallyport-arm64 ./cmd/sallyport
go test ./...
```
