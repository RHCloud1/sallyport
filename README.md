# Sallyport

少数人用的 TCP 后备通道。对外是一个挂在 Cloudflare 后面的私人网盘站，只有用正确方式访问的客户端才能得到代理。

```
你的设备 ── TLS(Chrome 指纹) ──▶ Cloudflare ── TLS ──▶ 服务器:443
                                                      ├─ 暗门 + 有效口令 → 隧道
                                                      └─ 其他一切        → 真网盘 (File Browser)
```

- **不直连**：客户端只连 Cloudflare，服务器防火墙只放行 Cloudflare 的 IP 段。服务器 IP 被封不影响使用，直接扫 IP 也什么都扫不到。
- **普通人看到的是网盘**：认证失败、乱发数据、重放口令，都会原样交给后面的真网盘处理。
- **暗门**：隧道是一次 WebSocket 请求 `/api/sync/<56位十六进制>`，看起来像在取一个按 SHA-224 命名的文件。这串字符由用户密钥和当前时间算出，两分钟换一次，并且只能用一次。
- **像一个真应用在工作**：
  - 首次连接前，客户端会像网盘网页那样先打开首页、登录、列出文件；
  - 隧道内容加密后像在同步加密备份；
  - 空闲时只按不规则间隔发心跳，并且会自动关闭；
  - 连接到时间就轮换。
- **稳定优先**：
  - 多条隧道复用，单条断开时自动补上；
  - 有多个 Cloudflare IP 时自动选最快的，失败的会被跳过；
  - 断线自动重连，退避期间请求只是排队等待，不会直接报错；
  - 服务端一条命令即可关掉代理，只剩网盘。

## 组成

| 路径 | 内容 |
|---|---|
| `internal/door` | 暗门口令：HMAC、时间窗、防重放 |
| `internal/wire` | WebSocket 上的加密分包：AES-GCM、按方向计数的 nonce、小包随机填充 |
| `internal/proto` | 流头（目标地址）、smux 设置、双向转发 |
| `internal/server` | 网站入口：分流到真网盘或隧道、用户、热重载、拒绝内网目标 |
| `internal/client` | 本地 SOCKS5/HTTP 入口、Chrome TLS、连接池、Cloudflare IP 选择、登录前奏 |

## 服务端部署

需要准备：一个新域名（不要和面板、机场用同一个），托管在 Cloudflare；一台 VPS。

1. **Cloudflare**
   - 添加 A 记录指向 VPS，**开启橙色云朵**；不要另建指向真实 IP 的灰云子域名。
   - SSL/TLS 模式设为 **Full (strict)**。
   - 在 "SSL/TLS → Origin Server" 生成一张源站证书，保存为 `/etc/sallyport/origin.pem` 和 `origin.key`。
2. **真网盘**：安装 [File Browser](https://github.com/filebrowser/filebrowser)。
   - 只监听 `127.0.0.1:8080`；
   - 设一个强管理员密码，关闭注册；
   - 放一些真实文件进去；
   - 每个用户再建一个普通账号，填到客户端的 `drive_user` / `drive_pass`。
3. **Sallyport**
   ```sh
   useradd -r -s /usr/sbin/nologin sallyport
   install -m 755 sallyport /usr/local/bin/
   mkdir -p /etc/sallyport   # server.json、证书放这里，属主 sallyport，权限 600
   sallyport genkey          # 每个用户一个 key
   cp deploy/sallyport.service /etc/systemd/system/
   systemctl enable --now sallyport
   ```
4. **防火墙**：执行 `sh deploy/cloudflare-only.sh 443`，可放进 cron 定期执行。

日常操作：

- 加减用户、开关代理：改 `server.json` 后执行 `systemctl reload sallyport`，不会断开其他用户。
- 风声紧时：把 `"proxy": false` 后 reload，站点就只剩网盘。

## 客户端

```sh
sallyport client -c client.json
```

- 本地 `127.0.0.1:1080` 同时支持 SOCKS5 和 HTTP 代理。
- 可以直接设为系统代理，也可以给其他代理软件当上游。
- `endpoints` 可以填几个 Cloudflare IP（即"优选 IP"），客户端会选最快的；留空则正常解析域名。
- 设备时间必须准确（误差在 2 分钟以内），否则口令会被当成过期。

## 构建

```sh
go build -trimpath -ldflags "-s -w" -o sallyport ./cmd/sallyport
GOOS=windows go build -trimpath -ldflags "-s -w" -o sallyport.exe ./cmd/sallyport
go test ./...
```
