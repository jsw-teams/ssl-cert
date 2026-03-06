# refactor-certsync

一个从零重写的证书自动化项目：

- GitHub Actions 定时运行
- 使用 Cloudflare DNS-01 + ZeroSSL ACME + acme.sh 申请 `jsw.ac.cn` 和 `*.jsw.ac.cn`
- 申请成功后统一发布到：
  - Cloudflare Business Custom Certificates
  - 阿里云数字证书管理服务（原云盾证书）
  - 腾讯云 SSL 证书服务（原云盾证书）
- 通过缓存保留 `~/.acme.sh`，让续期逻辑真正基于“接近过期再更新”运行
- 通过 `.state/certsync-state.json` 记录上次已分发证书的到期时间，避免无变化时重复上传

## GitHub Secrets

### ZeroSSL

- `ZEROSSL_EAB_KID`
- `ZEROSSL_EAB_HMAC_KEY`

### Cloudflare DNS 验证

- `CF_DNS_API_TOKEN`

要求：

- 只保存 token 本体，不要加 `Bearer ` 前缀
- Token 需有 `Zone:Read` 与 `DNS:Edit`
- 资源范围至少包含 `jsw.ac.cn`

### Cloudflare Custom Certificates

- `CF_EDGE_API_TOKEN`
- `CF_EDGE_ZONE_ID`

### 阿里云

- `ALIBABA_CLOUD_ACCESS_KEY_ID`
- `ALIBABA_CLOUD_ACCESS_KEY_SECRET`

### 腾讯云

- `TENCENTCLOUD_SECRET_ID`
- `TENCENTCLOUD_SECRET_KEY`

## 配置

复制 `config.example.yml` 为 `config.yml`。

默认只做上传；如果你还要自动部署到阿里云或腾讯云具体实例，打开对应的 `deploy.enabled` 并填资源列表。

## 说明

- Cloudflare Custom Certificates 上传时，代码会自动从 `fullchain.pem` 中提取叶子证书，再上传给 Cloudflare。
- 阿里云部署采用显式资源列表模式，不做全账号盲扫。
- 腾讯云部署采用显式实例列表模式，按 `resource_type + region + instance_id_list` 下发。
