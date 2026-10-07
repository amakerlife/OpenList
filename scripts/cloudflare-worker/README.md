# OpenList CF Worker：下载与光鸭上传

将 `worker.mjs` 的内容粘贴到 Cloudflare Workers 编辑器，使用 **Module Worker** 入口（导出带 `fetch` 方法的对象）。脚本以本目录中替换后的 CF Worker 为基础，保留顶部配置常量和下载请求的自定义 `Accept-Language`、`X-Forwarded-For`、`X-Real-IP` 头。

## 配置

可以继续修改脚本顶部的 `ADDRESS`、`TOKEN`、`WORKER_ADDRESS`，并填写新增的 `UPLOAD_TOKEN`。也可在 Cloudflare 控制台配置同名环境变量；**环境变量优先于顶部常量**，按请求读取。密钥推荐使用 Secret。

| 名称 | 类型 | 用途 |
| --- | --- | --- |
| `ADDRESS` | 文本 | OpenList 后端地址，例如 `https://openlist.example.com` |
| `TOKEN` | Secret | 上述 OpenList 实例的 API Token，用于下载验签及查询链接 |
| `WORKER_ADDRESS` | 文本，可选 | Worker 对外地址；默认读取顶部常量，该值为空时使用当前请求的 origin |
| `UPLOAD_TOKEN` | Secret | 单独生成的随机上传代理密钥，与光鸭存储的 `upload_proxy_token` 完全一致 |

可在本机运行 `node -e "console.log(require('node:crypto').randomBytes(32).toString('hex'))"` 生成上传密钥。不要复用网盘 AccessKey 或 OpenList API Token。

保存配置后部署 Worker。需要下载时填写 `ADDRESS` 和 `TOKEN`，并确认 `WORKER_ADDRESS` 是当前 Worker 地址；需要上传时填写 `UPLOAD_TOKEN`。顶部的 `ADDRESS`、`TOKEN` 占位值需要替换，或用环境变量覆盖。上传入口为保留路径 `/__openlist_upload`，只接受带签名的 OSS PUT、POST、DELETE 请求。

## OpenList 配置

使用包含本次修改的 OpenList，在**目标光鸭存储**中填写：

- `upload_proxy_url`：Worker 根地址，如 `https://your-worker.example.com`，不带路径或查询参数。
- `upload_proxy_token`：与 Worker 的 `UPLOAD_TOKEN` 一致。

留空上传代理地址时按原方式上传。源网盘的下载代理仍通过其“下载代理 URL”配置，下载签名需开启。

光鸭的账号 API、获取上传凭据及秒传仍由 OpenList 处理；OSS 初始化、上传分片、合并及零字节文件请求由 Worker 转发。分片正文直接流式传输，大小仍由光鸭驱动决定（1～8 MiB），Worker 不缓存整个文件，也不计算文件哈希。

上传请求保留原始 OSS URL、签名头和长度，代理鉴权使用独立的五分钟 HMAC 签名。CF 的 `FixedLengthStream` 用于保留 OSS 要求的请求长度，不缓存整个分片。上传响应保留状态码、`ETag`、校验头及正文，供 OSS SDK 校验和合并。上传不会跟随重定向，Worker 错误使用实际 HTTP 错误状态码。

下载的自定义地区/IP 请求头只应用于下载流程。下载验签失败返回 HTTP 401，OpenList 链接 API 错误也使用对应 HTTP 错误状态，避免把错误 JSON 当作文件传输。

Cloudflare 必须能够访问 `ADDRESS` 和 OSS 端点。服务器与 Worker 的时钟应准确。上传目标不设域名白名单，需使用 HTTPS 的 443 端口，并通过上传密钥验签。

## 本地检查

```sh
node --test scripts/cloudflare-worker/worker.test.mjs
go test ./drivers/guangyapan
```

部署后可先复制一个无法秒传的小文件，确认任务成功、下载后内容一致，再测试较大文件。仅秒传成功无法验证上传代理链路。
