# 运营IP质检平台

用于判断 IP 是否住宅网络，辅助评估 TikTok 店铺、账号运营、广告投放和 AI 平台访问风险。

仓库地址：

```text
https://github.com/359073395/operation-ip-quality-platform
```

## 功能

- 打开网站自动填入访问者 IP 地址
- IP 基础情报：国家/地区、城市、时区、经纬度、ASN、运营商
- 住宅属性判断：住宅、机房/VPS、未知需复核
- 主要信息：网络提供商、网络类型、归属商、归属商类型、使用者特征
- 重要检测：匿名 VPN、机房代理、公共代理、可疑代理、黑名单、滥用节点、TOR、攻击记录、云服务
- 免费第三方风控库：ipapi.is、proxycheck.io
- 地区时区：广播地区、注册地区、城市、经纬度、本地时区、主要语言
- 平台访问参考：TikTok、ChatGPT、OpenAI API、GitHub、Google、YouTube、Reddit、Netflix
- 平台卡片显示用户输入 IP 的归属地，例如 `归属地：印度尼西亚 / ID`
- 检测前验证码：防止频繁恶意提交

## 本地运行

```bash
npm install
npm start
```

打开：

```text
http://localhost:4173
```

后台管理：

```text
http://localhost:4173/admin
```

启用后台需要在 `.env` 中配置：

```bash
ADMIN_PASSWORD=你的后台密码
```

后台可用于：

- 修改首页标题、副标题、说明文字
- 修改 AbuseIPDB / IPQualityScore API Key
- 测试 API Key 是否连通

## VPS 一键部署

适用于 Ubuntu / Debian VPS。

在任意 VPS 上执行：

```bash
curl -fsSL https://raw.githubusercontent.com/359073395/operation-ip-quality-platform/main/scripts/deploy-vps.sh | sudo bash -s -- "https://github.com/359073395/operation-ip-quality-platform.git"
```

部署完成后访问：

```text
http://你的VPS公网IP:4173
```

指定端口部署：

```bash
curl -fsSL https://raw.githubusercontent.com/359073395/operation-ip-quality-platform/main/scripts/deploy-vps.sh | sudo PORT=8080 bash -s -- "https://github.com/359073395/operation-ip-quality-platform.git"
```

## 更新 VPS 上的项目

进入项目目录后执行：

```bash
sudo bash scripts/update-vps.sh
```

默认目录：

```text
/opt/operation-ip-quality-platform
```

## 平台访问参考说明

基础 IP 情报是针对输入 IP 的判断。

平台访问参考显示的是用户输入 IP 的归属国家/地区，不使用当前部署服务器/VPS 的出口 IP。

真实平台连通性必须让流量从该 IP 本身发出。服务器不能仅凭一个远程 IP 地址代替它访问 TikTok、ChatGPT 等网站。如果要做真实连通性测试，需要把项目部署到该 IP 所在 VPS，或让检测请求通过该 IP/代理出口。

## 免费风控库说明

项目当前接入了免费的第三方 IP 风控来源：

- `ipapi.is`：辅助判断 datacenter、proxy、vpn、tor、abuser、crawler 等信号
- `proxycheck.io`：辅助判断 proxy、vpn、hosting、anonymous、compromised、scraper、tor、risk/confidence 等信号
- `AbuseIPDB`：配置 `ABUSEIPDB_API_KEY` 后，辅助判断 abuse confidence score、报告次数、滥用历史等信号
- `IPQualityScore`：配置 `IPQUALITYSCORE_API_KEY` 后，辅助判断 fraud score、proxy、VPN、TOR、recent abuse、bot、connection type 等信号

这些来源不是 TikTok 官方数据库，只能作为运营风险辅助判断。

如果 IPQualityScore 返回 `insufficient credits`，说明 key 已配置但账户暂无可用查询额度，需要在 IPQualityScore 后台确认免费额度或充值。

在 VPS 上配置 AbuseIPDB：

```bash
cd /opt/operation-ip-quality-platform
sudo nano .env
```

加入：

```bash
ABUSEIPDB_API_KEY=你的AbuseIPDBKey
IPQUALITYSCORE_API_KEY=你的IPQualityScoreKey
```

然后重启：

```bash
pm2 restart operation-ip-quality-platform --update-env
```

## 常用命令

```bash
npm run check
pm2 status
pm2 logs operation-ip-quality-platform
pm2 restart operation-ip-quality-platform
```

## 下一步商业版方向

- 批量检测、CSV 导入导出、历史报告
- API Key、积分扣费、套餐充值
- 接入 MaxMind、IP2Location、IPQualityScore、Scamalytics 等付费 IP 情报库
- 多地区 VPS 探针节点
- 后台管理、用户系统和检测额度限制
