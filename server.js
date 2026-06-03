require("dotenv").config({ quiet: true });

const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { z } = require("zod");
const ipaddr = require("ipaddr.js");
const { analyzeIp } = require("./src/services/ipAnalyzer");

const app = express();
const port = Number(process.env.PORT || 4173);
const challengeStore = new Map();
const adminSessions = new Map();
const challengeTtlMs = 5 * 60 * 1000;
const adminSessionTtlMs = 12 * 60 * 60 * 1000;
const envPath = path.join(__dirname, ".env");
const dataDir = path.join(__dirname, "data");
const siteConfigPath = path.join(dataDir, "site-config.json");

const defaultSiteConfig = {
  pageTitle: "运营IP质检平台",
  eyebrow: "TikTok / ChatGPT / 主流平台访问参考",
  heroTitle: "运营IP质检平台",
  subhead: "判断 IP 是否住宅网络，辅助评估 TikTok 店铺、账号运营、广告投放和 AI 平台访问风险。",
  emptyTitle: "输入一个 IP，生成运营质量报告",
  emptyText: "第一版支持基础情报、住宅/VPS 倾向、DNS 黑名单、TikTok 与 ChatGPT 等平台访问参考、综合评分和运营建议。",
  loadingText: "正在收集 IP 情报、黑名单和平台访问参考...",
  reachabilityToggleLabel: "显示输入 IP 的平台访问参考",
  issueHelp: "根据实际 TikTok 运营中的限流、验证、封号情况总结：时区语言冲突建议调整设备设置，其它 IP 问题建议更换 IP，提示黑名单不建议使用。",
  importantHelp: "重要检测用于识别 VPN、机房代理、公开代理、黑名单、滥用来源、TOR、攻击记录和云服务节点。",
  platformTitle: "平台访问参考",
};

const configurableEnvKeys = [
  "ABUSEIPDB_API_KEY",
  "IPQUALITYSCORE_API_KEY",
];

app.set("trust proxy", true);
app.use(cors());
app.use(express.json({ limit: "64kb" }));
app.use(express.static(path.join(__dirname, "public")));

function ensureDataDir() {
  fs.mkdirSync(dataDir, { recursive: true });
}

function readSiteConfig() {
  ensureDataDir();

  try {
    const saved = JSON.parse(fs.readFileSync(siteConfigPath, "utf8"));
    return { ...defaultSiteConfig, ...saved };
  } catch (_error) {
    return { ...defaultSiteConfig };
  }
}

function writeSiteConfig(config) {
  ensureDataDir();
  const nextConfig = { ...defaultSiteConfig };

  for (const key of Object.keys(defaultSiteConfig)) {
    if (typeof config[key] === "string") {
      nextConfig[key] = config[key].trim();
    }
  }

  fs.writeFileSync(siteConfigPath, `${JSON.stringify(nextConfig, null, 2)}\n`, "utf8");
  return nextConfig;
}

function readEnvFile() {
  if (!fs.existsSync(envPath)) {
    return [];
  }

  return fs.readFileSync(envPath, "utf8").split(/\r?\n/);
}

function writeEnvValues(values) {
  const lines = readEnvFile();
  const seen = new Set();
  const nextLines = lines.map((line) => {
    const match = line.match(/^([A-Z0-9_]+)=/);

    if (!match || !Object.prototype.hasOwnProperty.call(values, match[1])) {
      return line;
    }

    seen.add(match[1]);
    return `${match[1]}=${values[match[1]]}`;
  });

  for (const [key, value] of Object.entries(values)) {
    if (!seen.has(key)) {
      nextLines.push(`${key}=${value}`);
    }
  }

  fs.writeFileSync(envPath, `${nextLines.filter((line, index, array) => line || index < array.length - 1).join("\n")}\n`, "utf8");

  for (const [key, value] of Object.entries(values)) {
    process.env[key] = value;
  }
}

function maskSecret(value) {
  if (!value) {
    return "";
  }

  if (value.length <= 10) {
    return "********";
  }

  return `${value.slice(0, 4)}…${value.slice(-4)}`;
}

function parseCookies(req) {
  return Object.fromEntries(String(req.headers.cookie || "")
    .split(";")
    .map((pair) => pair.trim())
    .filter(Boolean)
    .map((pair) => {
      const index = pair.indexOf("=");
      return index === -1
        ? [pair, ""]
        : [pair.slice(0, index), decodeURIComponent(pair.slice(index + 1))];
    }));
}

function cleanupAdminSessions() {
  const now = Date.now();

  for (const [token, session] of adminSessions.entries()) {
    if (session.expiresAt <= now) {
      adminSessions.delete(token);
    }
  }
}

function getAdminSession(req) {
  cleanupAdminSessions();
  const token = parseCookies(req).admin_session;

  if (!token) {
    return null;
  }

  const session = adminSessions.get(token);

  if (!session) {
    return null;
  }

  session.expiresAt = Date.now() + adminSessionTtlMs;
  return session;
}

function requireAdmin(req, res, next) {
  if (!getAdminSession(req)) {
    res.status(401).json({
      error: "ADMIN_AUTH_REQUIRED",
      message: "请先登录后台。",
    });
    return;
  }

  next();
}

async function testProvider(provider, ip) {
  if (provider === "abuseipdb") {
    if (!process.env.ABUSEIPDB_API_KEY) {
      return { ok: false, message: "未配置 ABUSEIPDB_API_KEY。" };
    }

    const params = new URLSearchParams({ ipAddress: ip, maxAgeInDays: "90" });
    const response = await fetch(`https://api.abuseipdb.com/api/v2/check?${params.toString()}`, {
      headers: {
        Key: process.env.ABUSEIPDB_API_KEY,
        Accept: "application/json",
      },
    });
    const data = await response.json().catch(() => ({}));

    return {
      ok: response.ok,
      status: response.status,
      message: response.ok ? "AbuseIPDB 连通正常。" : data.message || "AbuseIPDB 请求失败。",
      summary: response.ok && data.data
        ? `abuseConfidenceScore=${data.data.abuseConfidenceScore}, totalReports=${data.data.totalReports}`
        : JSON.stringify(data).slice(0, 240),
    };
  }

  if (provider === "ipqualityscore") {
    if (!process.env.IPQUALITYSCORE_API_KEY) {
      return { ok: false, message: "未配置 IPQUALITYSCORE_API_KEY。" };
    }

    const response = await fetch(`https://www.ipqualityscore.com/api/json/ip/${process.env.IPQUALITYSCORE_API_KEY}/${encodeURIComponent(ip)}?strictness=1&fast=true`, {
      headers: { Accept: "application/json" },
    });
    const data = await response.json().catch(() => ({}));
    const ok = response.ok && data.success !== false;

    return {
      ok,
      status: response.status,
      message: ok ? "IPQualityScore 连通正常。" : data.message || "IPQualityScore 请求失败。",
      summary: ok
        ? `fraud_score=${data.fraud_score}, proxy=${data.proxy}, vpn=${data.vpn}, tor=${data.tor}`
        : JSON.stringify(data).slice(0, 240),
    };
  }

  return { ok: false, message: "未知 API 服务。" };
}

const checkSchema = z.object({
  ip: z.string().trim().optional().default(""),
  runReachability: z.boolean().optional().default(true),
  deviceTimezone: z.string().trim().optional().default(""),
  deviceLanguages: z.array(z.string()).optional().default([]),
  challengeId: z.string().trim().min(1),
  challengeAnswer: z.string().trim().min(1),
});

function cleanupChallenges() {
  const now = Date.now();

  for (const [id, challenge] of challengeStore.entries()) {
    if (challenge.expiresAt <= now) {
      challengeStore.delete(id);
    }
  }
}

function createChallenge() {
  cleanupChallenges();

  const left = crypto.randomInt(3, 24);
  const right = crypto.randomInt(2, 18);
  const id = crypto.randomUUID();
  const answer = String(left + right);

  challengeStore.set(id, {
    answer,
    expiresAt: Date.now() + challengeTtlMs,
  });

  return {
    id,
    question: `${left} + ${right} = ?`,
    expiresInSeconds: Math.floor(challengeTtlMs / 1000),
  };
}

function verifyChallenge(id, answer) {
  cleanupChallenges();

  const challenge = challengeStore.get(id);

  if (!challenge) {
    return {
      ok: false,
      message: "验证已过期，请刷新验证码后重试。",
    };
  }

  challengeStore.delete(id);

  if (String(answer || "").trim() !== challenge.answer) {
    return {
      ok: false,
      message: "验证答案不正确，请重新验证。",
    };
  }

  return { ok: true };
}

function normalizeRequestIp(raw) {
  let ip = String(raw || "").trim();
  ip = ip.replace(/^::ffff:/i, "");

  if (ip.startsWith("[") && ip.includes("]")) {
    ip = ip.slice(1, ip.indexOf("]"));
  }

  return ip;
}

function getClientIp(req) {
  const forwarded = req.headers["x-forwarded-for"];
  const forwardedIp = Array.isArray(forwarded)
    ? forwarded[0]
    : String(forwarded || "").split(",")[0];
  const candidates = [
    forwardedIp,
    req.ip,
    req.socket.remoteAddress,
  ];

  for (const candidate of candidates) {
    const ip = normalizeRequestIp(candidate);

    if (ip && ipaddr.isValid(ip)) {
      return ip;
    }
  }

  return "";
}

app.get("/api/health", (_req, res) => {
  res.json({ ok: true, service: "ip-operability-checker" });
});

app.get("/api/site-config", (_req, res) => {
  res.json(readSiteConfig());
});

app.get("/api/challenge", (_req, res) => {
  res.json(createChallenge());
});

app.get("/api/client-ip", (req, res) => {
  const ip = getClientIp(req);
  let range = "";
  let isPublic = false;

  if (ip) {
    const parsed = ipaddr.parse(ip);
    range = parsed.range();
    isPublic = range === "unicast";
  }

  res.json({
    ip,
    range,
    isPublic,
  });
});

app.get("/api/admin/session", (req, res) => {
  res.json({
    authenticated: Boolean(getAdminSession(req)),
    enabled: Boolean(process.env.ADMIN_PASSWORD),
  });
});

app.post("/api/admin/login", (req, res) => {
  if (!process.env.ADMIN_PASSWORD) {
    res.status(503).json({
      error: "ADMIN_DISABLED",
      message: "后台未启用，请先在 .env 配置 ADMIN_PASSWORD。",
    });
    return;
  }

  const password = String(req.body && req.body.password || "");

  if (password !== process.env.ADMIN_PASSWORD) {
    res.status(401).json({
      error: "INVALID_PASSWORD",
      message: "后台密码不正确。",
    });
    return;
  }

  const token = crypto.randomBytes(32).toString("hex");
  adminSessions.set(token, {
    createdAt: Date.now(),
    expiresAt: Date.now() + adminSessionTtlMs,
  });

  res.cookie("admin_session", token, {
    httpOnly: true,
    sameSite: "lax",
    secure: Boolean(process.env.COOKIE_SECURE === "true"),
    maxAge: adminSessionTtlMs,
  });
  res.json({ ok: true });
});

app.post("/api/admin/logout", requireAdmin, (_req, res) => {
  res.clearCookie("admin_session");
  res.json({ ok: true });
});

app.get("/api/admin/config", requireAdmin, (_req, res) => {
  res.json(readSiteConfig());
});

app.post("/api/admin/config", requireAdmin, (req, res) => {
  res.json(writeSiteConfig(req.body || {}));
});

app.get("/api/admin/api-keys", requireAdmin, (_req, res) => {
  res.json({
    keys: Object.fromEntries(configurableEnvKeys.map((key) => [key, {
      configured: Boolean(process.env[key]),
      masked: maskSecret(process.env[key] || ""),
    }])),
  });
});

app.post("/api/admin/api-keys", requireAdmin, (req, res) => {
  const updates = {};
  const keys = req.body && req.body.keys ? req.body.keys : {};

  for (const key of configurableEnvKeys) {
    if (Object.prototype.hasOwnProperty.call(keys, key)) {
      updates[key] = String(keys[key] || "").trim();
    }
  }

  if (Object.keys(updates).length) {
    writeEnvValues(updates);
  }

  res.json({
    ok: true,
    keys: Object.fromEntries(configurableEnvKeys.map((key) => [key, {
      configured: Boolean(process.env[key]),
      masked: maskSecret(process.env[key] || ""),
    }])),
  });
});

app.post("/api/admin/test-api", requireAdmin, async (req, res) => {
  const provider = String(req.body && req.body.provider || "");
  const ip = normalizeRequestIp(req.body && req.body.ip || "8.8.8.8");

  if (!ipaddr.isValid(ip)) {
    res.status(400).json({
      ok: false,
      message: "请输入有效测试 IP。",
    });
    return;
  }

  try {
    res.json(await testProvider(provider, ip));
  } catch (error) {
    res.status(500).json({
      ok: false,
      message: error.message || "API 测试失败。",
    });
  }
});

app.get("/admin", (_req, res) => {
  res.sendFile(path.join(__dirname, "public", "admin.html"));
});

app.post("/api/check", async (req, res) => {
  const parsed = checkSchema.safeParse(req.body || {});

  if (!parsed.success) {
    res.status(400).json({
      error: "INVALID_PAYLOAD",
      message: "请求参数格式不正确。",
      details: parsed.error.flatten(),
    });
    return;
  }

  const challengeResult = verifyChallenge(parsed.data.challengeId, parsed.data.challengeAnswer);

  if (!challengeResult.ok) {
    res.status(403).json({
      error: "CHALLENGE_FAILED",
      message: challengeResult.message,
      challenge: createChallenge(),
    });
    return;
  }

  const fallbackIp = getClientIp(req);

  try {
    const result = await analyzeIp({
      ip: parsed.data.ip || fallbackIp,
      runReachability: parsed.data.runReachability,
      requestMeta: {
        userAgent: req.headers["user-agent"] || "",
        deviceTimezone: parsed.data.deviceTimezone,
        deviceLanguages: parsed.data.deviceLanguages,
      },
    });

    res.json(result);
  } catch (error) {
    const status = error.code === "INVALID_IP" ? 400 : 500;
    res.status(status).json({
      error: error.code || "CHECK_FAILED",
      message: error.message || "检测失败，请稍后重试。",
    });
  }
});

app.use((_req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(port, () => {
  console.log(`IP checker running at http://localhost:${port}`);
});
