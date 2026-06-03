require("dotenv").config({ quiet: true });

const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const path = require("path");
const { z } = require("zod");
const ipaddr = require("ipaddr.js");
const { analyzeIp } = require("./src/services/ipAnalyzer");

const app = express();
const port = Number(process.env.PORT || 4173);
const challengeStore = new Map();
const challengeTtlMs = 5 * 60 * 1000;

app.set("trust proxy", true);
app.use(cors());
app.use(express.json({ limit: "64kb" }));
app.use(express.static(path.join(__dirname, "public")));

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
