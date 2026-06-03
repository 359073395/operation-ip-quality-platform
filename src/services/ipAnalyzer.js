const dns = require("dns/promises");
const ipaddr = require("ipaddr.js");

const IPINFO_TIMEOUT_MS = 4500;
const PROBE_TIMEOUT_MS = 6500;
const DNSBL_TIMEOUT_MS = 2800;
const RISK_TIMEOUT_MS = 4500;

const languageByCountry = {
  ID: "Indonesian",
  US: "English",
  GB: "English",
  SG: "English / Malay / Chinese",
  MY: "Malay",
  TH: "Thai",
  VN: "Vietnamese",
  PH: "Filipino / English",
  JP: "Japanese",
  KR: "Korean",
  CN: "Chinese",
  HK: "Chinese / English",
  TW: "Chinese",
  IN: "Hindi / English",
  DE: "German",
  FR: "French",
  ES: "Spanish",
  BR: "Portuguese",
};

const languageCodeByCountry = {
  ID: ["id"],
  US: ["en"],
  GB: ["en"],
  SG: ["en", "ms", "zh"],
  MY: ["ms", "en"],
  TH: ["th"],
  VN: ["vi"],
  PH: ["fil", "tl", "en"],
  JP: ["ja"],
  KR: ["ko"],
  CN: ["zh"],
  HK: ["zh", "en"],
  TW: ["zh"],
  IN: ["hi", "en"],
  DE: ["de"],
  FR: ["fr"],
  ES: ["es"],
  BR: ["pt"],
};

const countryNameByCode = {
  ID: "印度尼西亚",
  US: "美国",
  GB: "英国",
  SG: "新加坡",
  MY: "马来西亚",
  TH: "泰国",
  VN: "越南",
  PH: "菲律宾",
  JP: "日本",
  KR: "韩国",
  CN: "中国",
  HK: "中国香港",
  TW: "中国台湾",
  IN: "印度",
  DE: "德国",
  FR: "法国",
  ES: "西班牙",
  BR: "巴西",
};

const residentialHints = [
  "telecom",
  "telekom",
  "telekomunikasi",
  "telkom",
  "broadband",
  "fiber",
  "fibre",
  "cable",
  "dsl",
  "communications",
  "telefonica",
  "comcast",
  "charter",
  "spectrum",
  "verizon",
  "at&t",
  "tmobile",
  "mobile",
  "wireless",
  "isp",
  "internet service",
];

const mobileHints = ["mobile", "wireless", "cellular", "lte", "5g", "4g", "indosat", "xl axiata", "telkomsel"];

const datacenterHints = [
  "amazon",
  "aws",
  "google cloud",
  "microsoft",
  "azure",
  "digitalocean",
  "linode",
  "akamai",
  "vultr",
  "ovh",
  "hetzner",
  "leaseweb",
  "contabo",
  "choopa",
  "cloudflare",
  "oracle",
  "alibaba",
  "tencent",
  "colo",
  "hosting",
  "vps",
  "server",
  "datacenter",
  "data center",
];

const platformTargets = [
  { key: "tiktok", name: "TikTok", category: "短视频/电商", url: "https://www.tiktok.com/", method: "GET" },
  { key: "chatgpt", name: "ChatGPT", category: "AI 服务", url: "https://chatgpt.com/", method: "GET" },
  { key: "openaiApi", name: "OpenAI API", category: "AI API", url: "https://api.openai.com/v1/models", method: "GET" },
  { key: "github", name: "GitHub", category: "开发者平台", url: "https://github.com/", method: "GET" },
  { key: "google", name: "Google", category: "搜索/广告", url: "https://www.google.com/generate_204", method: "GET" },
  { key: "youtube", name: "YouTube", category: "视频平台", url: "https://www.youtube.com/generate_204", method: "GET" },
  { key: "reddit", name: "Reddit", category: "社区", url: "https://www.reddit.com/", method: "GET" },
  { key: "netflix", name: "Netflix", category: "流媒体", url: "https://www.netflix.com/", method: "GET" },
];

function normalizeIp(raw) {
  let ip = String(raw || "").trim();
  ip = ip.replace(/^::ffff:/i, "");

  if (ip.includes(",")) {
    ip = ip.split(",")[0].trim();
  }

  if (!ipaddr.isValid(ip)) {
    const error = new Error("请输入有效的 IPv4 或 IPv6 地址。");
    error.code = "INVALID_IP";
    throw error;
  }

  return ip;
}

function getIpMeta(ip) {
  const parsed = ipaddr.parse(ip);
  const kind = parsed.kind();
  const range = parsed.range();

  return {
    ip,
    version: kind === "ipv4" ? "IPv4" : "IPv6",
    range,
    isPublic: range === "unicast",
    normalized: parsed.toString(),
  };
}

async function fetchJson(url, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(url, {
      signal: controller.signal,
      headers: {
        "User-Agent": "IP-Operability-Checker/0.2",
        Accept: "application/json,text/plain,*/*",
      },
    });

    if (!response.ok && response.status !== 429) {
      return { ok: false, status: response.status, data: null };
    }

    const data = await response.json().catch(() => null);
    return { ok: true, status: response.status, data };
  } catch (error) {
    return { ok: false, status: 0, data: null, error: error.name || "FetchError" };
  } finally {
    clearTimeout(timer);
  }
}

function normalizeGeoFromIpapi(data, source, status) {
  return {
    source,
    lookupStatus: "ok",
    country: data.country_name || data.country || "",
    countryCode: data.country_code || data.country || "",
    region: data.region || "",
    city: data.city || "",
    timezone: data.timezone || "",
    latitude: data.latitude || null,
    longitude: data.longitude || null,
    asn: data.asn || "",
    network: data.network || "",
    organization: data.org || "",
    isp: data.org || "",
    languages: data.languages || "",
    rawStatus: status,
  };
}

function normalizeGeoFromIpinfo(data, source, status) {
  const [latitude, longitude] = String(data.loc || ",").split(",");

  return {
    source,
    lookupStatus: "partial",
    country: data.country || "",
    countryCode: data.country || "",
    region: data.region || "",
    city: data.city || "",
    timezone: data.timezone || "",
    latitude: Number(latitude) || null,
    longitude: Number(longitude) || null,
    asn: data.org ? data.org.split(" ")[0] : "",
    network: "",
    organization: data.org || "",
    isp: data.org || "",
    languages: "",
    rawStatus: status,
  };
}

async function getGeoIntel(ipMeta) {
  if (!ipMeta.isPublic) {
    return {
      source: "local",
      lookupStatus: "skipped",
      reason: "private_or_reserved",
    };
  }

  const primary = await fetchJson(`https://ipapi.co/${ipMeta.ip}/json/`, IPINFO_TIMEOUT_MS);

  if (primary.ok && primary.data && !primary.data.error) {
    return normalizeGeoFromIpapi(primary.data, "ipapi.co", primary.status);
  }

  const backup = await fetchJson(`https://ipinfo.io/${ipMeta.ip}/json`, IPINFO_TIMEOUT_MS);

  if (backup.ok && backup.data) {
    return normalizeGeoFromIpinfo(backup.data, "ipinfo.io", backup.status);
  }

  return {
    source: "unavailable",
    lookupStatus: "failed",
    rawStatus: backup.status || primary.status,
  };
}

async function getCurrentEgressIntel() {
  const primary = await fetchJson("https://ipapi.co/json/", IPINFO_TIMEOUT_MS);

  if (primary.ok && primary.data && !primary.data.error) {
    const ip = primary.data.ip || "";
    return {
      ip,
      ...normalizeGeoFromIpapi(primary.data, "ipapi.co", primary.status),
    };
  }

  const backup = await fetchJson("https://ipinfo.io/json", IPINFO_TIMEOUT_MS);
  const data = backup.data || {};

  if (backup.ok && data.ip) {
    return {
      ip: data.ip,
      ...normalizeGeoFromIpinfo(data, "ipinfo.io", backup.status),
    };
  }

  return {
    ip: "",
    source: "unavailable",
    lookupStatus: "failed",
  };
}

function getIdentityText(geoIntel) {
  return [
    geoIntel.organization,
    geoIntel.isp,
    geoIntel.asn,
    geoIntel.network,
  ].filter(Boolean).join(" ").toLowerCase();
}

function classifyNetwork(geoIntel, ipMeta) {
  if (!ipMeta.isPublic) {
    return {
      type: "非公网地址",
      userFeature: "非公网",
      confidence: 98,
      severity: "critical",
      reasons: ["该地址属于内网、保留或本地地址，不能用于平台运营出口判断。"],
    };
  }

  const identity = getIdentityText(geoIntel);
  const datacenterHits = datacenterHints.filter((hint) => identity.includes(hint));
  const residentialHits = residentialHints.filter((hint) => identity.includes(hint));

  if (datacenterHits.length > 0) {
    return {
      type: "机房/VPS 倾向",
      userFeature: "机房/托管",
      confidence: Math.min(92, 62 + datacenterHits.length * 8),
      severity: "danger",
      reasons: [
        `运营商/组织命中云厂商或托管关键词：${datacenterHits.slice(0, 3).join(", ")}。`,
        "TikTok 店铺、账号养号和投放场景通常更偏好住宅或移动网络出口。",
      ],
    };
  }

  if (residentialHits.length > 0) {
    return {
      type: "住宅/宽带倾向",
      userFeature: "住宅",
      confidence: Math.min(92, 62 + residentialHits.length * 7),
      severity: "good",
      reasons: [`运营商名称更接近民用宽带/通信网络：${residentialHits.slice(0, 3).join(", ")}。`],
    };
  }

  return {
    type: "未知/需复核",
    userFeature: "未知",
    confidence: 46,
    severity: "warning",
    reasons: ["公开情报不足，建议接入 MaxMind、IP2Location、IPQualityScore 或人工样本复核。"],
  };
}

function buildOperatorProfile(geoIntel, classification) {
  const identity = getIdentityText(geoIntel);
  const isMobile = mobileHints.some((hint) => identity.includes(hint));
  const isDatacenter = classification.severity === "danger";
  const isResidential = classification.severity === "good";

  let networkType = "未知";
  if (isDatacenter) {
    networkType = "Cloud/VPS";
  } else if (isMobile) {
    networkType = "Mobile/Wireless";
  } else if (isResidential) {
    networkType = "Cable/DSL";
  }

  return {
    userFeature: classification.userFeature,
    provider: geoIntel.isp || geoIntel.organization || "-",
    networkType,
    registrant: geoIntel.organization || geoIntel.isp || "-",
    registrantType: isDatacenter ? "Hosting/Cloud" : isResidential ? "ISP" : "Unknown",
    independence: isDatacenter ? "较低" : isResidential ? "较高" : "待复核",
  };
}

async function checkDnsbl(ipMeta) {
  if (ipMeta.version !== "IPv4" || !ipMeta.isPublic) {
    return {
      status: "skipped",
      listed: [],
      checked: [],
      note: "DNSBL 当前仅检测公网 IPv4。",
    };
  }

  const zones = ["zen.spamhaus.org", "bl.spamcop.net", "dnsbl.sorbs.net"];
  const reversed = ipMeta.ip.split(".").reverse().join(".");

  async function resolve4WithTimeout(query) {
    const resolver = new dns.Resolver();
    let timer;

    try {
      return await Promise.race([
        resolver.resolve4(query),
        new Promise((_, reject) => {
          timer = setTimeout(() => {
            resolver.cancel();
            const error = new Error("DNSBL query timed out");
            error.code = "TIMEOUT";
            reject(error);
          }, DNSBL_TIMEOUT_MS);
        }),
      ]);
    } finally {
      clearTimeout(timer);
    }
  }

  const results = await Promise.all(zones.map(async (zone) => {
    const query = `${reversed}.${zone}`;
    try {
      const answers = await resolve4WithTimeout(query);
      return { zone, listed: true, answers };
    } catch (error) {
      return { zone, listed: false, error: error.code || "NXDOMAIN" };
    }
  }));

  return {
    status: "ok",
    checked: zones,
    listed: results.filter((item) => item.listed),
  };
}

async function getFreeRiskIntel(ipMeta) {
  const emptyFlags = {
    proxy: false,
    vpn: false,
    tor: false,
    hosting: false,
    datacenter: false,
    anonymous: false,
    compromised: false,
    scraper: false,
    abuser: false,
    mobile: false,
    risk: 0,
    confidence: null,
  };

  if (!ipMeta.isPublic) {
    return {
      status: "skipped",
      sources: [],
      flags: emptyFlags,
      details: {},
      note: "第三方风控仅检测公网 IP。",
    };
  }

  async function fetchAbuseIpDb() {
    if (!process.env.ABUSEIPDB_API_KEY) {
      return { ok: false, status: 0, data: null, skipped: true };
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), RISK_TIMEOUT_MS);

    try {
      const params = new URLSearchParams({
        ipAddress: ipMeta.ip,
        maxAgeInDays: "90",
        verbose: "true",
      });
      const response = await fetch(`https://api.abuseipdb.com/api/v2/check?${params.toString()}`, {
        signal: controller.signal,
        headers: {
          Key: process.env.ABUSEIPDB_API_KEY,
          Accept: "application/json",
        },
      });
      const data = await response.json().catch(() => null);

      return { ok: response.ok, status: response.status, data };
    } catch (error) {
      return { ok: false, status: 0, data: null, error: error.name || "FetchError" };
    } finally {
      clearTimeout(timer);
    }
  }

  async function fetchIpQualityScore() {
    if (!process.env.IPQUALITYSCORE_API_KEY) {
      return { ok: false, status: 0, data: null, skipped: true };
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), RISK_TIMEOUT_MS);

    try {
      const params = new URLSearchParams({
        strictness: "1",
        fast: "true",
        allow_public_access_points: "true",
      });
      const response = await fetch(`https://www.ipqualityscore.com/api/json/ip/${process.env.IPQUALITYSCORE_API_KEY}/${encodeURIComponent(ipMeta.ip)}?${params.toString()}`, {
        signal: controller.signal,
        headers: {
          Accept: "application/json",
        },
      });
      const data = await response.json().catch(() => null);

      return { ok: response.ok && data && data.success !== false, status: response.status, data };
    } catch (error) {
      return { ok: false, status: 0, data: null, error: error.name || "FetchError" };
    } finally {
      clearTimeout(timer);
    }
  }

  const [ipapiIs, proxycheck, abuseIpDb, ipQualityScore] = await Promise.all([
    fetchJson(`https://api.ipapi.is/?q=${encodeURIComponent(ipMeta.ip)}`, RISK_TIMEOUT_MS),
    fetchJson(`https://proxycheck.io/v3/${encodeURIComponent(ipMeta.ip)}`, RISK_TIMEOUT_MS),
    fetchAbuseIpDb(),
    fetchIpQualityScore(),
  ]);

  const ipapiData = ipapiIs.ok && ipapiIs.data ? ipapiIs.data : {};
  const proxyData = proxycheck.ok && proxycheck.data ? proxycheck.data[ipMeta.ip] || {} : {};
  const detections = proxyData.detections || {};
  const abuseData = abuseIpDb.ok && abuseIpDb.data && abuseIpDb.data.data ? abuseIpDb.data.data : {};
  const abuseConfidenceScore = Number(abuseData.abuseConfidenceScore || 0);
  const totalReports = Number(abuseData.totalReports || 0);
  const ipqsRawData = ipQualityScore.data || {};
  const ipqsData = ipQualityScore.ok && ipQualityScore.data ? ipQualityScore.data : {};
  const ipqsFraudScore = Number(ipqsData.fraud_score || 0);
  const ipqsProxy = Boolean(ipqsData.proxy);
  const ipqsVpn = Boolean(ipqsData.vpn || ipqsData.active_vpn);
  const ipqsTor = Boolean(ipqsData.tor || ipqsData.active_tor);
  const ipqsRecentAbuse = Boolean(ipqsData.recent_abuse);
  const ipqsBot = Boolean(ipqsData.bot_status);
  const ipqsConnectionType = String(ipqsData.connection_type || "").toLowerCase();
  const ipqsHosting = /hosting|data center|datacenter|cloud|server/.test(ipqsConnectionType);

  const flags = {
    proxy: Boolean(ipapiData.is_proxy || detections.proxy || ipqsProxy),
    vpn: Boolean(ipapiData.is_vpn || detections.vpn || ipqsVpn),
    tor: Boolean(ipapiData.is_tor || detections.tor || ipqsTor),
    hosting: Boolean(detections.hosting || ipqsHosting),
    datacenter: Boolean(ipapiData.is_datacenter || detections.hosting || ipqsHosting),
    anonymous: Boolean(detections.anonymous || ipapiData.is_proxy || ipapiData.is_vpn || ipapiData.is_tor || ipqsProxy || ipqsVpn || ipqsTor),
    compromised: Boolean(detections.compromised),
    scraper: Boolean(ipapiData.is_crawler || detections.scraper || ipqsBot),
    abuser: Boolean(ipapiData.is_abuser || detections.compromised || detections.scraper || abuseConfidenceScore >= 25 || totalReports > 0 || ipqsRecentAbuse || ipqsFraudScore >= 75),
    mobile: Boolean(ipapiData.is_mobile || ipqsData.mobile),
    risk: Math.max(Number(detections.risk || 0), abuseConfidenceScore, ipqsFraudScore),
    confidence: detections.confidence ?? null,
  };

  const sources = [];

  if (ipapiIs.ok && ipapiIs.data) {
    sources.push("ipapi.is");
  }

  if (proxycheck.ok && proxycheck.data && proxycheck.data.status === "ok") {
    sources.push("proxycheck.io");
  }

  if (abuseIpDb.ok && abuseIpDb.data) {
    sources.push("AbuseIPDB");
  }

  if (ipQualityScore.ok && ipQualityScore.data) {
    sources.push("IPQualityScore");
  }

  return {
    status: sources.length ? "ok" : "failed",
    sources,
    flags,
    details: {
      ipapiIs: {
        companyType: ipapiData.company && ipapiData.company.type,
        companyName: ipapiData.company && ipapiData.company.name,
        asnType: ipapiData.asn && ipapiData.asn.type,
        asnAbuserScore: ipapiData.asn && ipapiData.asn.abuser_score,
        companyAbuserScore: ipapiData.company && ipapiData.company.abuser_score,
      },
      proxycheck: {
        networkType: proxyData.network && proxyData.network.type,
        provider: proxyData.network && proxyData.network.provider,
        risk: flags.risk,
        confidence: flags.confidence,
        lastUpdated: proxyData.last_updated || "",
      },
      abuseIpDb: {
        enabled: Boolean(process.env.ABUSEIPDB_API_KEY),
        status: abuseIpDb.status || 0,
        abuseConfidenceScore,
        totalReports,
        numDistinctUsers: Number(abuseData.numDistinctUsers || 0),
        usageType: abuseData.usageType || "",
        isp: abuseData.isp || "",
        domain: abuseData.domain || "",
        lastReportedAt: abuseData.lastReportedAt || "",
      },
      ipQualityScore: {
        enabled: Boolean(process.env.IPQUALITYSCORE_API_KEY),
        status: ipQualityScore.status || 0,
        success: Boolean(ipQualityScore.ok),
        fraudScore: ipqsFraudScore,
        proxy: ipqsProxy,
        vpn: ipqsVpn,
        tor: ipqsTor,
        recentAbuse: ipqsRecentAbuse,
        botStatus: ipqsBot,
        mobile: Boolean(ipqsData.mobile),
        connectionType: ipqsData.connection_type || "",
        abuseVelocity: ipqsData.abuse_velocity || "",
        isp: ipqsData.ISP || ipqsData.isp || "",
        asn: ipqsData.ASN || ipqsData.asn || "",
        organization: ipqsData.organization || "",
        message: ipqsRawData.message || "",
      },
    },
  };
}

async function probeTarget(target, egress) {
  const startedAt = Date.now();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), PROBE_TIMEOUT_MS);

  try {
    const response = await fetch(target.url, {
      method: target.method,
      signal: controller.signal,
      redirect: "manual",
      headers: {
        "User-Agent": "Mozilla/5.0 IP-Operability-Checker/0.2",
      },
    });

    const latencyMs = Date.now() - startedAt;
    const reachable = response.status > 0 && response.status < 500;
    const restricted = [401, 403, 451, 429].includes(response.status);
    const countryLabel = formatCountry(egress);

    return {
      ...target,
      status: reachable ? (restricted ? "restricted" : "reachable") : "blocked",
      httpStatus: response.status,
      latencyMs,
      egressCountry: reachable ? egress.country || "" : "",
      egressCountryCode: reachable ? egress.countryCode || "" : "",
      detectedRegion: reachable ? countryLabel : "",
      verdict: restricted
        ? `可连通但可能受限制${countryLabel ? `，出口国家：${countryLabel}` : ""}`
        : reachable
          ? `可连通${countryLabel ? `，出口国家：${countryLabel}` : ""}`
          : "不可用",
    };
  } catch (error) {
    return {
      ...target,
      status: "blocked",
      httpStatus: 0,
      latencyMs: Date.now() - startedAt,
      egressCountry: "",
      egressCountryCode: "",
      detectedRegion: "",
      verdict: error.name === "AbortError" ? "超时" : "不可用",
    };
  } finally {
    clearTimeout(timer);
  }
}

function formatCountry(geo) {
  const code = geo.countryCode || "";
  const country = countryNameByCode[code] || geo.country || "";
  return [country, code].filter(Boolean).join(" / ");
}

async function runReachabilityChecks(enabled, geoIntel) {
  const inputRegion = formatCountry(geoIntel) || "-";

  if (!enabled) {
    return {
      mode: "skipped",
      note: "本次未显示平台访问参考。",
      egress: null,
      targets: [],
    };
  }

  const targets = platformTargets.map((target) => ({
    ...target,
    status: "reference",
    httpStatus: "-",
    latencyMs: "-",
    egressCountry: geoIntel.country || "",
    egressCountryCode: geoIntel.countryCode || "",
    detectedRegion: inputRegion,
    verdict: "归属地参考",
  }));

  return {
    mode: "input-ip-reference",
    note: "该部分按用户输入 IP 展示平台访问参考地区，不使用当前部署服务器/VPS 的出口 IP。",
    egress: null,
    reachableCount: 0,
    total: targets.length,
    targets,
  };
}

function buildReachabilityContext(reachability, geoIntel) {
  const inputRegion = formatCountry(geoIntel) || "-";

  return {
    ...reachability,
    note: reachability.note || "该部分按用户输入 IP 展示平台访问参考地区。",
    context: {
      subject: "用户输入 IP",
      inputRegion,
      egressRegion: "",
      isSameCountry: true,
      warning: "真实平台连通性必须让流量从该 IP 本身发出。服务器不能仅凭一个远程 IP 地址代替它访问 TikTok、ChatGPT 等网站。",
    },
  };
}

function buildImportantChecks({ classification, dnsbl, riskIntel }) {
  const isDatacenter = classification.severity === "danger";
  const listed = dnsbl.listed && dnsbl.listed.length > 0;
  const flags = riskIntel && riskIntel.flags ? riskIntel.flags : {};
  const isProxy = Boolean(flags.proxy);
  const isVpn = Boolean(flags.vpn);
  const isTor = Boolean(flags.tor);
  const isCloud = Boolean(flags.hosting || flags.datacenter);
  const isAbuse = Boolean(flags.abuser || flags.compromised || flags.scraper || flags.risk >= 50);
  const isSuspicious = Boolean(isProxy || isVpn || isTor || isCloud || isAbuse || listed);

  return {
    anonymousVpn: isVpn || flags.anonymous ? "是" : "否",
    datacenterProxy: isCloud || isDatacenter ? "是" : "否",
    publicProxy: isProxy ? "是" : "未发现",
    suspiciousProxy: isSuspicious ? "疑似" : "否",
    blacklist: listed ? "是" : "否",
    abuseNode: isAbuse || listed ? "疑似" : "否",
    torNode: isTor ? "是" : "未发现",
    attackParticipant: flags.compromised || listed ? "疑似" : "否",
    cloudService: isCloud || isDatacenter ? "是" : "否",
    riskSource: riskIntel && riskIntel.sources && riskIntel.sources.length
      ? riskIntel.sources.join(" / ")
      : "未获取",
    riskScore: flags.confidence === null || flags.confidence === undefined
      ? `risk ${flags.risk || 0}`
      : `risk ${flags.risk || 0} / confidence ${flags.confidence}`,
  };
}

function buildRegionTime(geoIntel) {
  const country = formatCountry(geoIntel);
  const language = languageByCountry[geoIntel.countryCode] || geoIntel.languages || "未知";

  return {
    broadcastRegion: country || "-",
    registeredRegion: country || "-",
    city: [geoIntel.region, geoIntel.city].filter(Boolean).join(" / ") || "-",
    longitude: geoIntel.longitude ?? "-",
    latitude: geoIntel.latitude ?? "-",
    timezone: geoIntel.timezone || "-",
    primaryLanguage: language,
  };
}

function normalizeLanguageCode(language) {
  return String(language || "").toLowerCase().split("-")[0];
}

function buildIssues({ classification, dnsbl, geoIntel, requestMeta, riskIntel }) {
  const issues = [];
  const listed = dnsbl.listed && dnsbl.listed.length > 0;
  const flags = riskIntel && riskIntel.flags ? riskIntel.flags : {};
  const deviceTimezone = requestMeta.deviceTimezone || "";
  const deviceLanguages = Array.isArray(requestMeta.deviceLanguages) ? requestMeta.deviceLanguages : [];
  const expectedLanguages = languageCodeByCountry[geoIntel.countryCode] || [];
  const actualLanguages = deviceLanguages.map(normalizeLanguageCode).filter(Boolean);
  const hasLanguageMismatch = expectedLanguages.length > 0
    && actualLanguages.length > 0
    && !actualLanguages.some((language) => expectedLanguages.includes(language));

  if (deviceTimezone && geoIntel.timezone && deviceTimezone === geoIntel.timezone) {
    issues.push({
      level: "good",
      title: "时区匹配",
      detail: `IP 本地时区为 ${geoIntel.timezone}，当前检测设备时区也是 ${deviceTimezone}。TikTok 运营时区设置与目标 IP 地区一致。`,
    });
  }

  if (!deviceTimezone && geoIntel.timezone) {
    issues.push({
      level: "warning",
      title: "无法读取设备时区",
      detail: `IP 本地时区为 ${geoIntel.timezone}，但当前浏览器未提供设备时区。做 TikTok 运营时，请确认设备时区与目标 IP 地区一致。`,
    });
  }

  if (deviceTimezone && geoIntel.timezone && deviceTimezone !== geoIntel.timezone) {
    issues.push({
      level: "warning",
      title: "时区和 IP 地区不匹配",
      detail: `IP 本地时区为 ${geoIntel.timezone}，当前检测设备时区为 ${deviceTimezone}。做 TikTok 运营时，请调整设备时区与目标 IP 地区一致。`,
    });
  }

  if (hasLanguageMismatch) {
    issues.push({
      level: "warning",
      title: "语言和 IP 地区不匹配",
      detail: `IP 主要语言建议为 ${languageByCountry[geoIntel.countryCode] || expectedLanguages.join(", ")}，当前检测设备语言为 ${deviceLanguages.join(", ")}。做 TikTok 运营时，请调整设备语言与目标地区一致。`,
    });
  }

  if (listed) {
    issues.push({
      level: "danger",
      title: "提示黑名单",
      detail: "该 IP 命中黑名单，媒体、商城、社交平台容易触发风控，不建议使用。",
    });
  }

  if (flags.proxy || flags.vpn || flags.tor || flags.hosting || flags.datacenter || flags.abuser || flags.risk >= 50) {
    const riskLabels = [
      flags.proxy ? "代理" : "",
      flags.vpn ? "VPN" : "",
      flags.tor ? "TOR" : "",
      flags.hosting || flags.datacenter ? "机房/云服务" : "",
      flags.abuser ? "滥用节点" : "",
      flags.risk >= 50 ? `风险分 ${flags.risk}` : "",
    ].filter(Boolean);

    issues.push({
      level: "danger",
      title: "第三方风控命中",
      detail: `免费风控库检测到 ${riskLabels.join("、")} 信号，媒体、商城、社交平台容易触发风控，建议更换 IP。`,
    });
  }

  if (classification.severity === "danger") {
    issues.push({
      level: "danger",
      title: "其它 IP 问题",
      detail: "该 IP 疑似机房/VPS/云服务出口，TikTok 运营中更容易出现限流、验证、封号等问题，建议更换住宅或移动网络 IP。",
    });
  }

  if (classification.severity === "warning") {
    issues.push({
      level: "warning",
      title: "其它 IP 问题",
      detail: "住宅属性证据不足，建议更换更明确的住宅 IP，或接入付费情报库交叉验证后再使用。",
    });
  }

  if (!issues.length) {
    issues.push({
      level: "good",
      title: "未发现明显问题",
      detail: "当前未发现黑名单、机房代理或明显时区语言冲突。仍建议小流量试运营并持续观察限流、验证、封号情况。",
    });
  }

  return issues;
}

function buildTermExplanations() {
  return {
    mainInfo: [
      ["网络提供商", "根据 ASN 识别提供网络的运营商。"],
      ["网络类型", "ISP、机房、企业、教育、政府等网络大类。"],
      ["归属商", "IP 的租用或承包商。"],
      ["归属商类型", "ISP、机房、企业、教育、政府等归属方类型。"],
      ["使用者特征", "根据 IP 日常流量识别特征，例如机房、住宅、企业、教育、CDN、图书馆、政府等。"],
    ],
    importantChecks: [
      ["匿名VPN", "匿名 VPN 提供商。"],
      ["机房代理", "托管在机房的代理。"],
      ["公共代理", "公开的代理节点。"],
      ["可疑代理", "此类型大多进入黑名单，媒体、商城、社交平台容易被风控。"],
      ["滥用节点", "已知的滥用来源，例如垃圾邮件、收割机、注册机器人。"],
      ["TOR节点", "Tor 出口中继节点。"],
      ["参与攻击", "曾参与恶意活动，例如攻击、恶意软件、僵尸网络活动。"],
      ["云服务", "云服务器节点。"],
    ],
    issueRules: [
      "时区和语言不匹配，请调整自己设备设置。",
      "其它 IP 问题，建议更换 IP。",
      "提示黑名单，都不建议使用。",
    ],
  };
}

function scoreIp({ classification, dnsbl, geoIntel, ipMeta, riskIntel }) {
  let score = 72;
  const penalties = [];
  const bonuses = [];
  const flags = riskIntel && riskIntel.flags ? riskIntel.flags : {};

  if (!ipMeta.isPublic) {
    score -= 65;
    penalties.push("非公网地址无法作为运营出口。");
  }

  if (classification.severity === "danger") {
    score -= 30;
    penalties.push("运营商类型疑似机房/VPS。");
  }

  if (classification.severity === "warning") {
    score -= 12;
    penalties.push("住宅属性证据不足。");
  }

  if (classification.severity === "good") {
    score += 14;
    bonuses.push("运营商更接近住宅/通信网络。");
  }

  if (dnsbl.listed && dnsbl.listed.length > 0) {
    score -= Math.min(35, dnsbl.listed.length * 14);
    penalties.push(`命中 ${dnsbl.listed.length} 个黑名单。`);
  }

  if (flags.proxy || flags.vpn || flags.tor || flags.hosting || flags.datacenter || flags.abuser) {
    score -= 28;
    penalties.push("第三方风控库命中代理/VPN/机房/滥用风险。");
  } else if (riskIntel && riskIntel.status === "ok" && flags.risk < 50) {
    score += 6;
    bonuses.push("免费第三方风控库未发现代理/VPN/TOR/机房/滥用信号。");
  }

  if (flags.risk >= 50) {
    score -= Math.min(22, Math.round(flags.risk / 5));
    penalties.push(`第三方风险分较高：${flags.risk}。`);
  }

  if (!geoIntel.countryCode) {
    score -= 8;
    penalties.push("地理位置或 ASN 数据不完整。");
  }

  const normalized = Math.max(0, Math.min(100, Math.round(score)));
  let label = "高风险";
  let grade = "D";

  if (normalized >= 86) {
    label = "优良";
    grade = "A";
  } else if (normalized >= 72) {
    label = "良好";
    grade = "B";
  } else if (normalized >= 55) {
    label = "一般";
    grade = "C";
  }

  return {
    score: normalized,
    grade,
    label,
    penalties,
    bonuses,
  };
}

function buildReportSummary({ classification, operatorProfile, score }) {
  if (classification.severity === "good") {
    return `您的 IP 使用者是${operatorProfile.userFeature}类型，网络线路属于 ${operatorProfile.networkType}，独立性${operatorProfile.independence}，IP 质量${score.label === "优良" ? "非常优质" : "较好"}。`;
  }

  if (classification.severity === "danger") {
    return `您的 IP 更接近${operatorProfile.userFeature}类型，网络线路属于 ${operatorProfile.networkType}，用于 TikTok 运营前建议更换住宅或移动出口。`;
  }

  return "公开情报不足，暂时无法确认该 IP 是否为住宅网络，建议接入付费情报库或在真实运营节点继续复核。";
}

function buildRecommendations({ classification, dnsbl, reachability, ipMeta }) {
  const recommendations = [];

  if (!ipMeta.isPublic) {
    recommendations.push("请使用公网 IP 或在目标 VPS 上部署探针后再测。");
  }

  if (classification.severity === "danger") {
    recommendations.push("如果目标是 TikTok 店铺/账号运营，优先选择住宅宽带、移动网络或稳定 ISP 代理。");
  }

  if (classification.severity === "warning") {
    recommendations.push("建议补充 IP2Location、MaxMind、IPQS、Scamalytics 等数据库交叉验证住宅属性。");
  }

  if (dnsbl.listed && dnsbl.listed.length) {
    recommendations.push("该 IP 命中邮件/滥用黑名单，建议更换出口或先做信誉修复。");
  }

  if (reachability.mode === "server-egress") {
    const blockedNames = reachability.targets
      .filter((item) => item.status === "blocked")
      .map((item) => item.name);

    if (blockedNames.length) {
      recommendations.push(`检测节点访问 ${blockedNames.slice(0, 4).join("、")} 异常，部署到真实 VPS 后需重新测试。`);
    }
  }

  if (!recommendations.length) {
    recommendations.push("当前检测未发现明显风险，建议小流量试运营并持续监控账号行为指标。");
  }

  return recommendations;
}

async function analyzeIp({ ip, runReachability = true, requestMeta = {} }) {
  const normalizedIp = normalizeIp(ip);
  const ipMeta = getIpMeta(normalizedIp);
  const [geoIntel, dnsbl, freeRiskIntel] = await Promise.all([
    getGeoIntel(ipMeta),
    checkDnsbl(ipMeta),
    getFreeRiskIntel(ipMeta),
  ]);
  const rawReachability = await runReachabilityChecks(runReachability, geoIntel);
  const reachability = buildReachabilityContext(rawReachability, geoIntel);
  const classification = classifyNetwork(geoIntel, ipMeta);
  const operatorProfile = buildOperatorProfile(geoIntel, classification);
  const importantChecks = buildImportantChecks({ classification, dnsbl, riskIntel: freeRiskIntel });
  const regionTime = buildRegionTime(geoIntel);
  const issues = buildIssues({ classification, dnsbl, geoIntel, requestMeta, riskIntel: freeRiskIntel });
  const score = scoreIp({ classification, dnsbl, geoIntel, ipMeta, riskIntel: freeRiskIntel });

  return {
    checkedAt: new Date().toISOString(),
    input: {
      ip: normalizedIp,
      userAgent: requestMeta.userAgent,
    },
    basic: {
      ...ipMeta,
      ...geoIntel,
    },
    classification,
    operatorProfile,
    mainInfo: {
      countryRegion: formatCountry(geoIntel),
      userFeature: operatorProfile.userFeature,
      networkProvider: operatorProfile.provider,
      networkType: operatorProfile.networkType,
      registrant: operatorProfile.registrant,
      registrantType: operatorProfile.registrantType,
    },
    importantChecks,
    regionTime,
    issues,
    termExplanations: buildTermExplanations(),
    reputation: {
      dnsbl,
      freeRiskIntel,
    },
    reachability,
    score,
    reportSummary: buildReportSummary({ classification, operatorProfile, score }),
    recommendations: buildRecommendations({ classification, dnsbl, reachability, ipMeta }),
    roadmap: [
      "接入付费 IP 情报库后可提升住宅/机房识别准确率。",
      "部署多地区 VPS 探针后可判断不同国家出口对 TikTok、ChatGPT、Google 等平台的可用性。",
      "批量检测、API Key、积分扣费和历史报告可以作为下一阶段商业版模块。",
    ],
  };
}

module.exports = {
  analyzeIp,
};
