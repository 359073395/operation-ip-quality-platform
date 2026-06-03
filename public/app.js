const form = document.querySelector("#checkForm");
const ipInput = document.querySelector("#ipInput");
const reachabilityInput = document.querySelector("#reachabilityInput");
const challengeQuestion = document.querySelector("#challengeQuestion");
const challengeAnswer = document.querySelector("#challengeAnswer");
const refreshChallenge = document.querySelector("#refreshChallenge");
const submitButton = document.querySelector("#submitButton");
const emptyState = document.querySelector("#emptyState");
const loadingState = document.querySelector("#loadingState");
const errorState = document.querySelector("#errorState");
const report = document.querySelector("#report");
const probePulse = document.querySelector("#probePulse");

const scoreValue = document.querySelector("#scoreValue");
const scoreGrade = document.querySelector("#scoreGrade");
const scoreLabel = document.querySelector("#scoreLabel");
const scoreSummary = document.querySelector("#scoreSummary");
const issueList = document.querySelector("#issueList");
const mainInfoList = document.querySelector("#mainInfoList");
const mainInfoHelp = document.querySelector("#mainInfoHelp");
const importantList = document.querySelector("#importantList");
const importantHelp = document.querySelector("#importantHelp");
const regionList = document.querySelector("#regionList");
const reachabilityNote = document.querySelector("#reachabilityNote");
const platformGrid = document.querySelector("#platformGrid");
const recommendationList = document.querySelector("#recommendationList");
let activeChallengeId = "";

function setState(state) {
  emptyState.hidden = state !== "empty";
  loadingState.hidden = state !== "loading";
  errorState.hidden = state !== "error";
  report.hidden = state !== "report";
  submitButton.disabled = state === "loading";
  probePulse.textContent = state === "loading" ? "Scanning" : "Ready";
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function formatValue(value) {
  if (value === null || value === undefined || value === "") {
    return "-";
  }

  return value;
}

function renderDl(element, rows) {
  element.innerHTML = rows
    .map(([label, value]) => `<dt>${escapeHtml(label)}</dt><dd>${escapeHtml(formatValue(value))}</dd>`)
    .join("");
}

function renderList(element, rows) {
  element.innerHTML = rows.map((row) => `<li>${escapeHtml(row)}</li>`).join("");
}

function renderIssueList(element, issues) {
  element.innerHTML = issues.map((issue) => `
    <li class="${escapeHtml(issue.level || "")}">
      <strong>${escapeHtml(issue.title || "问题")}</strong>
      <span>${escapeHtml(issue.detail || "")}</span>
    </li>
  `).join("");
}

function renderTermBox(element, rows) {
  element.innerHTML = (rows || []).map(([term, description]) => `
    <div class="term-row">
      <strong>${escapeHtml(term)}</strong>
      <span>${escapeHtml(description)}</span>
    </div>
  `).join("");
}

async function loadChallenge() {
  challengeQuestion.textContent = "加载中...";
  challengeAnswer.value = "";

  try {
    const response = await fetch("/api/challenge");
    const challenge = await response.json();

    if (!response.ok || !challenge.id) {
      throw new Error("验证题加载失败。");
    }

    activeChallengeId = challenge.id;
    challengeQuestion.textContent = challenge.question;
  } catch (error) {
    activeChallengeId = "";
    challengeQuestion.textContent = "请刷新";
    errorState.textContent = error.message || "验证题加载失败，请刷新后重试。";
    setState("error");
  }
}

function statusClass(value) {
  if (["是", "疑似"].includes(value)) {
    return "risk-yes";
  }

  if (["否", "未发现"].includes(value)) {
    return "risk-no";
  }

  return "";
}

function renderImportantChecks(checks) {
  const rows = [
    ["匿名VPN", checks.anonymousVpn],
    ["机房代理", checks.datacenterProxy],
    ["公共代理", checks.publicProxy],
    ["可疑代理", checks.suspiciousProxy],
    ["黑名单", checks.blacklist],
    ["滥用节点", checks.abuseNode],
    ["TOR节点", checks.torNode],
    ["参与攻击", checks.attackParticipant],
    ["云服务", checks.cloudService],
  ];

  importantList.innerHTML = rows.map(([label, value]) => `
    <dt>${escapeHtml(label)}</dt>
    <dd><span class="risk-pill ${statusClass(value)}">${escapeHtml(value)}</span></dd>
  `).join("");
}

function renderReport(data) {
  scoreValue.textContent = data.score.score;
  scoreGrade.textContent = data.score.grade;
  scoreLabel.textContent = data.score.label;
  const scoreTone = data.score.score >= 86
    ? "good"
    : data.score.score >= 55
      ? "warning"
      : "danger";
  document.querySelector(".score-band").className = `score-band score-${scoreTone}`;
  scoreSummary.textContent = data.reportSummary || [
    data.classification.type,
    `${data.classification.confidence}% 置信度`,
    data.basic.country || data.basic.countryCode || "未知地区",
  ].join(" · ");

  renderIssueList(issueList, data.issues || []);

  renderDl(mainInfoList, [
    ["国家/地区", data.mainInfo.countryRegion],
    ["使用者特征", data.mainInfo.userFeature],
    ["网络提供商", data.mainInfo.networkProvider],
    ["网络类型", data.mainInfo.networkType],
    ["归属商", data.mainInfo.registrant],
    ["归属商类型", data.mainInfo.registrantType],
    ["ASN", data.basic.asn],
    ["IP版本", data.basic.version],
  ]);
  renderTermBox(mainInfoHelp, data.termExplanations && data.termExplanations.mainInfo);

  renderImportantChecks(data.importantChecks);
  renderTermBox(importantHelp, data.termExplanations && data.termExplanations.importantChecks);

  renderDl(regionList, [
    ["广播地区", data.regionTime.broadcastRegion],
    ["注册地区", data.regionTime.registeredRegion],
    ["城市", data.regionTime.city],
    ["经度", data.regionTime.longitude],
    ["纬度", data.regionTime.latitude],
    ["本地时区", data.regionTime.timezone],
    ["主要语言", data.regionTime.primaryLanguage],
    ["数据源", `${data.basic.source} (${data.basic.lookupStatus})`],
  ]);

  reachabilityNote.textContent = data.reachability.note;
  platformGrid.innerHTML = (data.reachability.targets || []).map((target) => {
    const region = target.detectedRegion || "-";
    return `
      <div class="platform ${escapeHtml(target.status)}">
        <strong>${escapeHtml(target.name)}</strong>
        <span class="category">${escapeHtml(target.category)}</span>
        <span class="verdict">${escapeHtml(target.verdict)}</span>
        <span class="region">出口国家/地区：${escapeHtml(region)}</span>
        <span class="latency">HTTP ${escapeHtml(target.httpStatus)} · ${escapeHtml(target.latencyMs)} ms</span>
      </div>
    `;
  }).join("");

  renderList(recommendationList, data.recommendations);
  setState("report");
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  setState("loading");

  try {
    const response = await fetch("/api/check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ip: ipInput.value.trim(),
        runReachability: reachabilityInput.checked,
        deviceTimezone: Intl.DateTimeFormat().resolvedOptions().timeZone || "",
        deviceLanguages: navigator.languages ? [...navigator.languages] : [navigator.language].filter(Boolean),
        challengeId: activeChallengeId,
        challengeAnswer: challengeAnswer.value.trim(),
      }),
    });

    const data = await response.json();

    if (!response.ok) {
      if (data.challenge) {
        activeChallengeId = data.challenge.id;
        challengeQuestion.textContent = data.challenge.question;
        challengeAnswer.value = "";
      } else {
        await loadChallenge();
      }
      throw new Error(data.message || "检测失败，请稍后重试。");
    }

    renderReport(data);
    await loadChallenge();
  } catch (error) {
    errorState.textContent = error.message || "检测失败，请稍后重试。";
    setState("error");
  }
});

refreshChallenge.addEventListener("click", () => {
  loadChallenge();
});

function drawSignal() {
  const canvas = document.querySelector("#signalCanvas");
  const ctx = canvas.getContext("2d");
  const width = canvas.width;
  const height = canvas.height;
  let frame = 0;

  function render() {
    frame += 0.012;
    ctx.clearRect(0, 0, width, height);

    ctx.strokeStyle = "rgba(255,255,255,0.16)";
    ctx.lineWidth = 1;
    for (let x = -80; x < width + 80; x += 40) {
      ctx.beginPath();
      ctx.moveTo(x, 0);
      ctx.lineTo(x + 120, height);
      ctx.stroke();
    }

    const points = [
      [86, 82, "TikTok"],
      [212, 136, "ISP"],
      [366, 82, "AI"],
      [302, 244, "GitHub"],
      [132, 256, "DNSBL"],
    ];

    ctx.strokeStyle = "rgba(168,231,220,0.54)";
    ctx.lineWidth = 2;
    for (let index = 0; index < points.length; index += 1) {
      const [x1, y1] = points[index];
      const [x2, y2] = points[(index + 1) % points.length];
      ctx.beginPath();
      ctx.moveTo(x1, y1);
      ctx.lineTo(x2, y2);
      ctx.stroke();
    }

    points.forEach(([x, y, label], index) => {
      const pulse = 7 + Math.sin(frame * 6 + index) * 3;
      ctx.fillStyle = "rgba(15,143,124,0.32)";
      ctx.beginPath();
      ctx.arc(x, y, pulse + 12, 0, Math.PI * 2);
      ctx.fill();

      ctx.fillStyle = "#f8fffb";
      ctx.beginPath();
      ctx.arc(x, y, pulse, 0, Math.PI * 2);
      ctx.fill();

      ctx.fillStyle = "rgba(255,255,255,0.86)";
      ctx.font = "700 14px Segoe UI, Arial";
      ctx.fillText(label, x + 16, y + 5);
    });

    requestAnimationFrame(render);
  }

  render();
}

drawSignal();
loadChallenge();
setState("empty");
