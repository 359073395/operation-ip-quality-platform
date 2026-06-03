const loginPanel = document.querySelector("#loginPanel");
const adminPanel = document.querySelector("#adminPanel");
const loginForm = document.querySelector("#loginForm");
const copyForm = document.querySelector("#copyForm");
const apiKeyForm = document.querySelector("#apiKeyForm");
const apiStatus = document.querySelector("#apiStatus");
const logoutButton = document.querySelector("#logoutButton");
const testIp = document.querySelector("#testIp");

function setStatus(value) {
  apiStatus.textContent = typeof value === "string" ? value : JSON.stringify(value, null, 2);
}

async function requestJson(url, options = {}) {
  const response = await fetch(url, {
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options,
  });
  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(data.message || "请求失败");
  }

  return data;
}

function showAdmin(show) {
  loginPanel.hidden = show;
  adminPanel.hidden = !show;
  logoutButton.hidden = !show;
}

async function loadConfig() {
  const config = await requestJson("/api/admin/config");

  for (const [key, value] of Object.entries(config)) {
    const field = copyForm.elements[key];

    if (field) {
      field.value = value || "";
    }
  }
}

async function loadApiKeys() {
  const data = await requestJson("/api/admin/api-keys");

  for (const [key, meta] of Object.entries(data.keys || {})) {
    const field = apiKeyForm.elements[key];

    if (field) {
      field.value = "";
      field.placeholder = meta.configured ? `已配置：${meta.masked}` : "未配置";
    }
  }
}

async function refreshAdmin() {
  await Promise.all([loadConfig(), loadApiKeys()]);
}

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();

  try {
    await requestJson("/api/admin/login", {
      method: "POST",
      body: JSON.stringify({ password: document.querySelector("#adminPassword").value }),
    });
    showAdmin(true);
    await refreshAdmin();
    setStatus("已登录。");
  } catch (error) {
    setStatus(error.message);
  }
});

logoutButton.addEventListener("click", async () => {
  await requestJson("/api/admin/logout", { method: "POST", body: "{}" }).catch(() => {});
  showAdmin(false);
  setStatus("已退出。");
});

copyForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const payload = Object.fromEntries(new FormData(copyForm).entries());
  const config = await requestJson("/api/admin/config", {
    method: "POST",
    body: JSON.stringify(payload),
  });

  setStatus({ message: "页面文案已保存。", config });
});

apiKeyForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const keys = {};

  for (const [key, value] of new FormData(apiKeyForm).entries()) {
    if (String(value).trim()) {
      keys[key] = String(value).trim();
    }
  }

  if (!Object.keys(keys).length) {
    setStatus("没有填写新的 API Key。");
    return;
  }

  const result = await requestJson("/api/admin/api-keys", {
    method: "POST",
    body: JSON.stringify({ keys }),
  });
  await loadApiKeys();
  setStatus({ message: "API Key 已保存。", keys: result.keys });
});

async function testProvider(provider) {
  setStatus("正在测试...");
  const result = await requestJson("/api/admin/test-api", {
    method: "POST",
    body: JSON.stringify({ provider, ip: testIp.value.trim() || "8.8.8.8" }),
  });
  setStatus(result);
}

document.querySelector("#testAbuse").addEventListener("click", () => testProvider("abuseipdb").catch((error) => setStatus(error.message)));
document.querySelector("#testIpqs").addEventListener("click", () => testProvider("ipqualityscore").catch((error) => setStatus(error.message)));

(async () => {
  try {
    const session = await requestJson("/api/admin/session");

    if (!session.enabled) {
      setStatus("后台未启用：请先在 .env 中配置 ADMIN_PASSWORD。");
    }

    showAdmin(session.authenticated);

    if (session.authenticated) {
      await refreshAdmin();
    }
  } catch (error) {
    showAdmin(false);
    setStatus(error.message);
  }
})();
