const DEFAULT_API_URL = "http://localhost:3000/api/analyze";

// ─── Risky permissions and weights ────────────────────────────────────────────
const RISKY_PERMISSIONS = {
  history:      { score: 20, label: "Accesses browsing history" },
  cookies:      { score: 20, label: "Accesses browser cookies" },
  webRequest:   { score: 15, label: "Intercepts network requests" },
  tabs:         { score: 10, label: "Reads all open tab URLs" },
  downloads:    { score: 10, label: "Manages file downloads" },
  clipboardRead:{ score: 15, label: "Reads clipboard content" },
  bookmarks:    { score: 10, label: "Accesses bookmarks" },
  geolocation:  { score: 10, label: "Accesses your location" },
  notifications:{ score: 5,  label: "Shows notifications" },
  nativeMessaging:{ score: 20, label: "Communicates with native apps" },
  identity:     { score: 15, label: "Accesses account identity" },
  proxy:        { score: 20, label: "Controls proxy settings" },
  debugger:     { score: 25, label: "Attaches a debugger to browser" },
  webRequestBlocking: { score: 20, label: "Blocks/modifies network requests" },
};

// ─── Risk classification ───────────────────────────────────────────────────────
function classifyRisk(score) {
  if (score === 0) return "Safe";
  if (score <= 20) return "Low Risk";
  if (score <= 50) return "Medium Risk";
  return "High Risk";
}

// ─── Fetch and cache the blacklist ────────────────────────────────────────────
let cachedBlacklist = null;
async function getBlacklist() {
  if (cachedBlacklist) return cachedBlacklist;
  try {
    const url = chrome.runtime.getURL("blacklist.json");
    const res = await fetch(url);
    const data = await res.json();
    cachedBlacklist = data.maliciousExtensions || [];
  } catch {
    cachedBlacklist = [];
  }
  return cachedBlacklist;
}

// ─── Core audit logic ─────────────────────────────────────────────────────────
async function analyzeExtensions() {
  return new Promise(async (resolve) => {
    const blacklist = await getBlacklist();
    const myId = chrome.runtime.id;

    chrome.management.getAll((allExtensions) => {
      const results = allExtensions
        .filter((ext) => ext.id !== myId) // exclude self
        .map((ext) => {
          let score = 0;
          const reasons = [];

          // Check blacklist
          const isBlacklisted = blacklist.some(
            (name) => name.toLowerCase() === ext.name.toLowerCase()
          );
          if (isBlacklisted) {
            score += 50;
            reasons.push("⛔ Blacklisted extension");
          }

          // Check permissions
          const perms = ext.permissions || [];
          perms.forEach((perm) => {
            const risk = RISKY_PERMISSIONS[perm];
            if (risk) {
              score += risk.score;
              reasons.push(`⚠ ${risk.label} (${perm})`);
            }
          });

          // Cap at 100
          score = Math.min(100, score);
          const riskLevel = classifyRisk(score);

          return {
            id: ext.id,
            name: ext.name,
            enabled: ext.enabled,
            version: ext.version || "?",
            permissions: perms,
            score,
            riskLevel,
            reasons,
            isBlacklisted,
            iconUrl: ext.icons?.sort((a, b) => b.size - a.size)[0]?.url || null,
          };
        })
        // Sort: highest risk first
        .sort((a, b) => b.score - a.score);

      const summary = {
        total: results.length,
        highRisk: results.filter((e) => e.riskLevel === "High Risk").length,
        mediumRisk: results.filter((e) => e.riskLevel === "Medium Risk").length,
        lowRisk: results.filter((e) => e.riskLevel === "Low Risk").length,
        safe: results.filter((e) => e.riskLevel === "Safe").length,
        blacklisted: results.filter((e) => e.isBlacklisted).length,
      };

      resolve({ extensions: results, summary, scannedAt: Date.now() });
    });
  });
}

// ─── Message listener ─────────────────────────────────────────────────────────
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message.type === "GET_EXTENSIONS_AUDIT") {
    analyzeExtensions().then((report) => {
      sendResponse({ success: true, report });
    });
    return true; // keep channel open for async
  }
});

// ─── Existing URL scanning logic ──────────────────────────────────────────────
function shouldSkip(url) {
  return (
    !url ||
    url.startsWith("chrome://") ||
    url.startsWith("chrome-extension://") ||
    url.startsWith("about:") ||
    url.startsWith("edge://") ||
    url.startsWith("data:") ||
    url.startsWith("file:")
  );
}

async function analyzeUrl(url) {
  try {
    const { apiUrl } = await chrome.storage.local.get({ apiUrl: DEFAULT_API_URL });
    const res = await fetch(apiUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });

    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

async function rememberResult(url, result) {
  await chrome.storage.session.set({
    lastResult: {
      url,
      score: result.score,
      status: result.status,
      timestamp: Date.now(),
    },
  });
}

function sendPageMessage(tabId, message) {
  chrome.tabs.sendMessage(tabId, message).catch(() => {
    chrome.scripting.executeScript({
      target: { tabId },
      files: ["content.js"],
    }).then(() => {
      chrome.tabs.sendMessage(tabId, message).catch(() => {});
    }).catch(() => {});
  });
}

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0 || shouldSkip(details.url)) return;

  const result = await analyzeUrl(details.url);
  if (!result) return;

  await rememberResult(details.url, result);

  if (result.status === "Blocked") {
    const blockedUrl = chrome.runtime.getURL(
      `blocked.html?url=${encodeURIComponent(details.url)}&score=${encodeURIComponent(String(result.score))}`
    );
    await chrome.tabs.update(details.tabId, { url: blockedUrl });
    return;
  }

  if (result.status === "Suspicious") {
    setTimeout(() => {
      sendPageMessage(details.tabId, {
        type: "PHISHGUARD_WARNING",
        score: result.score,
        url: details.url,
      });
    }, 700);
    return;
  }

  if (result.status === "Safe") {
    setTimeout(() => {
      sendPageMessage(details.tabId, {
        type: "PHISHGUARD_SAFE",
        score: result.score,
        url: details.url,
      });
    }, 700);
  }
});
