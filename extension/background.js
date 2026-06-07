const DEFAULT_API_URL = "http://localhost:3000/api/analyze";

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
