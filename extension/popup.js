const DEFAULT_API_URL = "http://localhost:3000/api/analyze";

const STATUS_CONFIG = {
  Safe: {
    badgeClass: "badge-safe",
    scoreClass: "safe",
    barClass:   "bar-safe",
    msgClass:   "msg-safe",
    symbol:     "✓",
    message:    "This page appears safe. No threats detected.",
  },
  Suspicious: {
    badgeClass: "badge-suspicious",
    scoreClass: "suspicious",
    barClass:   "bar-suspicious",
    msgClass:   "msg-suspicious",
    symbol:     "!",
    message:    "This page looks suspicious. Proceed with caution.",
  },
  Blocked: {
    badgeClass: "badge-blocked",
    scoreClass: "blocked",
    barClass:   "bar-blocked",
    msgClass:   "msg-blocked",
    symbol:     "✕",
    message:    "Dangerous page detected! Avoid entering any information.",
  },
};

function timeAgo(ts) {
  const diff = Math.max(0, Math.floor((Date.now() - ts) / 1000));
  if (diff < 60)   return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  return `${Math.floor(diff / 3600)}h ago`;
}

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls)  e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}

function showLoading(url) {
  const content = document.getElementById("content");
  content.innerHTML = "";
  const wrap = el("div", "loading-wrap");
  wrap.appendChild(el("div", "spinner"));
  wrap.appendChild(el("div", "loading-label", "Scanning…"));
  if (url) wrap.appendChild(el("div", "loading-url", url));
  content.appendChild(wrap);
}

function showSystemPage() {
  const content = document.getElementById("content");
  content.innerHTML = "";
  const wrap = el("div", "no-data");
  wrap.appendChild(el("span", "no-data-icon", "🛡️"));
  wrap.appendChild(el("div", "no-data-title", "PhishGuard Active"));
  wrap.appendChild(el("div", "no-data-sub", "Navigate to any website and PhishGuard will automatically protect you."));
  content.appendChild(wrap);
}

function showError(msg) {
  const content = document.getElementById("content");
  content.innerHTML = "";
  content.appendChild(el("div", "error-msg", msg));
}

function renderResult(score, status, url, timestamp) {
  const cfg = STATUS_CONFIG[status] || STATUS_CONFIG.Safe;
  const content = document.getElementById("content");
  content.innerHTML = "";

  const card = el("div", "score-card");

  // Big score number
  card.appendChild(el("div", `big-score ${cfg.scoreClass}`, `${score}`));
  card.appendChild(el("div", "score-label", "THREAT SCORE"));

  // Status badge
  card.appendChild(el("span", `badge ${cfg.badgeClass}`, `${cfg.symbol} ${status}`));

  // Score bar
  const track = el("div", "bar-track");
  const fill  = el("div", `bar-fill ${cfg.barClass}`);
  fill.style.width = "0%";
  track.appendChild(fill);
  card.appendChild(track);

  // Status message
  card.appendChild(el("div", `status-msg ${cfg.msgClass}`, cfg.message));

  // URL + time
  const meta = el("div", "meta");
  meta.appendChild(el("div", "url-text", url));
  if (timestamp) {
    meta.appendChild(el("div", "time-text", `Scanned ${timeAgo(timestamp)}`));
  }
  card.appendChild(meta);

  content.appendChild(card);

  // Animate bar after paint
  requestAnimationFrame(() => {
    fill.style.width = `${Math.min(100, Math.max(0, score))}%`;
  });
}

/* ── Main ── */
async function init() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const currentUrl = tab?.url;

  const isSystemPage = !currentUrl ||
    currentUrl.startsWith("chrome://") ||
    currentUrl.startsWith("chrome-extension://") ||
    currentUrl.startsWith("about:") ||
    currentUrl.startsWith("edge://") ||
    currentUrl.startsWith("data:") ||
    currentUrl.startsWith("file:");

  if (isSystemPage) {
    showSystemPage();
    return;
  }

  // Check session cache — reuse result if < 5 minutes old for same URL
  const { lastResult } = await chrome.storage.session.get("lastResult");
  const isFresh = lastResult &&
                  lastResult.url === currentUrl &&
                  (Date.now() - lastResult.timestamp) < 5 * 60 * 1000;

  if (isFresh) {
    renderResult(lastResult.score, lastResult.status, lastResult.url, lastResult.timestamp);
    return;
  }

  // Need a fresh scan
  showLoading(currentUrl);

  try {
    const { apiUrl } = await chrome.storage.local.get({ apiUrl: DEFAULT_API_URL });
    const res = await fetch(apiUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: currentUrl }),
    });

    if (!res.ok) {
      showError(`Backend returned ${res.status}. Is the server running?`);
      return;
    }

    const data = await res.json();

    // Cache result
    await chrome.storage.session.set({
      lastResult: {
        url:       currentUrl,
        score:     data.score,
        status:    data.status,
        timestamp: Date.now(),
        breakdown: data.breakdown ?? null,
        virusTotal: data.virusTotal ?? null,
      },
    });

    renderResult(data.score, data.status, currentUrl, Date.now());
  } catch {
    showError("Cannot reach backend. Make sure the server is running on localhost:3000.");
  }
}

init();

/* ── Settings ── */
chrome.storage.local.get({ apiUrl: DEFAULT_API_URL }, ({ apiUrl }) => {
  const input = document.getElementById("api-url");
  if (input) input.value = apiUrl;
});

document.getElementById("save-api-url").addEventListener("click", async () => {
  const input = document.getElementById("api-url");
  const state = document.getElementById("save-state");
  const value = input.value.trim();
  try {
    const parsed = new URL(value);
    if (!["http:", "https:"].includes(parsed.protocol)) throw new Error();
    await chrome.storage.local.set({ apiUrl: value });
    state.textContent = "✓ Saved";
    state.className = "save-state";
    setTimeout(() => { state.textContent = ""; }, 2000);
  } catch {
    state.textContent = "⚠ Enter a valid HTTP(S) URL";
    state.className = "save-state error";
  }
});
