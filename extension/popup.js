const STATUS_CONFIG = {
  Safe: { badgeClass: "badge-safe", fillClass: "fill-safe", scoreClass: "safe", symbol: "OK" },
  Suspicious: { badgeClass: "badge-suspicious", fillClass: "fill-suspicious", scoreClass: "suspicious", symbol: "!" },
  Blocked: { badgeClass: "badge-blocked", fillClass: "fill-blocked", scoreClass: "blocked", symbol: "X" },
};
const DEFAULT_API_URL = "http://localhost:3000/api/analyze";

function timeAgo(ts) {
  const diff = Math.max(0, Math.floor((Date.now() - ts) / 1000));
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  return `${Math.floor(diff / 3600)}h ago`;
}

function appendText(parent, tagName, className, text) {
  const el = document.createElement(tagName);
  if (className) el.className = className;
  el.textContent = text;
  parent.appendChild(el);
  return el;
}

chrome.storage.session.get("lastResult", ({ lastResult }) => {
  if (!lastResult) return;

  const cfg = STATUS_CONFIG[lastResult.status];
  if (!cfg) return;

  const content = document.getElementById("content");
  content.textContent = "";

  const card = document.createElement("div");
  card.className = "result-card";

  const statusRow = document.createElement("div");
  statusRow.className = "status-row";

  appendText(statusRow, "span", `badge ${cfg.badgeClass}`, `${cfg.symbol} ${lastResult.status}`);
  appendText(statusRow, "span", `score-num ${cfg.scoreClass}`, `${lastResult.score}/100`);

  const scoreTrack = document.createElement("div");
  scoreTrack.className = "score-track";
  const bar = document.createElement("div");
  bar.className = `score-fill ${cfg.fillClass}`;
  bar.style.width = "0%";
  scoreTrack.appendChild(bar);

  appendText(card, "div", "url-text", lastResult.url);
  appendText(card, "div", "time-text", `Scanned ${timeAgo(lastResult.timestamp)}`);

  card.insertBefore(scoreTrack, card.firstChild);
  card.insertBefore(statusRow, card.firstChild);
  content.appendChild(card);

  requestAnimationFrame(() => {
    bar.style.width = `${Math.min(100, Math.max(0, lastResult.score))}%`;
  });
});

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
    if (!["http:", "https:"].includes(parsed.protocol)) {
      throw new Error("Invalid protocol");
    }
    await chrome.storage.local.set({ apiUrl: value });
    state.textContent = "Saved";
    setTimeout(() => { state.textContent = ""; }, 1800);
  } catch {
    state.textContent = "Enter a valid HTTP(S) API URL";
  }
});
