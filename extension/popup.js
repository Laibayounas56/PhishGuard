const STATUS_CONFIG = {
  Safe:       { badgeClass: "badge-safe",        fillClass: "fill-safe",        scoreClass: "safe",        symbol: "✓" },
  Suspicious: { badgeClass: "badge-suspicious",   fillClass: "fill-suspicious",   scoreClass: "suspicious",   symbol: "!" },
  Blocked:    { badgeClass: "badge-blocked",      fillClass: "fill-blocked",      scoreClass: "blocked",      symbol: "✕" },
};

const DEFAULT_API_URL = "http://localhost:3000/api/analyze";

const BREAKDOWN_META = [
  { key: "structure",        icon: "🔗", label: "URL Structure" },
  { key: "domainAge",        icon: "📅", label: "Domain Age" },
  { key: "blacklist",        icon: "🛡️", label: "Blacklist" },
  { key: "virusTotal",       icon: "🦠", label: "VirusTotal" },
  { key: "visualSimilarity", icon: "👁️", label: "Brand Impersonation" },
];

function timeAgo(ts) {
  const diff = Math.max(0, Math.floor((Date.now() - ts) / 1000));
  if (diff < 60)   return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  return `${Math.floor(diff / 3600)}h ago`;
}

function el(tag, className, text) {
  const e = document.createElement(tag);
  if (className) e.className = className;
  if (text !== undefined) e.textContent = text;
  return e;
}

/** Returns a human-readable detail string for each breakdown section */
function breakdownDetail(key, data) {
  if (!data) return "No data";
  switch (key) {
    case "structure":
      return data.flags && data.flags.length
        ? data.flags.join(" · ")
        : "No suspicious patterns";
    case "domainAge":
      if (data.error) return `Skipped: ${data.error}`;
      if (data.ageMonths !== null && data.ageMonths !== undefined)
        return `Domain is ${data.ageMonths} months old`;
      return "Age unavailable";
    case "blacklist":
      if (data.blacklisted) return `Listed by ${data.source}`;
      if (data.error)       return `${data.error} · ${data.source}`;
      return `Clean · ${data.source}`;
    case "virusTotal":
      if (data.error) return `Skipped: ${data.error}`;
      if (data.malicious > 0) return `Flagged by ${data.malicious}/${data.total} engines`;
      return `Clean — 0/${data.total} engines`;
    case "visualSimilarity":
      if (data.error)          return `Skipped: ${data.error}`;
      if (data.matchedBrand)   return `${data.attackType} — impersonates ${data.matchedBrand}`;
      return "No brand impersonation";
    default:
      return "";
  }
}

/** Returns chip class based on score */
function chipClass(score) {
  if (score === 0)  return "bd-chip chip-safe";
  if (score < 25)   return "bd-chip chip-warn";
  return "bd-chip chip-danger";
}

chrome.storage.session.get("lastResult", ({ lastResult }) => {
  if (!lastResult) return;

  const cfg = STATUS_CONFIG[lastResult.status];
  if (!cfg) return;

  const content = document.getElementById("content");
  content.textContent = "";

  /* ── Result Card ── */
  const card = el("div", "result-card");

  const top = el("div", "result-top");
  top.appendChild(el("span", `badge ${cfg.badgeClass}`, `${cfg.symbol} ${lastResult.status}`));
  top.appendChild(el("span", `score-num ${cfg.scoreClass}`, `${lastResult.score}/100`));
  card.appendChild(top);

  const track = el("div", "score-track");
  const fill  = el("div", `score-fill ${cfg.fillClass}`);
  fill.style.width = "0%";
  track.appendChild(fill);
  card.appendChild(track);

  const bottom = el("div", "result-bottom");
  bottom.appendChild(el("div", "url-text", lastResult.url));
  bottom.appendChild(el("div", "time-text", `Scanned ${timeAgo(lastResult.timestamp)}`));
  card.appendChild(bottom);

  content.appendChild(card);

  /* ── Breakdown Section ── */
  const bd = lastResult.breakdown;
  if (bd) {
    const section = el("div", "breakdown-section");

    // Heading
    const heading = el("div", "breakdown-heading");
    heading.appendChild(el("span", null, "Detection Breakdown"));
    heading.appendChild(el("div", "hline"));
    section.appendChild(heading);

    // One row per engine
    for (const { key, icon, label } of BREAKDOWN_META) {
      const data  = bd[key];
      const score = data?.score ?? 0;
      const detail = breakdownDetail(key, data);
      const chipLabel = score === 0 ? "Clean" : `+${score}`;

      const row = el("div", "bd-row");

      const iconEl = el("div", "bd-icon", icon);
      row.appendChild(iconEl);

      const text = el("div", "bd-text");
      text.appendChild(el("div", "bd-label", label));
      const detailEl = el("div", "bd-detail");
      detailEl.textContent = detail;
      detailEl.title = detail;
      text.appendChild(detailEl);
      row.appendChild(text);

      row.appendChild(el("span", chipClass(score), chipLabel));
      section.appendChild(row);
    }

    content.appendChild(section);
  }

  /* Animate score bar */
  requestAnimationFrame(() => {
    fill.style.width = `${Math.min(100, Math.max(0, lastResult.score))}%`;
  });
});

/* Load saved API URL */
chrome.storage.local.get({ apiUrl: DEFAULT_API_URL }, ({ apiUrl }) => {
  const input = document.getElementById("api-url");
  if (input) input.value = apiUrl;
});

/* Save API URL */
document.getElementById("save-api-url").addEventListener("click", async () => {
  const input = document.getElementById("api-url");
  const state = document.getElementById("save-state");
  const value = input.value.trim();

  try {
    const parsed = new URL(value);
    if (!["http:", "https:"].includes(parsed.protocol)) throw new Error("Invalid protocol");
    await chrome.storage.local.set({ apiUrl: value });
    state.textContent = "✓ Saved";
    state.className = "save-state";
    setTimeout(() => { state.textContent = ""; }, 2000);
  } catch {
    state.textContent = "⚠ Enter a valid HTTP(S) URL";
    state.className = "save-state error";
  }
});
