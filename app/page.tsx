"use client";

import { useState, useEffect, useCallback, useRef } from "react";

// ─── URL Analysis types ───────────────────────────────────────────────────────
type Status = "Safe" | "Suspicious" | "Blocked";

interface Breakdown {
  structure: { score: number; flags: string[] };
  domainAge: { score: number; ageMonths: number | null; error?: string };
  blacklist: { score: number; blacklisted: boolean; source: string; error?: string };
}

interface AnalysisResult {
  score: number;
  status: Status;
  normalizedUrl: string;
  analyzedAt: string;
  breakdown: Breakdown;
}

// ─── Extension Audit types ────────────────────────────────────────────────────
interface ExtensionInfo {
  id: string;
  name: string;
  enabled: boolean;
  version: string;
  permissions: string[];
  score: number;
  riskLevel: "Safe" | "Low Risk" | "Medium Risk" | "High Risk";
  reasons: string[];
  isBlacklisted: boolean;
  iconUrl: string | null;
}

interface AuditSummary {
  total: number;
  highRisk: number;
  mediumRisk: number;
  lowRisk: number;
  safe: number;
  blacklisted: number;
}

interface AuditReport {
  extensions: ExtensionInfo[];
  summary: AuditSummary;
  scannedAt: number;
}

// ─── Config ───────────────────────────────────────────────────────────────────
const STATUS_CONFIG = {
  Safe: { symbol: "OK", badgeClass: "badge-safe", fillClass: "score-fill-safe", label: "Safe", tone: "#34d399" },
  Suspicious: { symbol: "!", badgeClass: "badge-suspicious", fillClass: "score-fill-suspicious", label: "Suspicious", tone: "#fbbf24" },
  Blocked: { symbol: "X", badgeClass: "badge-blocked", fillClass: "score-fill-blocked", label: "Blocked", tone: "#f87171" },
} satisfies Record<Status, { symbol: string; badgeClass: string; fillClass: string; label: string; tone: string }>;

const RISK_BADGE: Record<string, string> = {
  "Safe": "risk-safe",
  "Low Risk": "risk-low",
  "Medium Risk": "risk-medium",
  "High Risk": "risk-high",
};

const SCORE_GRADIENT: Record<string, string> = {
  "Safe":       "linear-gradient(90deg,#10b981,#4ade80)",
  "Low Risk":   "linear-gradient(90deg,#3b82f6,#7dd3fc)",
  "Medium Risk":"linear-gradient(90deg,#f59e0b,#fde047)",
  "High Risk":  "linear-gradient(90deg,#ef4444,#fb7185)",
};

const SCORE_COLOR: Record<string, string> = {
  "Safe":       "#48e3aa",
  "Low Risk":   "#93c5fd",
  "Medium Risk":"#ffd166",
  "High Risk":  "#ff8a8a",
};

// ─── ExtensionCard component ──────────────────────────────────────────────────
function ExtensionCard({ ext }: { ext: ExtensionInfo }) {
  const [open, setOpen] = useState(false);
  const initials = ext.name.slice(0, 2).toUpperCase();

  return (
    <div className={`ext-card${open ? " open" : ""}`}>
      <div className="ext-card-header" onClick={() => setOpen((o) => !o)}>
        <div className="ext-icon-wrap">
          {ext.iconUrl ? (
            <img src={ext.iconUrl} alt={ext.name} />
          ) : (
            initials
          )}
        </div>
        <div className="ext-card-info">
          <div className="ext-card-name">{ext.name}</div>
          <div className="ext-card-meta">
            v{ext.version} · {ext.enabled ? "Enabled" : "Disabled"}
            {ext.isBlacklisted && " · ⛔ Blacklisted"}
          </div>
        </div>
        <span className={`ext-risk-badge ${RISK_BADGE[ext.riskLevel]}`}>
          {ext.riskLevel}
        </span>
        <span className="ext-expand-icon">▼</span>
      </div>

      <div className="ext-card-details">
        {/* Score bar */}
        <div className="ext-score-bar-wrap">
          <div className="ext-score-row">
            <span className="ext-score-label">Risk Score</span>
            <span
              className="ext-score-num"
              style={{ color: SCORE_COLOR[ext.riskLevel] }}
            >
              {ext.score}/100
            </span>
          </div>
          <div className="ext-score-track">
            <div
              className="ext-score-fill"
              style={{
                width: `${ext.score}%`,
                background: SCORE_GRADIENT[ext.riskLevel],
              }}
            />
          </div>
        </div>

        {/* Reasons */}
        {ext.reasons.length > 0 && (
          <div className="ext-detail-section">
            <div className="ext-detail-label">Risk Factors</div>
            <ul className="reason-list">
              {ext.reasons.map((r, i) => (
                <li key={i}>{r}</li>
              ))}
            </ul>
          </div>
        )}

        {/* All permissions */}
        {ext.permissions.length > 0 && (
          <div className="ext-detail-section">
            <div className="ext-detail-label">All Permissions ({ext.permissions.length})</div>
            <ul className="reason-list">
              {ext.permissions.map((p, i) => (
                <li key={i} style={{ fontFamily: "monospace", fontSize: "0.78rem" }}>{p}</li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </div>
  );
}

// ─── AuditPanel component ─────────────────────────────────────────────────────
function AuditPanel() {
  const [extensionDetected, setExtensionDetected] = useState<boolean | null>(null);
  const [report, setReport] = useState<AuditReport | null>(null);
  const [scanning, setScanning] = useState(true);
  const pingTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const triggerScan = useCallback(() => {
    setScanning(true);
    window.postMessage({ source: "PHISHGUARD_PAGE", type: "TRIGGER_EXTENSIONS_SCAN" }, "*");
  }, []);

  useEffect(() => {
    function handleMessage(event: MessageEvent) {
      if (event.source !== window) return;
      const data = event.data;
      if (!data || data.source !== "PHISHGUARD_EXT") return;

      if (data.type === "PHISHGUARD_PONG") {
        setExtensionDetected(true);
        if (pingTimerRef.current) clearTimeout(pingTimerRef.current);
      }

      if (data.type === "PHISHGUARD_EXTENSIONS_REPORT" && data.report) {
        setReport(data.report);
        setScanning(false);
        setExtensionDetected(true);
      }
    }

    window.addEventListener("message", handleMessage);

    // Ping the content script to detect extension
    window.postMessage({ source: "PHISHGUARD_PAGE", type: "PHISHGUARD_PING" }, "*");

    // If no PONG within 2s, extension is not installed / not detected
    pingTimerRef.current = setTimeout(() => {
      setExtensionDetected((prev) => {
        if (prev === null) {
          setScanning(false);
          return false;
        }
        return prev;
      });
    }, 2000);

    return () => {
      window.removeEventListener("message", handleMessage);
      if (pingTimerRef.current) clearTimeout(pingTimerRef.current);
    };
  }, []);

  const highRiskExts = report?.extensions.filter((e) => e.riskLevel === "High Risk") ?? [];

  return (
    <section className="audit-panel" aria-label="Extension Security Audit">
      {/* Header */}
      <div className="audit-header">
        <div className="audit-title-row">
          <div className="audit-icon" aria-hidden="true">🛡️</div>
          <div>
            <h2 className="audit-title">Extension Security Audit</h2>
            <p className="audit-subtitle">
              {report
                ? `Last scanned ${new Date(report.scannedAt).toLocaleTimeString()}`
                : "Scans all installed Chrome extensions for risks"}
            </p>
          </div>
        </div>
        {extensionDetected && (
          <button
            id="audit-rescan-btn"
            className={`rescan-btn${scanning ? " spinning" : ""}`}
            onClick={triggerScan}
            disabled={scanning}
            type="button"
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
              <path d="M21 2v6h-6" /><path d="M3 12a9 9 0 0 1 15-6.7L21 8" />
              <path d="M3 22v-6h6" /><path d="M21 12a9 9 0 0 1-15 6.7L3 16" />
            </svg>
            {scanning ? "Scanning…" : "Re-scan"}
          </button>
        )}
      </div>

      {/* States */}
      {extensionDetected === null || (extensionDetected && scanning && !report) ? (
        <div className="audit-loading" aria-live="polite">
          <div className="audit-spinner" />
          Detecting PhishGuard extension…
        </div>
      ) : extensionDetected === false ? (
        <div className="audit-not-installed">
          <div className="audit-ni-icon">🔌</div>
          <h3>Extension Not Detected</h3>
          <p>
            Load the <strong>PhishGuard</strong> Chrome extension in developer mode
            (chrome://extensions → Load unpacked → select the <code>/extension</code> folder),
            then refresh this page to run an Extension Security Audit.
          </p>
        </div>
      ) : report ? (
        <>
          {/* Stats bar */}
          <div className="audit-stats">
            <div className="audit-stat">
              <span className="audit-stat-num stat-total">{report.summary.total}</span>
              <span className="audit-stat-label">Total</span>
            </div>
            <div className="audit-stat">
              <span className="audit-stat-num stat-high">{report.summary.highRisk}</span>
              <span className="audit-stat-label">High Risk</span>
            </div>
            <div className="audit-stat">
              <span className="audit-stat-num stat-medium">{report.summary.mediumRisk}</span>
              <span className="audit-stat-label">Medium Risk</span>
            </div>
            <div className="audit-stat">
              <span className="audit-stat-num stat-low">{report.summary.lowRisk}</span>
              <span className="audit-stat-label">Low Risk</span>
            </div>
            <div className="audit-stat">
              <span className="audit-stat-num stat-safe">{report.summary.safe}</span>
              <span className="audit-stat-label">Safe</span>
            </div>
          </div>

          {/* High-risk alert banners */}
          {highRiskExts.length > 0 && (
            <div className="audit-alerts" aria-live="polite">
              {highRiskExts.map((ext) => (
                <div key={ext.id} className="audit-alert">
                  <span className="audit-alert-icon">⚠️</span>
                  <div className="audit-alert-body">
                    <strong>
                      {ext.isBlacklisted ? "⛔ Suspicious Extension Detected" : "High-Risk Extension Detected"}: {ext.name}
                    </strong>
                    <p>Risk Score: {ext.score}/100 · {ext.reasons.join(" · ")}</p>
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* Extension list */}
          {report.extensions.length === 0 ? (
            <div className="audit-loading">
              <span>✅</span> No other extensions found.
            </div>
          ) : (
            <div className="audit-list">
              {report.extensions.map((ext) => (
                <ExtensionCard key={ext.id} ext={ext} />
              ))}
            </div>
          )}
        </>
      ) : null}
    </section>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────────
export default function Home() {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!url.trim()) return;

    setLoading(true);
    setResult(null);
    setError(null);

    try {
      const res = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: url.trim() }),
      });
      const data = await res.json();

      if (!res.ok) {
        setError(data.error || "Analysis failed. Please try again.");
        return;
      }

      setResult(data);
    } catch {
      setError("Could not reach the analysis server. Please try again.");
    } finally {
      setLoading(false);
    }
  }

  const cfg = result ? STATUS_CONFIG[result.status] : null;

  return (
    <main className="app-shell">
      <section className="hero">
        <div className="mark" aria-hidden="true">PG</div>
        <h1>PhishGuard</h1>
        <p>Real-time phishing URL detection for manual checks and Chrome navigation protection.</p>
      </section>

      <section className="panel input-panel" aria-label="URL analyzer">
        <form onSubmit={handleSubmit} className="url-form">
          <label htmlFor="url-input">URL to analyze</label>
          <div className="input-row">
            <input
              id="url-input"
              type="url"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://example.com/login"
              autoComplete="off"
              spellCheck={false}
            />
            <button type="submit" disabled={loading || !url.trim()}>
              {loading ? "Analyzing..." : "Analyze"}
            </button>
          </div>
        </form>
      </section>

      {loading && (
        <section className="panel result-panel" aria-live="polite">
          <div className="spinner" />
          <p className="muted">Scanning URL structure, domain age, and blacklist sources.</p>
        </section>
      )}

      {error && !loading && (
        <section className="panel error-panel" aria-live="polite">
          <strong>Analysis error</strong>
          <p>{error}</p>
        </section>
      )}

      {result && cfg && !loading && (
        <section className="panel result-panel" aria-live="polite">
          <div className="result-header">
            <span className={`status-badge ${cfg.badgeClass}`}>
              <span aria-hidden="true">{cfg.symbol}</span>
              {cfg.label}
            </span>
            <span className="checked-url">{result.normalizedUrl}</span>
          </div>

          <div className="score-block">
            <div className="score-row">
              <span>Threat score</span>
              <strong style={{ color: cfg.tone }}>
                {result.score}<small>/100</small>
              </strong>
            </div>
            <div className="score-track" aria-hidden="true">
              <div className={`score-fill ${cfg.fillClass}`} style={{ width: `${result.score}%` }} />
            </div>
          </div>

          <div className="breakdown">
            <h2>Detection breakdown</h2>
            <BreakdownRow
              label="URL structure"
              score={result.breakdown.structure.score}
              detail={
                result.breakdown.structure.flags.length
                  ? result.breakdown.structure.flags.join(" | ")
                  : "No suspicious URL patterns detected"
              }
            />
            <BreakdownRow
              label="Domain age"
              score={result.breakdown.domainAge.score}
              detail={
                result.breakdown.domainAge.error
                  ? `Skipped: ${result.breakdown.domainAge.error}`
                  : result.breakdown.domainAge.ageMonths !== null
                    ? `Domain is ${result.breakdown.domainAge.ageMonths} months old`
                    : "Domain age unavailable"
              }
            />
            <BreakdownRow
              label="Blacklist"
              score={result.breakdown.blacklist.score}
              detail={
                result.breakdown.blacklist.blacklisted
                  ? `Listed as malicious by ${result.breakdown.blacklist.source}`
                  : result.breakdown.blacklist.error
                    ? `${result.breakdown.blacklist.error} | Source: ${result.breakdown.blacklist.source}`
                    : `No listing found | Source: ${result.breakdown.blacklist.source}`
              }
            />
          </div>
        </section>
      )}

      {/* Extension Security Audit — always visible */}
      <AuditPanel />

      <footer>PhishGuard | IS Security Project | 2026</footer>
    </main>
  );
}

function BreakdownRow({ label, score, detail }: { label: string; score: number; detail: string }) {
  return (
    <div className="breakdown-row">
      <div>
        <h3>{label}</h3>
        <p>{detail}</p>
      </div>
      <strong className={score === 0 ? "score-safe" : score < 25 ? "score-warning" : "score-danger"}>
        +{score}
      </strong>
    </div>
  );
}
