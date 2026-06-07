"use client";

import { useState } from "react";

type Status = "Safe" | "Suspicious" | "Blocked";

interface Breakdown {
  structure?: { score: number; flags: string[] };
  domainAge?: { score: number; ageMonths: number | null; error?: string };
  blacklist?: { score: number; blacklisted: boolean; source: string; error?: string };
  virusTotal?: { score: number; malicious: number; total: number; error?: string };
  visualSimilarity?: { score: number; matchedBrand: string | null; attackType: string | null; error?: string };
}

interface AnalysisResult {
  score: number;
  status: Status;
  normalizedUrl: string;
  analyzedAt: string;
  breakdown: Breakdown;
}

const STATUS_CONFIG = {
  Safe: {
    symbol: "✓",
    badgeClass: "badge-safe",
    fillClass: "score-fill-safe",
    label: "Safe",
    tone: "#34d399",
    description: "This URL appears to be safe. No significant threats were detected.",
    bgGlow: "rgba(16, 185, 129, 0.06)",
  },
  Suspicious: {
    symbol: "!",
    badgeClass: "badge-suspicious",
    fillClass: "score-fill-suspicious",
    label: "Suspicious",
    tone: "#fbbf24",
    description: "This URL shows suspicious characteristics. Proceed with caution.",
    bgGlow: "rgba(245, 158, 11, 0.06)",
  },
  Blocked: {
    symbol: "✕",
    badgeClass: "badge-blocked",
    fillClass: "score-fill-blocked",
    label: "Blocked",
    tone: "#f87171",
    description: "This URL is flagged as dangerous. Do not proceed.",
    bgGlow: "rgba(239, 68, 68, 0.06)",
  },
} satisfies Record<Status, { symbol: string; badgeClass: string; fillClass: string; label: string; tone: string; description: string; bgGlow: string }>;

const BREAKDOWN_ICONS: Record<string, string> = {
  structure: "🔗",
  domainAge: "📅",
  blacklist: "🛡️",
  virusTotal: "🦠",
  visualSimilarity: "👁️",
};

function formatDate(iso: string) {
  return new Date(iso).toLocaleTimeString("en-US", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

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
      {/* ── Hero ── */}
      <section className="hero">
        <div className="hero-badge">
          <span className="dot" />
          Real-time Protection
        </div>
        <h1>PhishGuard</h1>
        <p>
          Advanced phishing URL detection powered by multi-engine analysis —
          structure, domain age, blacklists, VirusTotal, and brand impersonation.
        </p>
        <div className="hero-stats">
          <div className="stat">
            <span className="stat-num">5+</span>
            <span className="stat-label">Detection Engines</span>
          </div>
          <div className="stat-divider" />
          <div className="stat">
            <span className="stat-num">90+</span>
            <span className="stat-label">AV Vendors</span>
          </div>
          <div className="stat-divider" />
          <div className="stat">
            <span className="stat-num">Real-time</span>
            <span className="stat-label">Analysis</span>
          </div>
        </div>
      </section>

      {/* ── Input Panel ── */}
      <section className="panel input-panel" aria-label="URL analyzer">
        <form onSubmit={handleSubmit} className="url-form">
          <div className="input-label-row">
            <svg className="label-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/>
              <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>
            </svg>
            <label htmlFor="url-input">Enter URL to analyze</label>
          </div>
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
              {loading ? "Analyzing…" : "Analyze →"}
            </button>
          </div>
        </form>
      </section>

      {/* ── Loading ── */}
      {loading && (
        <section className="panel" aria-live="polite">
          <div className="loading-panel">
            <div className="spinner-container">
              <div className="spinner" />
              <div className="spinner-inner" />
            </div>
            <div>
              <p className="loading-title">Analyzing URL…</p>
            </div>
            <div className="loading-steps">
              {[
                "Checking URL structure & patterns",
                "Verifying domain age via WHOIS",
                "Querying Google Safe Browsing",
                "Running VirusTotal multi-engine scan",
                "Detecting brand impersonation",
              ].map((step, i) => (
                <div key={i} className="loading-step">
                  <span className="step-dot" />
                  {step}
                </div>
              ))}
            </div>
          </div>
        </section>
      )}

      {/* ── Error ── */}
      {error && !loading && (
        <section className="panel error-panel" aria-live="polite">
          <div className="error-icon">✕</div>
          <div className="error-content">
            <strong>Analysis failed</strong>
            <p>{error}</p>
          </div>
        </section>
      )}

      {/* ── Result ── */}
      {result && cfg && !loading && (
        <section
          className="panel result-panel"
          aria-live="polite"
          style={{ borderColor: `color-mix(in srgb, ${cfg.tone} 25%, rgba(99,179,237,0.13))` }}
        >
          {/* Header */}
          <div className="result-header">
            <div className="result-header-left">
              <span className={`status-badge ${cfg.badgeClass}`}>
                <span aria-hidden="true">{cfg.symbol}</span>
                {cfg.label}
              </span>
              <p style={{ margin: 0, fontSize: "0.88rem", color: "var(--text-secondary)" }}>
                {cfg.description}
              </p>
            </div>
            <div style={{ textAlign: "right", flexShrink: 0 }}>
              <div className="checked-url">
                {result.normalizedUrl}
              </div>
              <div className="analyzed-at" style={{ marginTop: 4 }}>
                Analyzed at {formatDate(result.analyzedAt)}
              </div>
            </div>
          </div>

          {/* Score */}
          <div className="score-block">
            <div className="score-row">
              <div className="score-label-group">
                <span className="label">Threat Score</span>
                <span className="sublabel">
                  {result.score < 40 ? "Low risk" : result.score < 70 ? "Moderate risk" : "High risk"}
                </span>
              </div>
              <div className="score-num-group">
                <strong style={{ color: cfg.tone }}>
                  {result.score}<small>/100</small>
                </strong>
              </div>
            </div>
            <div className="score-track" aria-hidden="true">
              <div
                className={`score-fill ${cfg.fillClass}`}
                style={{ width: `${result.score}%` }}
              />
            </div>
          </div>

          {/* Breakdown */}
          <div className="breakdown">
            <div className="breakdown-header">
              <h2>Detection Breakdown</h2>
              <div className="header-line" />
            </div>

            <BreakdownRow
              icon={BREAKDOWN_ICONS.structure}
              label="URL Structure"
              score={result.breakdown.structure?.score ?? 0}
              detail={
                (result.breakdown.structure?.flags?.length ?? 0) > 0
                  ? result.breakdown.structure!.flags.join(" · ")
                  : "No suspicious URL patterns detected"
              }
            />
            <BreakdownRow
              icon={BREAKDOWN_ICONS.domainAge}
              label="Domain Age"
              score={result.breakdown.domainAge?.score ?? 0}
              detail={
                result.breakdown.domainAge?.error
                  ? `Skipped: ${result.breakdown.domainAge.error}`
                  : result.breakdown.domainAge?.ageMonths != null
                    ? `Domain registered ${result.breakdown.domainAge.ageMonths} months ago`
                    : "Domain age unavailable"
              }
            />
            <BreakdownRow
              icon={BREAKDOWN_ICONS.blacklist}
              label="Blacklist Check"
              score={result.breakdown.blacklist?.score ?? 0}
              detail={
                result.breakdown.blacklist?.blacklisted
                  ? `⚠ Listed as malicious by ${result.breakdown.blacklist.source}`
                  : result.breakdown.blacklist?.error
                    ? `${result.breakdown.blacklist.error} · Source: ${result.breakdown.blacklist.source}`
                    : `Clean · Source: ${result.breakdown.blacklist?.source ?? "unknown"}`
              }
            />
            <BreakdownRow
              icon={BREAKDOWN_ICONS.virusTotal}
              label="VirusTotal Scan"
              score={result.breakdown.virusTotal?.score ?? 0}
              detail={
                result.breakdown.virusTotal?.error
                  ? `Skipped: ${result.breakdown.virusTotal.error}`
                  : (result.breakdown.virusTotal?.malicious ?? 0) > 0
                    ? `⚠ Flagged by ${result.breakdown.virusTotal!.malicious}/${result.breakdown.virusTotal!.total} antivirus engines`
                    : `Clean — 0/${result.breakdown.virusTotal?.total ?? 0} engines flagged`
              }
            />
            <BreakdownRow
              icon={BREAKDOWN_ICONS.visualSimilarity}
              label="Brand Impersonation"
              score={result.breakdown.visualSimilarity?.score ?? 0}
              detail={
                result.breakdown.visualSimilarity?.error
                  ? `Skipped: ${result.breakdown.visualSimilarity.error}`
                  : result.breakdown.visualSimilarity?.matchedBrand
                    ? `⚠ ${result.breakdown.visualSimilarity.attackType} — impersonates ${result.breakdown.visualSimilarity.matchedBrand}`
                    : "No brand impersonation detected"
              }
            />
          </div>
        </section>
      )}

      {/* ── Footer ── */}
      <footer>
        <div className="footer-brand">
          <span>PG</span>
          PhishGuard
        </div>
        <div style={{ color: "var(--muted)", fontSize: "0.78rem" }}>
          Information Security Project · 4th Semester · 2026
        </div>
        <div className="footer-links">
          <a href="https://www.virustotal.com" target="_blank" rel="noopener noreferrer">VirusTotal</a>
          <a href="https://safebrowsing.google.com" target="_blank" rel="noopener noreferrer">Safe Browsing</a>
        </div>
      </footer>
    </main>
  );
}

interface BreakdownRowProps {
  icon: string;
  label: string;
  score: number;
  detail: string;
}

function BreakdownRow({ icon, label, score, detail }: BreakdownRowProps) {
  const chipClass =
    score === 0 ? "score-chip score-safe"
    : score < 25 ? "score-chip score-warning"
    : "score-chip score-danger";

  const chipLabel = score === 0 ? "Clean" : `+${score}`;

  return (
    <div className="breakdown-row">
      <div className="breakdown-row-left">
        <div className="breakdown-icon">{icon}</div>
        <div className="breakdown-text">
          <h3>{label}</h3>
          <p title={detail}>{detail}</p>
        </div>
      </div>
      <span className={chipClass}>{chipLabel}</span>
    </div>
  );
}
