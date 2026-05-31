"use client";

import { useState } from "react";

type Status = "Safe" | "Suspicious" | "Blocked";

interface Breakdown {
  structure: { score: number; flags: string[] };
  domainAge: { score: number; ageMonths: number | null; error?: string };
  blacklist: { score: number; blacklisted: boolean; source: string; error?: string };
  virusTotal: { score: number; malicious: number; total: number; error?: string };
  visualSimilarity: { score: number; matchedBrand: string | null; attackType: string | null; error?: string; };
}

interface AnalysisResult {
  score: number;
  status: Status;
  normalizedUrl: string;
  analyzedAt: string;
  breakdown: Breakdown;
}


const STATUS_CONFIG = {
  Safe: { symbol: "OK", badgeClass: "badge-safe", fillClass: "score-fill-safe", label: "Safe", tone: "#34d399" },
  Suspicious: { symbol: "!", badgeClass: "badge-suspicious", fillClass: "score-fill-suspicious", label: "Suspicious", tone: "#fbbf24" },
  Blocked: { symbol: "X", badgeClass: "badge-blocked", fillClass: "score-fill-blocked", label: "Blocked", tone: "#f87171" },
} satisfies Record<Status, { symbol: string; badgeClass: string; fillClass: string; label: string; tone: string }>;

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
          <p className="muted">Scanning URL structure, domain age, blacklist sources, VirusTotal engines, and brand impersonation.</p>
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
            <BreakdownRow
            label="VirusTotal Scan"
            score={result.breakdown.virusTotal.score}
            detail={
              result.breakdown.virusTotal.error
                ? `Skipped: ${result.breakdown.virusTotal.error}`
                : result.breakdown.virusTotal.malicious > 0
                  ? `Flagged by ${result.breakdown.virusTotal.malicious}/${result.breakdown.virusTotal.total} antivirus engines`
                  : `Clean — 0/${result.breakdown.virusTotal.total} engines flagged`
              }
            />
            <BreakdownRow
              label="Brand Impersonation" 
              score={result.breakdown.visualSimilarity.score}
              detail={
                result.breakdown.visualSimilarity.error
                  ? `Skipped: ${result.breakdown.visualSimilarity.error}`
                  : result.breakdown.visualSimilarity.matchedBrand
                    ? `${result.breakdown.visualSimilarity.attackType} — impersonates ${result.breakdown.visualSimilarity.matchedBrand}`
                    : "No brand impersonation detected"
              }
            />
          </div>
        </section>
      )}

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
