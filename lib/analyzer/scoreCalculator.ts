import { StructureResult } from "./structureAnalyzer";
import { DomainAgeResult } from "./domainAgeChecker";
import { BlacklistResult } from "./blacklistChecker";

export type Status = "Safe" | "Suspicious" | "Blocked";

export interface AnalysisBreakdown {
  structure: { score: number; flags: string[] };
  domainAge: { score: number; ageMonths: number | null; error?: string };
  blacklist: { score: number; blacklisted: boolean; source: string; error?: string };
}

export interface ScoreResult {
  score: number;
  status: Status;
  breakdown: AnalysisBreakdown;
}

function clamp(n: number, min: number, max: number) {
  return Math.max(min, Math.min(max, n));
}

export function calculateScore(
  structure: StructureResult,
  domainAge: DomainAgeResult,
  blacklist: BlacklistResult
): ScoreResult {
  const raw = structure.score + domainAge.score + blacklist.score;
  const score = clamp(raw, 0, 100);

  let status: Status;
  if (score >= 70) status = "Blocked";
  else if (score >= 40) status = "Suspicious";
  else status = "Safe";

  return {
    score,
    status,
    breakdown: {
      structure: { score: structure.score, flags: structure.flags },
      domainAge: { score: domainAge.score, ageMonths: domainAge.ageMonths, error: domainAge.error },
      blacklist: { score: blacklist.score, blacklisted: blacklist.blacklisted, source: blacklist.source, error: blacklist.error },
    },
  };
}
