import { StructureResult } from "./structureAnalyzer";
import { DomainAgeResult } from "./domainAgeChecker";
import { BlacklistResult } from "./blacklistChecker";

export type Status = "Safe" | "Suspicious" | "Blocked";

export interface VirusTotalResult {
  malicious:  number;
  suspicious?: number;
  harmless?:  number;
  total:      number;
  error?:     string;
}

export interface BrandImpersonationResult {
  score:        number;
  matchedBrand: string | null;
  attackType:   string | null;
  error?:       string;
}

export interface AnalysisBreakdown {
  structure:        { score: number; flags: string[] };
  domainAge:        { score: number; ageMonths: number | null; error?: string };
  blacklist:        { score: number; blacklisted: boolean; source: string; error?: string };
  virusTotal:       { score: number; malicious: number; total: number; error?: string };
  visualSimilarity: { score: number; matchedBrand: string | null; attackType: string | null; error?: string };
}

export interface ScoreResult {
  score:    number;
  status:   Status;
  breakdown: AnalysisBreakdown;
}

function clamp(n: number, min: number, max: number) {
  return Math.max(min, Math.min(max, n));
}

export function calculateScore(
  structure:        StructureResult,
  domainAge:        DomainAgeResult,
  blacklist:        BlacklistResult,
  virusTotal:       VirusTotalResult,
  visualSimilarity: BrandImpersonationResult
): ScoreResult {
  // VirusTotal contribution: 5 pts per malicious engine, capped at 40
  const vtScore = virusTotal.error
    ? 0
    : clamp(virusTotal.malicious * 5, 0, 40);

  const raw   = structure.score + domainAge.score + blacklist.score + vtScore + visualSimilarity.score;
  const score = clamp(raw, 0, 100);

  let status: Status;

  // Google Safe Browsing / local deny-list hit → always Blocked, no matter the combined score
  if (blacklist.blacklisted) {
    status = "Blocked";
  } else if (score >= 70) {
    status = "Blocked";
  } else if (score >= 40) {
    status = "Suspicious";
  } else {
    status = "Safe";
  }

  return {
    score,
    status,
    breakdown: {
      structure:        { score: structure.score,        flags: structure.flags },
      domainAge:        { score: domainAge.score,        ageMonths: domainAge.ageMonths,       error: domainAge.error },
      blacklist:        { score: blacklist.score,        blacklisted: blacklist.blacklisted,   source: blacklist.source, error: blacklist.error },
      virusTotal:       { score: vtScore,                malicious: virusTotal.malicious,      total: virusTotal.total,  error: virusTotal.error },
      visualSimilarity: { score: visualSimilarity.score, matchedBrand: visualSimilarity.matchedBrand, attackType: visualSimilarity.attackType, error: visualSimilarity.error },
    },
  };
}
