export interface StructureResult {
  score: number;
  flags: string[];
}

const SUSPICIOUS_KEYWORDS = ["login", "verify", "secure", "update", "free"];
const IP_REGEX = /^(\d{1,3}\.){3}\d{1,3}$/;

export function analyzeStructure(url: string): StructureResult {
  const flags: string[] = [];
  let score = 0;

  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return { score: 30, flags: ["Invalid or malformed URL"] };
  }

  // Check for @ symbol in URL (credential phishing trick)
  if (url.includes("@")) {
    score += 20;
    flags.push("Contains '@' symbol");
  }

  // Check for excessive subdomains (dot count > 3)
  const hostname = parsed.hostname;
  const dotCount = (hostname.match(/\./g) || []).length;
  if (dotCount > 3) {
    score += 15;
    flags.push(`Excessive subdomains (${dotCount} dots)`);
  }

  // Check for IP address as hostname
  if (IP_REGEX.test(hostname)) {
    score += 25;
    flags.push("IP address used as hostname");
  }

  // Check for suspicious keywords in full URL
  const lowerUrl = url.toLowerCase();
  let keywordScore = 0;
  for (const keyword of SUSPICIOUS_KEYWORDS) {
    if (lowerUrl.includes(keyword)) {
      keywordScore += 10;
      flags.push(`Suspicious keyword: "${keyword}"`);
    }
  }
  score += Math.min(keywordScore, 40);

  // Penalize very long URLs
  if (url.length > 100) {
    score += 5;
    flags.push("Unusually long URL");
  }

  return { score, flags };
}
