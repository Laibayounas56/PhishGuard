export interface BrandImpersonationResult {
  score: number;
  matchedBrand: string | null;
  attackType: string | null;
  error?: string;
}

const KNOWN_BRANDS = [
  { name: "paypal", domain: "paypal.com" },
  { name: "google", domain: "google.com" },
  { name: "facebook", domain: "facebook.com" },
  { name: "instagram", domain: "instagram.com" },
  { name: "microsoft", domain: "microsoft.com" },
  { name: "apple", domain: "apple.com" },
  { name: "amazon", domain: "amazon.com" },
  { name: "netflix", domain: "netflix.com" },
  { name: "twitter", domain: "twitter.com" },
  { name: "linkedin", domain: "linkedin.com" },
  { name: "dropbox", domain: "dropbox.com" },
  { name: "chase", domain: "chase.com" },
  { name: "wellsfargo", domain: "wellsfargo.com" },
  { name: "bankofamerica", domain: "bankofamerica.com" },
];

const LEET_MAP: Record<string, string> = {
  "0": "o",
  "1": "l",
  "3": "e",
  "4": "a",
  "5": "s",
  "7": "t",
  "@": "a",
  "$": "s",
  "rn": "m",
  "vv": "w",
};

function normalizeLeet(str: string): string {
  let result = str.toLowerCase();
  for (const [leet, normal] of Object.entries(LEET_MAP)) {
    result = result.split(leet).join(normal);
  }
  return result;
}

function extractDomainParts(url: string): string {
  try {
    const hostname = new URL(url).hostname.toLowerCase();
    const withoutWww = hostname.replace(/^www\./, "");
    const withoutTld = withoutWww.replace(/\.[a-z]{2,}$/, "");
    return withoutTld;
  } catch {
    return "";
  }
}

function levenshteinDistance(a: string, b: string): number {
  const matrix: number[][] = [];
  for (let i = 0; i <= b.length; i++) matrix[i] = [i];
  for (let j = 0; j <= a.length; j++) matrix[0][j] = j;

  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b[i - 1] === a[j - 1]) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j] + 1
        );
      }
    }
  }
  return matrix[b.length][a.length];
}

// ✅ Internal function — alag naam "detectBrandMatch"
function detectBrandMatch(url: string): {
  matched: boolean;
  brand: string | null;
  attackType: string | null;
} {
  const domainPart = extractDomainParts(url);
  const normalizedDomain = normalizeLeet(domainPart);
  const fullHostname = new URL(url).hostname.toLowerCase();

  for (const brand of KNOWN_BRANDS) {
    const brandName = brand.name;

    // 1. Direct inclusion check
    if (normalizedDomain.includes(brandName)) {
      if (fullHostname === brand.domain || fullHostname === `www.${brand.domain}`) {
        continue;
      }
      return {
        matched: true,
        brand: brand.domain,
        attackType: "Brand name in domain",
      };
    }

    // 2. Typosquatting check
    const parts = domainPart.split("-");
    for (const part of parts) {
      if (part.length < 4) continue;
      const distance = levenshteinDistance(normalizeLeet(part), brandName);
      const threshold = brandName.length <= 5 ? 1 : 2;
      if (distance > 0 && distance <= threshold) {
        return {
          matched: true,
          brand: brand.domain,
          attackType: `Typosquatting detected (${part} ≈ ${brandName})`,
        };
      }
    }

    // 3. Leet speak check
    if (normalizedDomain.includes(brandName) && normalizedDomain !== domainPart) {
      return {
        matched: true,
        brand: brand.domain,
        attackType: "Leet speak substitution",
      };
    }
  }

  return { matched: false, brand: null, attackType: null };
}

// ✅ Export function — alag naam conflict nahi
export function checkBrandImpersonation(url: string): BrandImpersonationResult {
  try {
    const result = detectBrandMatch(url);  // 👈 detectBrandMatch call ho raha hai

    if (result.matched) {
      return {
        score: 30,
        matchedBrand: result.brand,
        attackType: result.attackType,
      };
    }

    return {
      score: 0,
      matchedBrand: null,
      attackType: null,
    };
  } catch {
    return {
      score: 0,
      matchedBrand: null,
      attackType: null,
      error: "Brand impersonation check failed",
    };
  }
}