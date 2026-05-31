export interface BlacklistResult {
  blacklisted: boolean;
  score: number;
  source: string;
  error?: string;
}

// Local deny-list fallback — known phishing domains
const LOCAL_DENY_LIST: string[] = [
  "phishing-example.com",
  "malware-site.net",
  "free-iphone-winner.com",
  "secure-login-verify.com",
  "account-update-required.com",
];

function extractDomain(url: string): string | null {
  try {
    return new URL(url).hostname.replace(/^www\./, "");
  } catch {
    return null;
  }
}

async function checkGoogleSafeBrowsing(url: string): Promise<BlacklistResult> {
  const apiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;
  if (!apiKey) {
    throw new Error("Google Safe Browsing API key not configured");
  }

  const body = {
    client: { clientId: "phishguard", clientVersion: "1.0" },
    threatInfo: {
      threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
      platformTypes: ["ANY_PLATFORM"],
      threatEntryTypes: ["URL"],
      threatEntries: [{ url }],
    },
  };

  const res = await fetch(
    `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(1800),
    }
  );

  if (!res.ok) {
    throw new Error(`Safe Browsing API error: ${res.status}`);
  }

  const data = await res.json();
  const blacklisted = !!(data.matches && data.matches.length > 0);
  return {
    blacklisted,
    score: blacklisted ? 50 : 0,
    source: "Google Safe Browsing",
  };
}

function checkLocalDenyList(url: string): BlacklistResult {
  const domain = extractDomain(url);
  const blacklisted = domain ? LOCAL_DENY_LIST.includes(domain) : false;
  return {
    blacklisted,
    score: blacklisted ? 50 : 0,
    source: "Local deny-list",
  };
}

export async function checkBlacklist(url: string): Promise<BlacklistResult> {
  // Try Google Safe Browsing first
  try {
    return await checkGoogleSafeBrowsing(url);
  } catch {
    // Fall back to local deny-list
    const local = checkLocalDenyList(url);
    return {
      ...local,
      error: "Google Safe Browsing unavailable; used local deny-list",
    };
  }
}
