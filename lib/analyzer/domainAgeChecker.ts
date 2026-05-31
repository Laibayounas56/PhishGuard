export interface DomainAgeResult {
  score: number;
  ageMonths: number | null;
  error?: string;
}

function extractDomain(url: string): string | null {
  try {
    return new URL(url).hostname.replace(/^www\./, "");
  } catch {
    return null;
  }
}

function monthsBetween(date: Date, now: Date): number {
  return (
    (now.getFullYear() - date.getFullYear()) * 12 +
    (now.getMonth() - date.getMonth())
  );
}

export async function checkDomainAge(url: string): Promise<DomainAgeResult> {
  const domain = extractDomain(url);
  if (!domain) {
    return { score: 10, ageMonths: null, error: "Could not extract domain" };
  }

  const apiKey = process.env.WHOIS_API_KEY;
  if (!apiKey) {
    return { score: 0, ageMonths: null, error: "WHOIS API key not configured" };
  }

  try {
    const res = await fetch(
      `https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=${apiKey}&domainName=${domain}&outputFormat=JSON`,
      { signal: AbortSignal.timeout(1800) }
    );

    if (!res.ok) {
      return { score: 0, ageMonths: null, error: `WHOIS API error: ${res.status}` };
    }

    const data = await res.json();
    const createdDateStr =
      data?.WhoisRecord?.createdDate ||
      data?.WhoisRecord?.registryData?.createdDate;

    if (!createdDateStr) {
      return { score: 5, ageMonths: null, error: "Creation date not found in WHOIS data" };
    }

    const createdDate = new Date(createdDateStr);
    const now = new Date();
    const ageMonths = monthsBetween(createdDate, now);

    // Newly registered domains are high risk
    if (ageMonths < 6) {
      return { score: 20, ageMonths };
    }

    return { score: 0, ageMonths };
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : "Unknown error";
    return { score: 0, ageMonths: null, error: `WHOIS lookup failed: ${message}` };
  }
}
