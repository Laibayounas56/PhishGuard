// eslint-disable-next-line @typescript-eslint/no-require-imports
const whois = require("whois-json") as (domain: string) => Promise<Record<string, unknown>>;

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

function scoreFromAge(ageMonths: number): number {
  // Domains younger than 6 months are high risk
  return ageMonths < 6 ? 20 : 0;
}

function parseDate(raw: unknown): Date | null {
  if (!raw) return null;
  const s = Array.isArray(raw) ? raw[0] : raw;
  if (typeof s !== "string" && typeof s !== "number") return null;
  const d = new Date(s);
  return isNaN(d.getTime()) ? null : d;
}

// ── Primary: RDAP ─────────────────────────────────────────────────────────────
async function tryRDAP(domain: string): Promise<Date | null> {
  // IANA bootstrap: determine the correct RDAP server for the TLD
  const tld = domain.split(".").pop()?.toLowerCase();
  if (!tld) return null;

  try {
    // 1. Try IANA bootstrap to find RDAP server for this TLD
    const bootstrapRes = await fetch(
      "https://data.iana.org/rdap/dns.json",
      { signal: AbortSignal.timeout(5000) }
    );
    if (bootstrapRes.ok) {
      const bootstrap = await bootstrapRes.json();
      const services: Array<[string[], string[]]> = bootstrap?.services ?? [];
      let rdapBase: string | null = null;

      for (const [tlds, urls] of services) {
        if (tlds.includes(tld) && urls.length > 0) {
          rdapBase = urls[0].replace(/\/$/, "");
          break;
        }
      }

      if (rdapBase) {
        const rdapRes = await fetch(
          `${rdapBase}/domain/${domain}`,
          {
            headers: { Accept: "application/rdap+json" },
            signal: AbortSignal.timeout(8000),
          }
        );
        if (rdapRes.ok) {
          const rdap = await rdapRes.json();
          const events: Array<{ eventAction: string; eventDate: string }> =
            rdap?.events ?? [];
          const reg = events.find(
            (e) => e.eventAction === "registration"
          );
          if (reg?.eventDate) return parseDate(reg.eventDate);
        }
      }
    }

    // 2. Fallback: try the generic RDAP lookup services directly
    const fallbackBases = [
      "https://rdap.org",
      "https://rdap.arin.net/registry",
    ];
    for (const base of fallbackBases) {
      try {
        const res = await fetch(`${base}/domain/${domain}`, {
          headers: { Accept: "application/rdap+json" },
          signal: AbortSignal.timeout(8000),
        });
        if (res.ok) {
          const data = await res.json();
          const events: Array<{ eventAction: string; eventDate: string }> =
            data?.events ?? [];
          const reg = events.find((e) => e.eventAction === "registration");
          if (reg?.eventDate) return parseDate(reg.eventDate);
        }
      } catch {
        // try next
      }
    }
  } catch {
    // RDAP completely unavailable
  }

  return null;
}

// ── Fallback: whois-json ───────────────────────────────────────────────────────
async function tryWhois(domain: string): Promise<Date | null> {
  try {
    const data = await whois(domain);
    // Different registrars use different field names
    const raw =
      data?.creationDate ??
      data?.created ??
      data?.registrationDate ??
      data?.["Creation Date"] ??
      data?.["Created Date"] ??
      data?.["Domain Registration Date"] ??
      null;
    return parseDate(raw);
  } catch {
    return null;
  }
}

// ── Main export ───────────────────────────────────────────────────────────────
export async function checkDomainAge(url: string): Promise<DomainAgeResult> {
  const domain = extractDomain(url);
  if (!domain) {
    return { score: 10, ageMonths: null, error: "Could not extract domain" };
  }

  const now = new Date();

  // 1. Try RDAP
  const rdapDate = await tryRDAP(domain);
  if (rdapDate) {
    const ageMonths = monthsBetween(rdapDate, now);
    return { score: scoreFromAge(ageMonths), ageMonths };
  }

  // 2. Try WHOIS fallback
  const whoisDate = await tryWhois(domain);
  if (whoisDate) {
    const ageMonths = monthsBetween(whoisDate, now);
    return { score: scoreFromAge(ageMonths), ageMonths };
  }

  // 3. Both failed — treat unknown age as slightly suspicious
  return {
    score: 10,
    ageMonths: null,
    error: "Domain age lookup failed (RDAP and WHOIS both unavailable)",
  };
}
