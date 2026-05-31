import { NextRequest, NextResponse } from "next/server";
import { analyzeStructure } from "@/lib/analyzer/structureAnalyzer";
import { checkDomainAge } from "@/lib/analyzer/domainAgeChecker";
import { checkBlacklist } from "@/lib/analyzer/blacklistChecker";
import { calculateScore } from "@/lib/analyzer/scoreCalculator";
import { checkBrandImpersonation } from "@/lib/analyzer/brandImpersonation";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

function normalizeUrl(raw: string): string {
  const trimmed = raw.trim();
  if (!/^https?:\/\//i.test(trimmed)) {
    return "https://" + trimmed;
  }
  return trimmed;
}

function validateUrl(url: string): string | null {
  try {
    const parsed = new URL(url);
    if (!["http:", "https:"].includes(parsed.protocol)) {
      return "Only HTTP and HTTPS URLs can be analyzed";
    }
    if (!parsed.hostname || parsed.hostname.length > 253) {
      return "Invalid URL hostname";
    }
    return null;
  } catch {
    return "Invalid URL format";
  }
}

// ✅ POST ke bahar nikala
async function checkVirusTotal(url: string) {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  if (!apiKey) return { error: "API key not configured", malicious: 0, total: 0 };

  try {
    const submitRes = await fetch("https://www.virustotal.com/api/v3/urls", {
      method: "POST",
      headers: {
        "x-apikey": apiKey,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: `url=${encodeURIComponent(url)}`,
    });
    const submitData = await submitRes.json();
    const analysisId = submitData?.data?.id;
    if (!analysisId) return { error: "Submission failed", malicious: 0, total: 0 };

    await new Promise((r) => setTimeout(r, 3000));

    const resultRes = await fetch(
      `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
      { headers: { "x-apikey": apiKey } }
    );
    const resultData = await resultRes.json();
    const stats = resultData?.data?.attributes?.stats ?? {};
    const total = Object.values(stats).reduce((a: number, b) => a + (b as number), 0);

    return {
      malicious: stats.malicious ?? 0,
      suspicious: stats.suspicious ?? 0,
      harmless: stats.harmless ?? 0,
      total,
    };
  } catch {
    return { error: "VirusTotal request failed", malicious: 0, total: 0 };
  }
}

function json(data: unknown, init?: ResponseInit) {
  return NextResponse.json(data, {
    ...init,
    headers: {
      ...corsHeaders,
      ...(init?.headers || {}),
    },
  });
}

export async function POST(req: NextRequest) {
  let body: { url?: string };
  try {
    body = await req.json();
  } catch {
    return json({ error: "Invalid JSON body" }, { status: 400 });
  }

  if (!body.url || typeof body.url !== "string" || body.url.trim() === "") {
    return json({ error: "URL is required" }, { status: 400 });
  }

  const normalizedUrl = normalizeUrl(body.url);
  const validationError = validateUrl(normalizedUrl);

  if (validationError) {
    return json({ error: validationError }, { status: 400 });
  }

  const [structure, domainAge, blacklist, virusTotal] = await Promise.all([
    Promise.resolve(analyzeStructure(normalizedUrl)),
    checkDomainAge(normalizedUrl),
    checkBlacklist(normalizedUrl),
    checkVirusTotal(normalizedUrl),
  ]);

  // ✅ variable name update
  const brandImpersonation = checkBrandImpersonation(normalizedUrl);

  // ✅ brandImpersonation pass karo
  const result = calculateScore(structure, domainAge, blacklist, virusTotal, brandImpersonation);

  return json({
    ...result,
    normalizedUrl,
    analyzedAt: new Date().toISOString(),
    virusTotal,
    brandImpersonation,  // ✅ name update
  });
}

export async function OPTIONS() {
  return new NextResponse(null, {
    status: 204,
    headers: corsHeaders,
  });
}