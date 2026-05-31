import { NextRequest, NextResponse } from "next/server";
import { analyzeStructure } from "@/lib/analyzer/structureAnalyzer";
import { checkDomainAge } from "@/lib/analyzer/domainAgeChecker";
import { checkBlacklist } from "@/lib/analyzer/blacklistChecker";
import { calculateScore } from "@/lib/analyzer/scoreCalculator";

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

  const [structure, domainAge, blacklist] = await Promise.all([
    Promise.resolve(analyzeStructure(normalizedUrl)),
    checkDomainAge(normalizedUrl),
    checkBlacklist(normalizedUrl),
  ]);

  const result = calculateScore(structure, domainAge, blacklist);

  return json({
    ...result,
    normalizedUrl,
    analyzedAt: new Date().toISOString(),
  });
}

export async function OPTIONS() {
  return new NextResponse(null, {
    status: 204,
    headers: corsHeaders,
  });
}
