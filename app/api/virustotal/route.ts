import { NextRequest, NextResponse } from "next/server";

export async function POST(req: NextRequest) {
  const { url } = await req.json();
  const apiKey = process.env.VIRUSTOTAL_API_KEY;

  if (!apiKey) {
    return NextResponse.json({ error: "API key not configured" }, { status: 500 });
  }

  try {
    // Step 1: Submit URL for scanning
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

    if (!analysisId) {
      return NextResponse.json({ error: "Failed to submit URL" }, { status: 500 });
    }

    // Step 2: Poll for results (wait 3 seconds)
    await new Promise((r) => setTimeout(r, 3000));

    const resultRes = await fetch(
      `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
      {
        headers: { "x-apikey": apiKey },
      }
    );

    const resultData = await resultRes.json();
    const stats = resultData?.data?.attributes?.stats;

    return NextResponse.json({
      malicious: stats?.malicious ?? 0,
      suspicious: stats?.suspicious ?? 0,
      harmless: stats?.harmless ?? 0,
      undetected: stats?.undetected ?? 0,
      total: Object.values(stats ?? {}).reduce((a: number, b) => a + (b as number), 0),
    });

  } catch (err) {
    return NextResponse.json({ error: "VirusTotal request failed" }, { status: 500 });
  }
}