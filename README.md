# PhishGuard

Real-time phishing URL detection system with a Next.js web app, backend API, and Chrome Extension (Manifest V3).

## What It Does

- Accepts manual URL checks from the web app.
- Scans top-level browser navigation from the Chrome extension.
- Scores phishing risk using URL structure, domain age, and blacklist checks.
- Classifies URLs as `Safe`, `Suspicious`, or `Blocked`.
- Shows a dismissible warning for suspicious pages.
- Redirects blocked pages to a dedicated PhishGuard block screen.

## Project Structure

```text
phishguard/
  app/
    api/analyze/route.ts       POST /api/analyze
    page.tsx                   Web analyzer UI
    layout.tsx
    globals.css
  lib/analyzer/
    structureAnalyzer.ts       URL structure checks
    domainAgeChecker.ts        WHOIS domain age lookup
    blacklistChecker.ts        Google Safe Browsing or local deny-list
    scoreCalculator.ts         Score aggregation and status thresholds
  extension/
    manifest.json              Chrome MV3 manifest
    background.js              Navigation scanner and enforcement
    content.js                 Suspicious-site warning banner
    blocked.html               Blocked-site interstitial
    popup.html
    popup.js                   Last scan popup
    icons/
```

## Setup

```bash
npm install
npm run dev
```

Open `http://localhost:3000` to use the web app.

## Optional API Keys

The app works without API keys by using URL structure analysis and the local deny-list. Add these variables in `.env.local` when available:

```env
WHOIS_API_KEY=your_whoisxmlapi_key
GOOGLE_SAFE_BROWSING_API_KEY=your_google_safe_browsing_key
```

## API

### `POST /api/analyze`

Request:

```json
{ "url": "https://example.com/login" }
```

Response:

```json
{
  "score": 75,
  "status": "Blocked",
  "normalizedUrl": "https://example.com/login",
  "analyzedAt": "2026-05-31T12:00:00.000Z",
  "breakdown": {
    "structure": { "score": 30, "flags": ["Suspicious keyword: \"login\""] },
    "domainAge": { "score": 20, "ageMonths": 2 },
    "blacklist": { "score": 50, "blacklisted": true, "source": "Google Safe Browsing" }
  }
}
```

Thresholds:

| Status | Score |
| --- | --- |
| Safe | 0-39 |
| Suspicious | 40-69 |
| Blocked | 70-100 |

## Chrome Extension

1. Run the app with `npm run dev`.
2. Open Chrome and go to `chrome://extensions`.
3. Enable Developer mode.
4. Click Load unpacked.
5. Select the `extension/` folder.
6. Pin PhishGuard from the toolbar.

The extension calls `http://localhost:3000/api/analyze` by default.

## Notes

- Domain age and Google Safe Browsing lookups time out quickly so the API can respond near the PRD target.
- If an external API is unavailable, PhishGuard continues with the available checks.
- `Blocked` pages do not offer a proceed action; `Suspicious` pages show a warning with a proceed option.
