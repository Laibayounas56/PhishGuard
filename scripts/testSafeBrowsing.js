// Quick test script for Google Safe Browsing API
const apiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY || 'AIzaSyAEB0jUot9quBKCWpa-BLVCumNI5HegaMc';
const testUrl = 'http://testsafebrowsing.appspot.com/s/malware.html';

const body = {
  client: { clientId: 'phishguard', clientVersion: '1.0' },
  threatInfo: {
    threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'],
    platformTypes: ['ANY_PLATFORM'],
    threatEntryTypes: ['URL'],
    threatEntries: [{ url: testUrl }],
  },
};

(async () => {
  try {
    const res = await fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        // 5s timeout via AbortController
        signal: AbortSignal.timeout ? AbortSignal.timeout(5000) : undefined,
      }
    );

    console.log('HTTP', res.status, res.statusText);
    const text = await res.text();
    try {
      console.log('JSON Response:', JSON.parse(text));
    } catch (e) {
      console.log('Raw Response:', text);
    }
  } catch (err) {
    console.error('Request error:', err && err.message ? err.message : err);
    process.exitCode = 2;
  }
})();
