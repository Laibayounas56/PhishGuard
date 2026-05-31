import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "PhishGuard - Phishing URL Detector",
  description:
    "Detect phishing URLs in real time. PhishGuard analyzes URL structure, domain age, and blacklists to classify links as Safe, Suspicious, or Blocked.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
