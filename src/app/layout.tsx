import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "pcap-engine",
  description: "Inspect .pcap and .pcapng captures entirely in your browser.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="min-h-screen font-sans antialiased">{children}</body>
    </html>
  );
}
