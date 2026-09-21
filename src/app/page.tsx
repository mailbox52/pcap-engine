import PcapUploader from "@/components/PcapUploader";

export default function Home() {
  return (
    <main className="mx-auto max-w-4xl px-6 py-12">
      <h1 className="text-2xl font-semibold tracking-tight">pcap-engine</h1>
      <p className="mt-2 text-sm text-zinc-400">
        Open a .pcap or .pcapng capture. Parsing runs in a background thread in your browser.
        Your file never leaves this device.
      </p>
      <div className="mt-8">
        <PcapUploader />
      </div>
    </main>
  );
}
