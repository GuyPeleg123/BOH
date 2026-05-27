import { useEffect, useState } from "react";
import { api } from "../lib/api";
import { useStore, shallow } from "../lib/store";

// Launches Wireshark on the configured pcap_stream_fifo so live MAC PDUs
// are dissected as they're written by the C++ side. The button is disabled
// when the fifo isn't configured; the tooltip explains the next step.
export function WiresharkButton() {
  const { lifecycle, mock } = useStore((s) => ({ lifecycle: s.lifecycle, mock: s.mock }), shallow);
  const [fifo, setFifo] = useState<string>("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [ok, setOk] = useState<string | null>(null);

  useEffect(() => {
    api.getConfig()
      .then((c) => setFifo(c.pcap_stream_fifo || ""))
      .catch(() => {});
  }, []);

  async function open() {
    setBusy(true); setErr(null); setOk(null);
    try {
      const r = await api.openWireshark();
      setOk(`Wireshark opened on ${r.fifo} (pid ${r.pid}). Now start capture if not running.`);
      setTimeout(() => setOk(null), 5000);
    } catch (e: any) {
      setErr(e?.message ?? String(e));
    } finally {
      setBusy(false);
    }
  }

  const captureRunning = lifecycle === "running";
  const disabled = busy || mock || !fifo;
  const title = mock
    ? "Live stream needs a real C++ capture, not mock mode"
    : !fifo
      ? "Set a 'Live-stream FIFO' path on the Config page first (e.g. /tmp/lte.pcap), then come back here"
      : captureRunning
        ? `⚠ Capture is already running — the C++ writer opened the FIFO before Wireshark could attach, so packets may not flow. After clicking, restart capture so the writer reopens the FIFO with Wireshark already listening.`
        : `Open Wireshark on ${fifo}; then click ▶ Start to begin capture (writer connects to the reader).`;

  return (
    <div className="flex flex-col items-stretch gap-1">
      <button
        className={captureRunning ? "btn btn-warn" : "btn"}
        onClick={open}
        disabled={disabled}
        title={title}
      >
        🦈 {busy ? "opening…" : "Wireshark"}
      </button>
      {(err || ok) && (
        <div className={`text-[10px] font-mono px-1 py-0.5 rounded max-w-[260px] truncate ${err ? "text-bad bg-bad/10" : "text-ok bg-ok/10"}`}
             title={err ?? ok ?? ""}>
          {err ?? ok}
        </div>
      )}
    </div>
  );
}
