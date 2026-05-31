import { useEffect, useState } from "react";
import { api } from "../lib/api";
import { useStore, shallow } from "../lib/store";

const DEFAULT_FIFO = "/tmp/lte.pcap";

// Launches Wireshark on the configured pcap_stream_fifo so live MAC PDUs
// are dissected as they're written by the C++ side. If no FIFO is set, the
// button offers to seed cfg.pcap_stream_fifo with /tmp/lte.pcap and open
// Wireshark in one click (single-confirm prompt) rather than punting the
// user back to the Config page.
export function WiresharkButton() {
  const { lifecycle, mock } = useStore((s) => ({ lifecycle: s.lifecycle, mock: s.mock }), shallow);
  const [fifo, setFifo] = useState<string>("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [ok, setOk] = useState<string | null>(null);

  // Re-read the FIFO from /api/config whenever the page regains focus or the
  // capture lifecycle flips — if the user just saved a new path on the Config
  // page, this picks it up without a hard refresh.
  const refreshFifo = () => {
    api.getConfig()
      .then((c) => setFifo(c.pcap_stream_fifo || ""))
      .catch(() => {});
  };

  useEffect(() => {
    refreshFifo();
    const onFocus = () => refreshFifo();
    window.addEventListener("focus", onFocus);
    const id = setInterval(refreshFifo, 5000);
    return () => {
      window.removeEventListener("focus", onFocus);
      clearInterval(id);
    };
  }, []);

  // Whenever the lifecycle flips, re-poll config too. (Restart/Start can
  // happen from anywhere in the GUI; cheaper than chasing every entrypoint.)
  useEffect(() => { refreshFifo(); }, [lifecycle]);

  async function setFifoAndOpen(path: string) {
    // 1. PUT config with the new FIFO path  2. open wireshark  3. inform user.
    const cfg = await api.getConfig();
    cfg.pcap_stream_fifo = path;
    await api.putConfig(cfg);
    setFifo(path);
    const r = await api.openWireshark();
    setOk(
      `Saved FIFO=${path}. Wireshark opened (pid ${r.pid}). ` +
      `Frames stream in automatically once a capture is running — no restart needed.`
    );
  }

  async function open() {
    setBusy(true); setErr(null); setOk(null);
    try {
      if (!fifo) {
        // Offer the default fifo path so the user gets a working stream in one
        // confirm-click instead of being shoved off to the Config page.
        const ok = window.confirm(
          `No live-stream FIFO configured yet.\n\n` +
          `Use the default ${DEFAULT_FIFO} ?\n` +
          `→ Will save it to your config and open Wireshark right now.`
        );
        if (!ok) return;
        await setFifoAndOpen(DEFAULT_FIFO);
      } else {
        const r = await api.openWireshark();
        setOk(`Wireshark opened on ${r.fifo} (pid ${r.pid}). ` +
              (lifecycle === "running"
                ? "Frames will appear within ~1s — no restart needed."
                : "▶ Now start capture and frames will stream in."));
      }
      setTimeout(() => setOk(null), 8000);
    } catch (e: any) {
      setErr(e?.message ?? String(e));
    } finally {
      setBusy(false);
    }
  }

  const captureRunning = lifecycle === "running";
  // Only truly disable for mock mode (the live stream needs a real C++
  // capture) or while a request is in flight. The empty-FIFO case is now
  // a soft, click-to-fix state — not a dead button.
  const disabled = busy || mock;

  const title = mock
    ? "Live stream needs a real C++ capture, not mock mode."
    : !fifo
      ? `Click to set the default FIFO (${DEFAULT_FIFO}) and open Wireshark in one step. ` +
        `Alternatively, set a custom path in Config → Output files → "Live-stream FIFO".`
      : captureRunning
        ? `Wireshark will open on ${fifo}. Capture is already running, so after Wireshark attaches, click ⟳ Restart so the C++ writer reopens the FIFO with Wireshark listening.`
        : `Open Wireshark on ${fifo}; then click ▶ Start to begin capture.`;

  const cls = mock ? "btn opacity-60"
    : !fifo ? "btn btn-secondary"   // soft state — clickable, distinctly styled
    : captureRunning ? "btn btn-warn"
    : "btn";
  const label = mock ? "🦈 Wireshark (mock mode)"
    : busy ? "… opening"
    : !fifo ? "🦈 Wireshark (setup)"
    : "🦈 Wireshark";

  return (
    <div className="flex flex-col items-stretch gap-1">
      <button className={cls} onClick={open} disabled={disabled} title={title}>
        {label}
      </button>
      {(err || ok) && (
        <div className={`text-[10px] font-mono px-1 py-0.5 rounded max-w-[280px] truncate ${err ? "text-bad bg-bad/10" : "text-ok bg-ok/10"}`}
             title={err ?? ok ?? ""}>
          {err ?? ok}
        </div>
      )}
    </div>
  );
}
