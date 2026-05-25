import { useEffect, useMemo, useRef, useState } from "react";
import { useStore } from "../lib/store";
import type { USRPDevice } from "../lib/types";

interface PreflightCheck { ok: boolean; detail: string; fix: string | null; }

interface SpectrumStatus {
  available: { cmd: string; label: string }[];
  running: boolean;
  tool: string | null;
  pid: number | null;
  argv: string[];
  display_required: boolean;
  display_env: string | null;
  last_error: string | null;
  last_exit_code: number | null;
  last_tool: string | null;
  preflight: {
    display: PreflightCheck;
    uhd_images: PreflightCheck;
    tool: PreflightCheck;
    all_ok: boolean;
  };
}

function buildDeviceArgs(serial: string): string {
  // UHD device-args syntax. Keep it minimal — just the serial.
  return `serial=${serial}`;
}

// Pull a USRP serial out of an LTESniffer rfargs string (e.g. "clock=gpsdo,serial=32FCD4C,...")
function serialFromRfArgs(s: string): string | null {
  const m = s.match(/serial=([A-Za-z0-9]+)/);
  return m ? m[1] : null;
}

export function SpectrumButton() {
  const { state } = useStore();
  const [status, setStatus] = useState<SpectrumStatus | null>(null);
  const [usrps, setUsrps] = useState<USRPDevice[]>([]);
  const [chosenSerial, setChosenSerial] = useState<string>("");
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [launchErr, setLaunchErr] = useState<string | null>(null);
  const wrapRef = useRef<HTMLDivElement>(null);

  const refresh = () =>
    fetch("/api/spectrum")
      .then((r) => r.json())
      .then(setStatus)
      .catch(() => {});

  const refreshUsrps = () =>
    fetch("/api/usrps")
      .then((r) => r.json())
      .then((j) => setUsrps(j.devices ?? []))
      .catch(() => {});

  // Poll fast when the popover is open or spectrum is already running (need timely updates).
  // Poll slowly otherwise — no point hammering the backend when nothing is happening.
  useEffect(() => {
    refresh();
    refreshUsrps();
    const interval = (open || status?.running) ? 3000 : 10000;
    const i = setInterval(refresh, interval);
    return () => clearInterval(i);
  }, [open, status?.running]);

  // Re-poll USRPs when the popover opens (cheap; ~5s timeout in backend)
  useEffect(() => {
    if (open) refreshUsrps();
  }, [open]);

  // Outside-click close
  useEffect(() => {
    if (!open) return;
    function onDown(e: MouseEvent) {
      if (wrapRef.current && !wrapRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    window.addEventListener("mousedown", onDown);
    return () => window.removeEventListener("mousedown", onDown);
  }, [open]);

  const freq = state.cell?.dl_freq ?? state.hello?.args?.rf_freq ?? 0;
  const sr = state.cell?.sample_rate ?? 0;

  // Serials the sniffer is likely holding (from saved rfargs in lifecycle argv).
  const heldSerials = useMemo(() => {
    const argv = state.argv ?? [];
    const out = new Set<string>();
    for (let i = 0; i < argv.length - 1; i++) {
      if (["-X", "-Z", "-a"].includes(argv[i])) {
        const s = serialFromRfArgs(argv[i + 1] ?? "");
        if (s) out.add(s);
      }
    }
    return out;
  }, [state.argv]);

  // Default the picker to a USRP not currently held by the sniffer (if any free).
  useEffect(() => {
    if (chosenSerial) return;
    if (usrps.length === 0) return;
    const free = usrps.find((d) => d.serial && !heldSerials.has(d.serial));
    setChosenSerial((free?.serial ?? usrps[0]?.serial ?? "") as string);
  }, [usrps, heldSerials, chosenSerial]);

  async function launch(tool?: string) {
    setBusy(true);
    setLaunchErr(null);
    try {
      const device_args = chosenSerial ? buildDeviceArgs(chosenSerial) : "";
      const r = await fetch("/api/spectrum/launch", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ freq_hz: freq, sample_rate_hz: sr, tool, device_args }),
      });
      const j = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(j.detail ?? `HTTP ${r.status}`);
      await refresh();
      setOpen(false);
    } catch (e: any) {
      setLaunchErr(e?.message ?? String(e));
      await refresh();
    } finally {
      setBusy(false);
    }
  }

  async function stop() {
    setBusy(true);
    try {
      await fetch("/api/spectrum/stop", { method: "POST" });
      await refresh();
    } finally {
      setBusy(false);
    }
  }

  const outerDisabled = busy;
  const isRunning = !!status?.running;
  const hasError = !!status?.last_error && !isRunning;

  const buttonClass = isRunning ? "btn btn-ok" : hasError ? "btn btn-danger" : "btn";
  const buttonLabel = isRunning
    ? `■ Spectrum (${status?.tool})`
    : busy
      ? "… launching"
      : hasError
        ? `⚠ Spectrum failed`
        : "📡 Spectrum";
  const buttonTitle = !freq
    ? "Set DL freq first (capture must be running, or set it in Config)"
    : isRunning
      ? "Click to stop the spectrum analyzer"
      : hasError
        ? `Last error: ${status?.last_error}\nClick to retry`
        : "Open spectrum analyzer (uhd_fft / gqrx) on the backend's display";

  const sniffRunning = state.lifecycle === "running";
  const chosenIsHeld = chosenSerial && heldSerials.has(chosenSerial);
  const launchDisabled = busy || !freq || !!chosenIsHeld;

  return (
    <div ref={wrapRef} className="relative">
      <button
        className={buttonClass}
        onClick={() => {
          if (isRunning) { stop(); return; }
          setOpen((o) => !o);
          setLaunchErr(null);
        }}
        disabled={outerDisabled}
        title={buttonTitle}
      >
        {buttonLabel}
      </button>

      {open && !isRunning && (
        <div className="absolute right-0 mt-2 w-[28rem] panel p-3 z-30 shadow-xl border-accent/30">
          {/* Pre-flight panel: tells the operator which preconditions are already met */}
          {status?.preflight && (
            <div className="mb-3 bg-bg border border-border rounded p-2 space-y-1.5">
              <div className="text-[10px] uppercase tracking-wide text-muted mb-1">Pre-flight</div>
              {([
                ["display",    status.preflight.display],
                ["uhd images", status.preflight.uhd_images],
                ["tool",       status.preflight.tool],
              ] as const).map(([label, c]) => (
                <div key={label} className="text-xs">
                  <div className="flex items-baseline gap-2">
                    <span className={c.ok ? "text-ok" : "text-bad"}>{c.ok ? "✓" : "✗"}</span>
                    <span className="text-slate-200 uppercase tracking-wide text-[10px] w-20">{label}</span>
                    <span className="text-muted font-mono truncate" title={c.detail}>{c.detail}</span>
                  </div>
                  {!c.ok && c.fix && (
                    <div className="ml-6 mt-0.5 text-[11px] text-warn font-mono bg-warn/5 border-l-2 border-warn/40 pl-2 py-0.5">
                      {c.fix}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}

          <div className="text-xs text-muted mb-2">
            {freq > 0 ? (
              <>
                Tuning <span className="font-mono text-slate-200">{(freq / 1e6).toFixed(3)} MHz</span>
                {sr > 0 && <> @ <span className="font-mono text-slate-200">{(sr / 1e6).toFixed(2)} MHz</span> sample rate</>}.
              </>
            ) : (
              <span className="text-warn"> No DL freq known yet — set one in Config, or start a capture.</span>
            )}
          </div>

          {/* USRP picker */}
          <div className="mb-3">
            <div className="flex items-baseline justify-between mb-1">
              <span className="label">USRP device</span>
              <button className="text-[10px] text-muted hover:text-slate-200" onClick={refreshUsrps}>↻ rescan</button>
            </div>
            {usrps.length === 0 ? (
              <div className="text-xs text-warn p-2 bg-warn/10 rounded">
                No USRP detected by <code>uhd_find_devices</code>. The tool will probably error with "No devices found".
              </div>
            ) : (
              <div className="flex flex-col gap-1">
                {usrps.map((d) => {
                  const serial = d.serial ?? "";
                  const held = heldSerials.has(serial);
                  const checked = serial && chosenSerial === serial;
                  return (
                    <label
                      key={serial || (d as any).type}
                      className={`flex items-center gap-2 px-2 py-1 rounded border cursor-pointer text-xs
                        ${checked ? "border-accent bg-accent/10" : "border-border hover:bg-bg"}
                        ${held ? "opacity-60" : ""}`}
                    >
                      <input
                        type="radio"
                        className="accent-accent"
                        name="usrp"
                        checked={!!checked}
                        onChange={() => setChosenSerial(serial)}
                      />
                      <span className="font-mono text-slate-100">{d.product ?? d.type ?? "USRP"}</span>
                      <span className="font-mono text-muted">{serial}</span>
                      {held && (
                        <span className="ml-auto text-[10px] text-warn font-semibold uppercase">
                          held by sniffer
                        </span>
                      )}
                    </label>
                  );
                })}
                {!chosenSerial && (
                  <label className="flex items-center gap-2 px-2 py-1 rounded border border-border text-xs cursor-pointer">
                    <input type="radio" className="accent-accent" name="usrp" checked={chosenSerial === ""} onChange={() => setChosenSerial("")} />
                    <span className="text-muted">No -a (let UHD pick)</span>
                  </label>
                )}
              </div>
            )}
            {sniffRunning && chosenIsHeld && (
              <div className="mt-2 text-xs text-warn">
                This USRP is held by the running capture — UHD will fail. Stop the capture first, or pick a different USRP.
              </div>
            )}
            {sniffRunning && !chosenIsHeld && heldSerials.size > 0 && (
              <div className="mt-2 text-[11px] text-muted">
                Capture is using {[...heldSerials].join(", ")} — chose a free USRP for the spectrum.
              </div>
            )}
          </div>

          {status && status.available.length === 0 && (
            <div className="text-xs text-warn mb-2 p-2 bg-warn/10 rounded">
              No spectrum tool found on PATH. Install <code className="text-slate-200">gnuradio-uhd</code> (for <code>uhd_fft</code>) or <code className="text-slate-200">gqrx-sdr</code>.
            </div>
          )}

          <div className="flex flex-col gap-1">
            {status?.available.map((t) => (
              <button
                key={t.cmd}
                className="btn !justify-start"
                onClick={() => launch(t.cmd)}
                disabled={launchDisabled}
                title={
                  !freq ? "DL freq required" :
                  chosenIsHeld ? "Selected USRP is held by the sniffer" :
                  `Launch ${t.cmd} with ${chosenSerial ? `serial=${chosenSerial}` : "no -a"}`
                }
              >
                <span className="text-accent font-mono">{t.cmd}</span>
                <span className="text-muted text-xs">— {t.label}</span>
              </button>
            ))}
          </div>

          {busy && (
            <div className="mt-3 text-xs text-muted flex items-center gap-2">
              <span className="inline-block w-2 h-2 rounded-full bg-accent animate-pulse" />
              launching… (waiting for early-exit window)
            </div>
          )}

          {launchErr && (
            <div className="mt-3 text-xs text-bad font-mono whitespace-pre-wrap bg-bad/10 border border-bad/30 rounded p-2 max-h-40 overflow-auto">
              {launchErr}
            </div>
          )}

          {!launchErr && status?.last_error && !isRunning && (
            <div className="mt-3 text-xs text-warn font-mono whitespace-pre-wrap bg-warn/10 border border-warn/30 rounded p-2 max-h-40 overflow-auto">
              <div className="text-[10px] uppercase tracking-wide text-muted mb-1">
                last attempt ({status.last_tool}) exit {status.last_exit_code ?? "?"}
              </div>
              {status.last_error}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
