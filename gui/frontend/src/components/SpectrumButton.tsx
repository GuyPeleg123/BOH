import { useEffect, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { useStore, shallow } from "../lib/store";
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
  const state = useStore((s) => ({
    cell: s.cell, hello: s.hello, argv: s.argv, lifecycle: s.lifecycle, mock: s.mock,
  }), shallow);
  const [status, setStatus] = useState<SpectrumStatus | null>(null);
  const [usrps, setUsrps] = useState<USRPDevice[]>([]);
  const [chosenSerial, setChosenSerial] = useState<string>("");
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [launchErr, setLaunchErr] = useState<string | null>(null);
  // Fallback frequency from /api/config so the spectrum can launch *before*
  // any capture has run — you usually need to look at the band first to find
  // a cell to tune to.
  const [configFreq, setConfigFreq] = useState<number>(0);
  // User-tunable launch parameters. Each is null/empty until the user touches
  // it — null means "let the tool pick its default" (uhd_fft midpoint gain,
  // built-in FFT size etc.).
  const [freqOverrideMhz, setFreqOverrideMhz] = useState<string>("");  // "" = use derived freq
  const [spanMhz, setSpanMhz]                 = useState<string>("");  // "" = use sr from cell or 23.04 default
  const [gainDb, setGainDb]                   = useState<string>("");  // "" = AGC / tool default
  const [fftSize, setFftSize]                 = useState<string>("1024");
  const [fftAverage, setFftAverage]           = useState<"off"|"low"|"medium"|"high"|"">("medium");
  const [antenna, setAntenna]                 = useState<string>("");
  const [showAdvanced, setShowAdvanced]       = useState<boolean>(false);
  const wrapRef = useRef<HTMLDivElement>(null);
  const popoverRef = useRef<HTMLDivElement>(null);
  // Position the portal-rendered popover beneath the button using fixed coords
  // so it can't be clipped by ancestor `overflow-hidden`.
  const [popPos, setPopPos] = useState<{ top: number; left: number } | null>(null);

  function computePopPos() {
    const btn = wrapRef.current?.querySelector("button");
    if (!btn) return;
    const r = btn.getBoundingClientRect();
    const popW = 448; // matches w-[28rem]
    const margin = 8;
    // Prefer right-aligned with button right edge so it grows toward the left,
    // but clamp so it doesn't escape the viewport on either side.
    let left = r.right - popW;
    if (left < margin) left = margin;
    if (left + popW > window.innerWidth - margin) {
      left = window.innerWidth - popW - margin;
    }
    const top = r.bottom + 6;
    setPopPos({ top, left });
  }

  useEffect(() => {
    if (!open) return;
    computePopPos();
    const onResize = () => computePopPos();
    window.addEventListener("resize", onResize);
    window.addEventListener("scroll", onResize, true);
    return () => {
      window.removeEventListener("resize", onResize);
      window.removeEventListener("scroll", onResize, true);
    };
  }, [open]);

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

  // Pull the persisted rf_freq from /api/config so the spectrum can launch
  // before any capture has run. Refreshed when the popover opens so a freshly
  // edited Config takes effect without a page reload.
  useEffect(() => {
    if (!open) return;
    fetch("/api/config")
      .then((r) => r.json())
      .then((c) => setConfigFreq(Number(c?.rf_freq) || 0))
      .catch(() => {});
  }, [open]);

  // Outside-click close. The popover is now portaled to <body>, so checking
  // wrapRef.contains(target) alone wouldn't recognise clicks inside the
  // popover. Check both the wrap (button) and the popover refs.
  useEffect(() => {
    if (!open) return;
    function onDown(e: MouseEvent) {
      const t = e.target as Node;
      const inWrap = wrapRef.current && wrapRef.current.contains(t);
      const inPop = popoverRef.current && popoverRef.current.contains(t);
      if (!inWrap && !inPop) setOpen(false);
    }
    window.addEventListener("mousedown", onDown);
    return () => window.removeEventListener("mousedown", onDown);
  }, [open]);

  const freq = state.cell?.dl_freq ?? state.hello?.args?.rf_freq ?? configFreq ?? 0;
  const sr = state.cell?.sample_rate ?? 0;
  const freqSource: "live" | "hello" | "config" | "none" =
    state.cell?.dl_freq ? "live"
    : state.hello?.args?.rf_freq ? "hello"
    : configFreq ? "config"
    : "none";

  // Serials the sniffer is likely holding (from saved rfargs in lifecycle argv).
  // Only meaningful while the sniffer is actually running — once it stops,
  // every USRP is free, regardless of what argv the previous run used.
  const heldSerials = useMemo(() => {
    if (state.lifecycle !== "running") return new Set<string>();
    const argv = state.argv ?? [];
    const out = new Set<string>();
    for (let i = 0; i < argv.length - 1; i++) {
      if (["-X", "-Z", "-a"].includes(argv[i])) {
        const s = serialFromRfArgs(argv[i + 1] ?? "");
        if (s) out.add(s);
      }
    }
    return out;
  }, [state.argv, state.lifecycle]);

  // Default the picker to a USRP not currently held by the sniffer (if any free).
  useEffect(() => {
    if (chosenSerial) return;
    if (usrps.length === 0) return;
    const free = usrps.find((d) => d.serial && !heldSerials.has(d.serial));
    setChosenSerial((free?.serial ?? usrps[0]?.serial ?? "") as string);
  }, [usrps, heldSerials, chosenSerial]);

  // Resolve final freq/span/extras to send.
  // Center freq:  user override (MHz) → state-derived freq (Hz).
  // Span (=sample rate): user override (MHz) → state.cell.sample_rate (Hz) → 23.04 MHz default
  //                      (≈ 20 MHz LTE bandwidth, a sensible default for B3).
  const launchFreqHz = freqOverrideMhz.trim() !== ""
    ? Math.round(parseFloat(freqOverrideMhz) * 1e6)
    : freq;
  const launchSpanHz = spanMhz.trim() !== ""
    ? Math.round(parseFloat(spanMhz) * 1e6)
    : (sr || 23_040_000);

  async function launch(tool?: string) {
    setBusy(true);
    setLaunchErr(null);
    try {
      const device_args = chosenSerial ? buildDeviceArgs(chosenSerial) : "";
      const body: Record<string, unknown> = {
        freq_hz: launchFreqHz,
        sample_rate_hz: launchSpanHz,
        tool,
        device_args,
      };
      if (gainDb.trim() !== "")  body.gain_db = parseFloat(gainDb);
      if (antenna.trim() !== "") body.antenna = antenna.trim();
      if (fftSize)               body.fft_size = parseInt(fftSize, 10);
      if (fftAverage)            body.fft_average = fftAverage;
      const r = await fetch("/api/spectrum/launch", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
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

  // Mock mode has no real USRP, so launching a spectrum analyzer would just
  // fail with "No devices found". Block the action and tell the operator why.
  const mock = state.mock;

  const outerDisabled = busy || mock;
  const isRunning = !!status?.running;
  const hasError = !!status?.last_error && !isRunning;

  const buttonClass =
    mock      ? "btn opacity-60" :
    isRunning ? "btn btn-ok" :
    hasError  ? "btn btn-danger" :
                "btn";
  const buttonLabel = mock
    ? "📡 Spectrum (mock mode)"
    : isRunning
      ? `■ Spectrum (${status?.tool})`
      : busy
        ? "… launching"
        : hasError
          ? `⚠ Spectrum failed`
          : "📡 Spectrum";
  const buttonTitle = mock
    ? "The spectrum analyzer needs a real USRP — it reads live RF samples and FFTs them. " +
      "Restart the backend without LTESNIFFER_GUI_MOCK=1 (and plug in a USRP) to enable it."
    : !freq
      ? "Set DL freq first (capture must be running, or set it in Config)"
      : isRunning
        ? "Click to stop the spectrum analyzer"
        : hasError
          ? `Last error: ${status?.last_error}\nClick to retry`
          : "Open spectrum analyzer (uhd_fft / gqrx) on the backend's display";

  const sniffRunning = state.lifecycle === "running";
  const chosenIsHeld = chosenSerial && heldSerials.has(chosenSerial);
  const launchDisabled = busy || !launchFreqHz || !!chosenIsHeld;

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

      {open && !isRunning && popPos && createPortal(
        <div
          ref={popoverRef}
          className="w-[30rem] panel p-3 z-50 shadow-xl border-accent/30 max-h-[80vh] overflow-y-auto"
          style={{ position: "fixed", top: popPos.top, left: popPos.left }}
        >
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

          {/* Tuning form: every value is editable; defaults come from cell/config */}
          <div className="mb-3 bg-bg border border-border rounded p-2 space-y-2">
            <div className="flex items-baseline justify-between">
              <span className="text-[10px] uppercase tracking-wide text-muted">Tuning</span>
              <span className="text-[10px] text-muted">
                {freqSource === "live"   && <span className="text-ok/70">live cell</span>}
                {freqSource === "hello"  && "last launch"}
                {freqSource === "config" && "saved config"}
                {freqSource === "none"   && <span className="text-warn">no source</span>}
              </span>
            </div>

            {/* Center freq + span */}
            <div className="grid grid-cols-2 gap-2">
              <label className="flex flex-col gap-0.5">
                <span className="text-[10px] text-muted">Center freq (MHz)</span>
                <input
                  type="number" step="0.001" min="0"
                  className="input !text-xs !py-1 !px-2 font-mono"
                  placeholder={freq > 0 ? (freq / 1e6).toFixed(3) : "1845.000"}
                  value={freqOverrideMhz}
                  onChange={(e) => setFreqOverrideMhz(e.target.value)}
                />
              </label>
              <label className="flex flex-col gap-0.5">
                <span className="text-[10px] text-muted">Span / sample rate (MHz)</span>
                <input
                  type="number" step="0.01" min="0"
                  className="input !text-xs !py-1 !px-2 font-mono"
                  placeholder={sr > 0 ? (sr / 1e6).toFixed(2) : "23.04"}
                  value={spanMhz}
                  onChange={(e) => setSpanMhz(e.target.value)}
                />
              </label>
            </div>

            {/* Span presets */}
            <div className="flex flex-wrap gap-1 items-center">
              <span className="text-[10px] text-muted mr-1">Span presets:</span>
              {[
                { label: "1.4 MHz BW", mhz: "1.92" },
                { label: "5 MHz BW",   mhz: "7.68" },
                { label: "10 MHz BW",  mhz: "15.36" },
                { label: "20 MHz BW",  mhz: "23.04" },
                { label: "wide 40 MHz", mhz: "40" },
                { label: "wide 56 MHz", mhz: "56" },
              ].map((p) => (
                <button
                  key={p.mhz}
                  className={`btn !px-2.5 !py-1 !text-xs ${spanMhz === p.mhz ? "btn-primary" : ""}`}
                  onClick={() => setSpanMhz(p.mhz)}
                  title={`Set sample rate to ${p.mhz} MHz`}
                >
                  {p.label}
                </button>
              ))}
            </div>

            {/* Gain + advanced toggle */}
            <div className="grid grid-cols-2 gap-2 pt-1">
              <label className="flex flex-col gap-0.5">
                <span className="text-[10px] text-muted">RX gain (dB) — empty = tool default</span>
                <input
                  type="number" step="1" min="0" max="90"
                  className="input !text-xs !py-1 !px-2 font-mono"
                  placeholder="(midpoint)"
                  value={gainDb}
                  onChange={(e) => setGainDb(e.target.value)}
                />
              </label>
              <div className="flex items-end">
                <button
                  className="btn !px-2 !py-1 !text-xs w-full"
                  onClick={() => setShowAdvanced((v) => !v)}
                  title="FFT size, averaging, antenna selection"
                >
                  {showAdvanced ? "▾ Hide advanced" : "▸ Show advanced"}
                </button>
              </div>
            </div>

            {showAdvanced && (
              <div className="grid grid-cols-3 gap-2 pt-1">
                <label className="flex flex-col gap-0.5">
                  <span className="text-[10px] text-muted">FFT size</span>
                  <select
                    className="input !text-xs !py-1 !px-2 font-mono"
                    value={fftSize}
                    onChange={(e) => setFftSize(e.target.value)}
                  >
                    {["256","512","1024","2048","4096","8192"].map((v) => <option key={v}>{v}</option>)}
                  </select>
                </label>
                <label className="flex flex-col gap-0.5">
                  <span className="text-[10px] text-muted">Averaging</span>
                  <select
                    className="input !text-xs !py-1 !px-2 font-mono"
                    value={fftAverage}
                    onChange={(e) => setFftAverage(e.target.value as any)}
                  >
                    <option value="">default</option>
                    <option value="off">off</option>
                    <option value="low">low</option>
                    <option value="medium">medium</option>
                    <option value="high">high</option>
                  </select>
                </label>
                <label className="flex flex-col gap-0.5">
                  <span className="text-[10px] text-muted">Antenna</span>
                  <input
                    type="text"
                    className="input !text-xs !py-1 !px-2 font-mono"
                    placeholder="(default)"
                    value={antenna}
                    onChange={(e) => setAntenna(e.target.value)}
                  />
                </label>
              </div>
            )}

            {launchFreqHz > 0 ? (
              <div className="text-[11px] text-muted font-mono pt-1 border-t border-border/50">
                Launching: <span className="text-slate-200">{(launchFreqHz / 1e6).toFixed(3)} MHz</span> @
                <span className="text-slate-200"> {(launchSpanHz / 1e6).toFixed(2)} MS/s</span>
                {gainDb && <>, gain <span className="text-slate-200">{gainDb} dB</span></>}
              </div>
            ) : (
              <div className="text-[11px] text-warn pt-1 border-t border-border/50">
                No center freq — enter one or set rf_freq in Config first.
              </div>
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
                  !launchFreqHz ? "Center freq required" :
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
        </div>,
        document.body
      )}
    </div>
  );
}
