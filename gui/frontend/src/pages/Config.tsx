import { useEffect, useRef, useState } from "react";
import { api } from "../lib/api";
import { useStore } from "../lib/store";
import type { SnifferConfig, USRPDevice } from "../lib/types";

// Fields that auto-detect is allowed to overwrite
const HARDWARE_KEYS = new Set(["sniffer_mode", "rf_args", "usrp_a_args", "usrp_b_args"]);

// LTE FDD band table for UL freq suggestion
const LTE_FDD_BANDS: { band: number; dl_low: number; dl_high: number; offset_mhz: number }[] = [
  { band: 1,  dl_low: 2110, dl_high: 2170, offset_mhz: -190 },
  { band: 2,  dl_low: 1930, dl_high: 1990, offset_mhz: -80  },
  { band: 3,  dl_low: 1805, dl_high: 1880, offset_mhz: -95  },
  { band: 4,  dl_low: 2110, dl_high: 2155, offset_mhz: -400 },
  { band: 5,  dl_low: 869,  dl_high: 894,  offset_mhz: -45  },
  { band: 7,  dl_low: 2620, dl_high: 2690, offset_mhz: -120 },
  { band: 8,  dl_low: 935,  dl_high: 960,  offset_mhz: -45  },
  { band: 12, dl_low: 729,  dl_high: 746,  offset_mhz: -30  },
  { band: 13, dl_low: 746,  dl_high: 756,  offset_mhz: 31   },
  { band: 17, dl_low: 734,  dl_high: 746,  offset_mhz: -30  },
  { band: 20, dl_low: 791,  dl_high: 821,  offset_mhz: 41   },
  { band: 25, dl_low: 1930, dl_high: 1995, offset_mhz: -80  },
  { band: 26, dl_low: 859,  dl_high: 894,  offset_mhz: -45  },
  { band: 28, dl_low: 758,  dl_high: 803,  offset_mhz: -55  },
  { band: 30, dl_low: 2350, dl_high: 2360, offset_mhz: -45  },
  { band: 66, dl_low: 2110, dl_high: 2200, offset_mhz: -400 },
];

function suggestUlFreq(dl_hz: number): { band: number; ul_mhz: number } | null {
  const dl_mhz = dl_hz / 1e6;
  for (const b of LTE_FDD_BANDS) {
    if (dl_mhz >= b.dl_low && dl_mhz <= b.dl_high) {
      return { band: b.band, ul_mhz: Math.round((dl_mhz + b.offset_mhz) * 10) / 10 };
    }
  }
  return null;
}

type SelectOption = { value: number | string; label: string; requiresUsrps?: number };

type Section = {
  title: string;
  fields: { key: keyof SnifferConfig; label: string; hint?: string; flag: string; widget?: "freq" | "select" | "text" }[];
  selectOptions?: Partial<Record<keyof SnifferConfig, SelectOption[]>>;
};

const SECTIONS: Section[] = [
  {
    title: "RF / hardware",
    fields: [
      { key: "rf_freq",       label: "DL frequency (MHz)", flag: "-f", widget: "freq" },
      { key: "ul_freq",       label: "UL frequency (MHz)", flag: "-u", widget: "freq" },
      { key: "rf_gain",       label: "RX gain (dB, -1 = AGC)", flag: "-g" },
      { key: "rf_nof_rx_ant", label: "RX antennas", flag: "-A" },
      { key: "rf_args",       label: "rfargs (single-USRP)", flag: "-a", widget: "text" },
      { key: "usrp_a_args",   label: "USRP A rfargs (dual — DL device)", flag: "-X", widget: "text",
        hint: "Dual-USRP mode: e.g. clock=gpsdo,serial=<A_serial>  — use Auto-detect to fill" },
      { key: "usrp_b_args",   label: "USRP B rfargs (dual — UL device)", flag: "-Z", widget: "text",
        hint: "Dual-USRP mode: e.g. clock=gpsdo,serial=<B_serial>  — use Auto-detect to fill" },
      { key: "decimate",      label: "Decimate", flag: "-Y" },
      { key: "cpu_affinity",  label: "CPU affinity mask (-1 disable)", flag: "-y" },
    ],
  },
  {
    title: "Cell & mode",
    fields: [
      { key: "sniffer_mode", label: "Sniffer mode", flag: "-m", widget: "select" },
      { key: "api_mode",     label: "API mode",     flag: "-z", widget: "select" },
      { key: "cell_search",  label: "Enable cell search (-C)", flag: "-C" },
      { key: "cell_id",      label: "Fixed cell ID (when -C off)", flag: "-I" },
      { key: "nof_prb",      label: "PRBs (fixed cell)", flag: "-p", widget: "select" },
      { key: "target_rnti",  label: "Target RNTI (0 = all)", flag: "-r" },
    ],
    selectOptions: {
      sniffer_mode: [
        { value: 0, label: "0 — DL only" },
        { value: 1, label: "1 — UL only",        requiresUsrps: 2 },
        { value: 2, label: "2 — Dual (2 USRPs)", requiresUsrps: 2 },
      ],
      api_mode: [
        { value: -1, label: "-1 — disabled" },
        { value: 0,  label: "0 — identity mapping" },
        { value: 1,  label: "1 — IMSI collecting" },
        { value: 2,  label: "2 — UE capability" },
        { value: 3,  label: "3 — all" },
      ],
      // Only legal LTE bandwidths — prevents an invalid value (e.g. 125) that
      // crashes the FFT/MIB init with "Invalid number of PRB".
      nof_prb: [
        { value: 6,   label: "6 — 1.4 MHz" },
        { value: 15,  label: "15 — 3 MHz" },
        { value: 25,  label: "25 — 5 MHz" },
        { value: 50,  label: "50 — 10 MHz" },
        { value: 75,  label: "75 — 15 MHz" },
        { value: 100, label: "100 — 20 MHz" },
      ],
    },
  },
  {
    title: "Decoder",
    fields: [
      { key: "nof_sniffer_thread", label: "Worker threads", flag: "-W" },
      { key: "skip_secondary_meta_formats", label: "Skip secondary DCI formats", flag: "-s" },
      { key: "dci_format_split_ratio", label: "DCI split ratio", flag: "-S" },
      { key: "dci_format_split_update_interval_ms", label: "DCI split interval (ms)", flag: "-T" },
      { key: "enable_shortcut_discovery", label: "Shortcut discovery (uncheck = -L)", flag: "-L" },
      { key: "rnti_histogram_threshold", label: "RNTI histogram threshold", flag: "-H" },
      { key: "mcs_tracking_mode", label: "MCS tracking mode", flag: "-q" },
      { key: "en_debug", label: "Debug logging", flag: "-d" },
    ],
  },
  {
    title: "Output files",
    fields: [
      { key: "dci_file_name",   label: "DCI output (empty = stdout)", flag: "-D", widget: "text" },
      { key: "stats_file_name", label: "Stats file", flag: "-E", widget: "text" },
      { key: "keys_file",       label: "PDCP key JSON", flag: "-K", widget: "text" },
      { key: "pcap_stream_fifo", label: "Live-stream FIFO (Wireshark)", flag: "", widget: "text",
        hint: "Optional named pipe (e.g. /tmp/lte.pcap). When set, the backend mkfifos this path and passes it to the C++ side as LTESNIFFER_PCAP_STREAM, so Wireshark can dissect MAC PDUs live. Must live under /tmp/ or ~/ltesniffer-captures/. Open Wireshark (Dashboard → 🦈 Wireshark button) BEFORE starting capture — the C++ writer fails silently if no reader is connected yet." },
    ],
  },
  {
    title: "GUI",
    fields: [
      { key: "binary_path",  label: "LTESniffer binary path", flag: "", widget: "text" },
      { key: "captures_dir", label: "Captures directory (pcap output)", flag: "", widget: "text",
        hint: "Sniffer runs with this as cwd; pcaps land here. Created if missing. ~ is expanded." },
      { key: "sudo",         label: "Run via sudo -n", flag: "" },
    ],
  },
];

export function ConfigPage() {
  const lifecycle = useStore((s) => s.lifecycle);

  const [cfg, setCfg] = useState<SnifferConfig | null>(null);
  const [usrps, setUsrps] = useState<USRPDevice[]>([]);
  const [knownCells, setKnownCells] = useState<import("../lib/types").KnownCell[]>([]);
  const [knownCellsPath, setKnownCellsPath] = useState<string>("");
  const [busy, setBusy] = useState(false);
  const [autoMsg, setAutoMsg] = useState<string | null>(null);
  const [gpsdoMsg, setGpsdoMsg] = useState<string | null>(null);
  const [saved, setSaved] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const autoMsgTimerRef = useRef<number | null>(null);
  const gpsdoMsgTimerRef = useRef<number | null>(null);

  // --- helpers ---

  function showAutoMsg(msg: string, ttl = 8000) {
    setAutoMsg(msg);
    if (autoMsgTimerRef.current) window.clearTimeout(autoMsgTimerRef.current);
    autoMsgTimerRef.current = window.setTimeout(() => setAutoMsg(null), ttl);
  }

  function showGpsdoMsg(msg: string, ttl = 10000) {
    setGpsdoMsg(msg);
    if (gpsdoMsgTimerRef.current) window.clearTimeout(gpsdoMsgTimerRef.current);
    gpsdoMsgTimerRef.current = window.setTimeout(() => setGpsdoMsg(null), ttl);
  }

  function applyPatch(patch: Record<string, any>) {
    const validKeys = Object.keys(patch).filter(
      (k) => !k.startsWith("_") && HARDWARE_KEYS.has(k)
    );
    if (validKeys.length > 0) {
      setCfg((c) =>
        c ? { ...c, ...Object.fromEntries(validKeys.map((k) => [k, patch[k]])) } : c
      );
    }
  }

  function applyGpsdoResults(
    devices: Array<{ serial?: string; gpsdo: boolean }>,
    message: string
  ) {
    setCfg((c) => {
      if (!c) return c;
      let a = c.usrp_a_args;
      let b = c.usrp_b_args;
      for (const d of devices) {
        if (!d.serial || !d.gpsdo) continue;
        if (a.includes(d.serial) && !a.includes("clock=gpsdo")) {
          a = "clock=gpsdo," + a;
        }
        if (b.includes(d.serial) && !b.includes("clock=gpsdo")) {
          b = "clock=gpsdo," + b;
        }
      }
      return { ...c, usrp_a_args: a, usrp_b_args: b };
    });
    showGpsdoMsg(message);
  }

  function fireGpsdoProbe() {
    api.gpsdoProbe()
      .then((r) => applyGpsdoResults(r.devices, r.message))
      .catch(() => showGpsdoMsg("GPSDO probe failed — check that uhd_usrp_probe is installed."));
  }

  // --- mount: load the form only. NO hardware probing, ever — the radios are
  // touched only when the user explicitly clicks "Auto-detect USRPs". This
  // fully decouples the Config tab from the hardware, so opening it can never
  // disturb a running capture (no uhd_find_devices, no uhd_usrp_probe). ---
  useEffect(() => {
    api.getKnownCells()
      .then((r) => { setKnownCells(r.cells); setKnownCellsPath(r.path); })
      .catch(() => {});
    api.getConfig()
      .then(setCfg)
      .catch((e) => setErr(e.message));
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // --- known cells helpers ---

  async function refreshKnownCells() {
    try {
      const r = await api.getKnownCells();
      setKnownCells(r.cells); setKnownCellsPath(r.path);
    } catch (e: any) { setErr(e?.message ?? String(e)); }
  }

  async function loadKnownCell(idx: number) {
    setBusy(true); setErr(null);
    try {
      const r = await api.loadKnownCell(idx);
      setCfg(r.config);
      setSaved(`Loaded "${r.loaded}"`);
      setTimeout(() => setSaved(null), 2500);
    } catch (e: any) {
      setErr(e?.message ?? String(e));
    } finally {
      setBusy(false);
    }
  }

  async function deleteKnownCell(idx: number) {
    if (!confirm(`Delete known cell #${idx} "${knownCells[idx]?.label}" ?`)) return;
    setBusy(true); setErr(null);
    try {
      const r = await api.deleteKnownCell(idx);
      setSaved(`Removed "${r.removed_label}"`);
      setTimeout(() => setSaved(null), 2500);
      await refreshKnownCells();
    } catch (e: any) {
      setErr(e?.message ?? String(e));
    } finally {
      setBusy(false);
    }
  }

  async function saveCurrentAsKnownCell() {
    const label = window.prompt("Label for this known cell (operator name, location, etc.):", "");
    if (!label || !label.trim()) return;
    const notes = window.prompt("Notes (optional — what makes it noteworthy):", "") ?? "";
    setBusy(true); setErr(null);
    try {
      await api.saveCurrentAsKnownCell({ label: label.trim(), notes: notes.trim() });
      setSaved(`Saved "${label.trim()}" as known cell`);
      setTimeout(() => setSaved(null), 2500);
      await refreshKnownCells();
    } catch (e: any) {
      setErr(e?.message ?? String(e));
    } finally {
      setBusy(false);
    }
  }

  // --- manual auto-detect button (always applies, no downgrade guard) ---
  async function autoDetect() {
    setBusy(true);
    setErr(null);
    setAutoMsg(null);
    setGpsdoMsg(null);
    try {
      const patch = await api.get<Record<string, any>>("/api/usrps/autoconfig");
      applyPatch(patch);
      // Populate the "Detected USRPs" panel from this explicit probe (the mount
      // no longer auto-fills it, by design).
      setUsrps((patch._detected_devices ?? []) as USRPDevice[]);
      showAutoMsg(patch._message ?? "Auto-detect complete.", 10000);
      const count: number = patch._detected_devices?.length ?? 0;
      if (count >= 2) fireGpsdoProbe();
    } catch (e: any) {
      setErr(e?.message ?? String(e));
    } finally {
      setBusy(false);
    }
  }

  if (!cfg) return <div className="p-6 text-muted">Loading config…</div>;

  function up<K extends keyof SnifferConfig>(k: K, v: SnifferConfig[K]) {
    setCfg((c) => (c ? { ...c, [k]: v } : c));
    setSaved(null);
  }

  async function save() {
    if (!cfg) return;
    setBusy(true);
    setErr(null);
    try {
      await api.putConfig(cfg);
      setSaved("Saved");
      setTimeout(() => setSaved(null), 1500);
    } catch (e: any) {
      setErr(e?.message ?? String(e));
    } finally {
      setBusy(false);
    }
  }

  async function saveAndRestart() {
    if (!cfg) return;
    setBusy(true);
    setErr(null);
    try {
      await api.putConfig(cfg);
      await api.restart(cfg);
      setSaved("Saved & restarted");
      setTimeout(() => setSaved(null), 1500);
    } catch (e: any) {
      setErr(e?.message ?? String(e));
    } finally {
      setBusy(false);
    }
  }

  const needsUlFreq = (cfg.sniffer_mode === 1 || cfg.sniffer_mode === 2) && cfg.ul_freq === 0;
  const ulSuggestion = needsUlFreq && cfg.rf_freq > 0 ? suggestUlFreq(cfg.rf_freq) : null;

  function field(s: Section, f: Section["fields"][number]) {
    const v = cfg![f.key] as any;
    const isBool = typeof v === "boolean";
    const isText = f.widget === "text";
    const isFreq = f.widget === "freq";
    const isSelect = f.widget === "select";
    const isUlFreq = f.key === "ul_freq";

    return (
      <label key={f.key as string} className="block">
        <div className="flex justify-between items-baseline mb-1">
          <span className="label">{f.label}</span>
          {f.flag && <span className="text-[10px] font-mono text-muted">{f.flag}</span>}
        </div>
        {isBool ? (
          <label className="inline-flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              className="accent-accent w-4 h-4"
              checked={v}
              onChange={(e) => up(f.key, e.target.checked as any)}
            />
            <span className="text-muted">{v ? "enabled" : "disabled"}</span>
          </label>
        ) : isSelect ? (
          <select
            className="input"
            value={String(v)}
            onChange={(e) => up(f.key, (isNaN(+e.target.value) ? e.target.value : +e.target.value) as any)}
          >
            {(s.selectOptions?.[f.key] ?? []).map((o) => {
              const disabled = o.requiresUsrps != null && usrps.length < o.requiresUsrps;
              return (
                <option
                  key={String(o.value)}
                  value={String(o.value)}
                  disabled={disabled}
                  title={disabled ? `Requires ${o.requiresUsrps} USRPs (${usrps.length} detected)` : undefined}
                >
                  {o.label}{disabled ? " — requires 2 USRPs" : ""}
                </option>
              );
            })}
          </select>
        ) : isText ? (
          <input
            className="input font-mono"
            value={v as string}
            onChange={(e) => up(f.key, e.target.value as any)}
          />
        ) : isFreq ? (
          <div className="flex flex-col gap-1">
            <div className="flex gap-2 items-center">
              <input
                className={`input font-mono${isUlFreq && needsUlFreq ? " border-bad" : ""}`}
                type="number"
                step="any"
                value={(v as number) / 1e6 || ""}
                onChange={(e) => up(f.key, ((+e.target.value || 0) * 1e6) as any)}
              />
              <span className="text-xs text-muted">MHz</span>
            </div>
            {isUlFreq && needsUlFreq && (
              <div className="text-[11px] text-bad">
                Required for UL/Dual mode.
                {ulSuggestion && (
                  <button
                    type="button"
                    className="ml-2 underline text-accent"
                    onClick={() => up("ul_freq", ulSuggestion.ul_mhz * 1e6 as any)}
                  >
                    Use Band {ulSuggestion.band} suggestion: {ulSuggestion.ul_mhz} MHz
                  </button>
                )}
              </div>
            )}
          </div>
        ) : (
          <input
            className="input font-mono"
            type="number"
            step="any"
            value={v as number}
            onChange={(e) => up(f.key, +e.target.value as any)}
          />
        )}
        {f.hint && <div className="text-[11px] text-muted mt-1">{f.hint}</div>}
      </label>
    );
  }

  return (
    <div className="p-4 max-w-6xl mx-auto h-full overflow-auto">
      <div className="flex items-center mb-2 gap-3 flex-wrap">
        <h1 className="text-lg font-semibold">Sniffer Configuration</h1>
        <div className="ml-auto flex items-center gap-2 flex-wrap">
          {saved && <span className="text-ok text-sm">{saved}</span>}
          {err && <span className="text-bad text-sm font-mono">{err}</span>}
          <button
            className="btn"
            disabled={busy || lifecycle === "running"}
            onClick={autoDetect}
            title={lifecycle === "running"
              ? "Stop the capture first — probing USRPs would reset the running radios"
              : "Detect connected USRPs and fill serial/rfargs automatically"}
          >
            🔍 Auto-detect USRPs
          </button>
          <button className="btn" disabled={busy} onClick={save}>Save</button>
          <button className="btn btn-primary" disabled={busy} onClick={saveAndRestart}>
            Save & Restart
          </button>
        </div>
      </div>

      {/* Status banners — auto-dismiss after a few seconds */}
      {(autoMsg || gpsdoMsg) && (
        <div className="flex flex-col gap-1 mb-3">
          {autoMsg && (
            <div className={`text-xs px-3 py-1.5 rounded border ${autoMsg.includes("⚠") || autoMsg.includes("expects") ? "bg-warn/10 text-warn border-warn/20" : "bg-ok/10 text-ok border-ok/20"}`}>
              🔍 {autoMsg}
            </div>
          )}
          {gpsdoMsg && (
            <div className={`text-xs px-3 py-1.5 rounded border ${gpsdoMsg.includes("NOT") || gpsdoMsg.includes("No GPSDO") || gpsdoMsg.includes("failed") ? "bg-warn/10 text-warn border-warn/20" : "bg-ok/10 text-ok border-ok/20"}`}>
              📡 {gpsdoMsg}
            </div>
          )}
        </div>
      )}

      <div className="panel p-4 mb-4">
        <div className="flex items-baseline justify-between mb-2 gap-3">
          <span className="label">Known cells — one-click load</span>
          <button
            className="btn btn-ok !px-3 !py-1 !text-xs"
            disabled={busy || !cfg}
            onClick={saveCurrentAsKnownCell}
            title="Snapshot the current config (freq, mode, USRP, gain) as a new known cell"
          >
            + Save current as known cell
          </button>
          <span className="text-[10px] text-muted font-mono ml-auto">{knownCellsPath}</span>
        </div>
        {knownCells.length === 0 ? (
          <div className="text-xs text-muted py-3">
            No cells saved yet. Tune to a working cell in the form below, then click
            "Save current as known cell" so you can recall it later in one click.
          </div>
        ) : (
          <div className="flex flex-col gap-2">
            {knownCells.map((c, i) => (
              <div key={i} className="flex items-center gap-3 p-2 rounded border border-border bg-bg">
                <button
                  className="btn btn-primary !px-3 !py-1 !text-xs"
                  disabled={busy}
                  onClick={() => loadKnownCell(i)}
                  title="Copy these settings into the config form below"
                >
                  ↓ Load
                </button>
                <div className="flex-1 min-w-0">
                  <div className="text-sm text-slate-100 truncate">{c.label}</div>
                  <div className="text-xs text-muted font-mono">
                    DL <span className="text-slate-200">{c.dl_freq_mhz}</span> MHz ·
                    UL <span className="text-slate-200">{c.ul_freq_mhz}</span> MHz ·
                    {c.bandwidth_mhz != null && <> {c.bandwidth_mhz} MHz BW ·</>}
                    {c.nof_prb} PRB · mode {c.sniffer_mode}
                    {c.pci != null && <> · PCI {c.pci}</>}
                  </div>
                  {c.notes && <div className="text-[11px] text-muted mt-0.5 truncate" title={c.notes}>{c.notes}</div>}
                </div>
                {c.last_success_iso && (
                  <span className="text-[10px] text-muted font-mono whitespace-nowrap">{c.last_success_iso}</span>
                )}
                <button
                  className="btn btn-danger !px-2 !py-0.5 !text-[10px]"
                  disabled={busy}
                  onClick={() => deleteKnownCell(i)}
                  title="Remove this cell from the registry"
                >
                  ✕
                </button>
              </div>
            ))}
          </div>
        )}
      </div>

      {usrps.length > 0 && (
        <div className="panel p-4 mb-4">
          <div className="label mb-2">
            Detected USRPs
            <span className={`ml-2 text-[10px] font-mono px-1.5 py-0.5 rounded ${usrps.length >= 2 ? "bg-ok/20 text-ok" : "bg-warn/20 text-warn"}`}>
              {usrps.length} connected
            </span>
          </div>
          <div className="flex flex-wrap gap-2">
            {usrps.map((d, i) => (
              <button
                key={i}
                className="btn !px-2 !py-1 !text-xs font-mono"
                title="Click to copy a sample rfargs string"
                onClick={() =>
                  up(
                    "rf_args",
                    `clock=gpsdo${d.serial ? `,serial=${d.serial}` : ""}${d.type ? `,type=${d.type}` : ""}`
                  )
                }
              >
                {d.product ?? d.type ?? "USRP"} · {d.serial ?? "?"}
              </button>
            ))}
            {usrps.length < 2 && (
              <span className="text-xs text-muted self-center">UL and Dual modes require 2 USRPs</span>
            )}
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {SECTIONS.map((s) => (
          <div className="panel p-4" key={s.title}>
            <h2 className="text-sm font-semibold uppercase tracking-wide text-muted mb-3">
              {s.title}
            </h2>
            <div className="grid gap-3">{s.fields.map((f) => field(s, f))}</div>
          </div>
        ))}
      </div>
    </div>
  );
}
