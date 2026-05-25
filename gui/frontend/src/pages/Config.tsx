import { useEffect, useState } from "react";
import { api } from "../lib/api";
import type { SnifferConfig, USRPDevice } from "../lib/types";

type Section = {
  title: string;
  fields: { key: keyof SnifferConfig; label: string; hint?: string; flag: string; widget?: "freq" | "select" | "text" }[];
  selectOptions?: Partial<Record<keyof SnifferConfig, { value: number | string; label: string }[]>>;
};

const SECTIONS: Section[] = [
  {
    title: "RF / hardware",
    fields: [
      { key: "rf_freq",       label: "DL frequency (Hz)", flag: "-f", widget: "freq" },
      { key: "ul_freq",       label: "UL frequency (Hz)", flag: "-u", widget: "freq" },
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
      { key: "nof_prb",      label: "PRBs (fixed cell)", flag: "-p" },
      { key: "target_rnti",  label: "Target RNTI (0 = all)", flag: "-r" },
    ],
    selectOptions: {
      sniffer_mode: [
        { value: 0, label: "0 — DL only" },
        { value: 1, label: "1 — UL only" },
        { value: 2, label: "2 — Dual (2 USRPs)" },
      ],
      api_mode: [
        { value: -1, label: "-1 — disabled" },
        { value: 0,  label: "0 — identity mapping" },
        { value: 1,  label: "1 — IMSI collecting" },
        { value: 2,  label: "2 — UE capability" },
        { value: 3,  label: "3 — all" },
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
      { key: "pcap_file",       label: "PCAP file", flag: "-F", widget: "text" },
      { key: "dci_file_name",   label: "DCI output (empty = stdout)", flag: "-D", widget: "text" },
      { key: "stats_file_name", label: "Stats file", flag: "-E", widget: "text" },
      { key: "keys_file",       label: "PDCP key JSON", flag: "-K", widget: "text" },
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
  const [cfg, setCfg] = useState<SnifferConfig | null>(null);
  const [usrps, setUsrps] = useState<USRPDevice[]>([]);
  const [busy, setBusy] = useState(false);
  const [autoMsg, setAutoMsg] = useState<string | null>(null);
  const [saved, setSaved] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    api.getConfig().then(setCfg).catch((e) => setErr(e.message));
    api.usrps().then((r) => setUsrps(r.devices)).catch(() => {});
  }, []);

  async function autoDetect() {
    setBusy(true);
    setErr(null);
    setAutoMsg(null);
    try {
      const patch = await api.get<Record<string, any>>("/api/usrps/autoconfig");
      // Apply non-metadata fields to the config
      const validKeys = Object.keys(patch).filter((k) => !k.startsWith("_"));
      if (validKeys.length > 0) {
        setCfg((c) => c ? { ...c, ...Object.fromEntries(validKeys.map((k) => [k, patch[k]])) } : c);
      }
      setAutoMsg(patch._message ?? "Auto-detect complete.");
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

  function field(s: Section, f: Section["fields"][number]) {
    const v = cfg![f.key] as any;
    const isBool = typeof v === "boolean";
    const isText = f.widget === "text";
    const isFreq = f.widget === "freq";
    const isSelect = f.widget === "select";
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
            {(s.selectOptions?.[f.key] ?? []).map((o) => (
              <option key={String(o.value)} value={String(o.value)}>
                {o.label}
              </option>
            ))}
          </select>
        ) : isText ? (
          <input
            className="input font-mono"
            value={v as string}
            onChange={(e) => up(f.key, e.target.value as any)}
          />
        ) : isFreq ? (
          <div className="flex gap-2 items-center">
            <input
              className="input font-mono"
              type="number"
              step="any"
              value={(v as number) / 1e6 || ""}
              onChange={(e) => up(f.key, ((+e.target.value || 0) * 1e6) as any)}
            />
            <span className="text-xs text-muted">MHz</span>
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
      <div className="flex items-center mb-4 gap-3 flex-wrap">
        <h1 className="text-lg font-semibold">Sniffer Configuration</h1>
        <div className="ml-auto flex items-center gap-2 flex-wrap">
          {autoMsg && <span className="text-ok text-xs max-w-xs truncate" title={autoMsg}>{autoMsg}</span>}
          {saved && <span className="text-ok text-sm">{saved}</span>}
          {err && <span className="text-bad text-sm font-mono">{err}</span>}
          <button className="btn" disabled={busy} onClick={autoDetect} title="Detect connected USRPs and fill serial/rfargs automatically">
            🔍 Auto-detect USRPs
          </button>
          <button className="btn" disabled={busy} onClick={save}>Save</button>
          <button className="btn btn-primary" disabled={busy} onClick={saveAndRestart}>
            Save & Restart
          </button>
        </div>
      </div>

      {usrps.length > 0 && (
        <div className="panel p-4 mb-4">
          <div className="label mb-2">Detected USRPs</div>
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
