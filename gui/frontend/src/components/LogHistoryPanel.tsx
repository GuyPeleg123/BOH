import { useEffect, useMemo, useRef, useState } from "react";
import { api, type RunLog } from "../lib/api";

function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(2)} MB`;
}

// Run tag is "YYYY-MM-DD_HH-MM-SS" → split into date + clock for display.
function fmtRun(run: string): { date: string; time: string } {
  const m = run.match(/^(\d{4}-\d{2}-\d{2})_(\d{2})-(\d{2})-(\d{2})$/);
  if (m) return { date: m[1], time: `${m[2]}:${m[3]}:${m[4]}` };
  return { date: run, time: "" };
}

// ── log parsing ──────────────────────────────────────────────────────────────
// A sniffer.log is mostly UHD/B200 driver INFO noise. We classify each line so
// the meaningful bits (config, radios, warnings, errors) stand out, and distil
// a plain-language summary. The exact raw text stays available via the Raw view.

type Sev = "header" | "error" | "warn" | "event" | "info";

function classify(line: string): Sev {
  const l = line.trim();
  if (!l) return "info";
  if (l.startsWith("#")) return "header";
  if (/\b(error|cannot|could ?n[o']t|abort|segfault|terminate|unable|invalid|exception)\b/i.test(l)
      && !/\b0 errors?\b/i.test(l)) return "error";
  if (/\b(fail(ed|ure)?|warn(ing)?|retry|skipp?ed|dropp?ed|timeout|not found)\b/i.test(l)) return "warn";
  if (/Detected Device|GPSDO|\[GPS\]|Found Cell_id|\bPPS\b|clock rate|Operating over USB|MULTI_USRP|ref_locked|gps_locked/i.test(l))
    return "event";
  return "info";
}

const MODE: Record<string, string> = { "0": "Downlink only", "1": "Uplink only", "2": "Dual (DL + UL)" };

interface Chip { label: string; value: string; accent?: boolean; }

function parseArgv(argvLine: string): Chip[] {
  const rest = argvLine.replace(/^#?\s*argv:\s*/i, "");
  const toks = rest.split(/\s+/).filter(Boolean);
  const val: Record<string, string> = {};
  const takesVal = new Set(["-f", "-u", "-g", "-G", "-A", "-a", "-m", "-X", "-Z", "-z", "-q", "-W", "-S", "-T", "-K", "-J", "-l", "-N", "-b", "-t"]);
  for (let i = 0; i < toks.length; i++) {
    const t = toks[i];
    if (t.startsWith("-")) {
      if (takesVal.has(t)) { val[t] = toks[i + 1] ?? ""; i++; }
    }
  }
  const chips: Chip[] = [];
  const mhz = (hz: string) => `${(parseInt(hz, 10) / 1e6).toFixed(1)} MHz`;
  if (val["-m"]) chips.push({ label: "Mode", value: MODE[val["-m"]] ?? val["-m"], accent: true });
  if (val["-f"]) chips.push({ label: "Downlink", value: mhz(val["-f"]) });
  if (val["-u"]) chips.push({ label: "Uplink", value: mhz(val["-u"]) });
  if (val["-g"]) chips.push({ label: "RX gain", value: `${val["-g"]} dB` });
  if (val["-G"]) chips.push({ label: "UL gain", value: `${val["-G"]} dB` });
  if (val["-A"]) chips.push({ label: "RX antennas", value: val["-A"] });
  const radios: string[] = [];
  let clock = "";
  for (const k of ["-X", "-Z", "-a"]) {
    const v = val[k]; if (!v) continue;
    const cm = v.match(/clock=(\w+)/); if (cm) clock = cm[1];
    const sm = v.match(/serial=([A-Za-z0-9]+)/); if (sm && !radios.includes(sm[1])) radios.push(sm[1]);
  }
  if (clock) chips.push({ label: "Clock", value: clock === "external" ? "External (shared)" : clock });
  if (radios.length) chips.push({ label: radios.length > 1 ? "Radios" : "Radio", value: radios.join(", ") });
  if (val["-K"] !== undefined) chips.push({ label: "Decrypt", value: "on" });
  if (val["-l"] !== undefined || val["-N"] !== undefined) chips.push({ label: "PCI pin", value: "on" });
  return chips;
}

function parseHardware(text: string): string[] {
  const out: string[] = [];
  const dev = [...text.matchAll(/Detected Device:\s*(B\d+)/g)].map((m) => m[1]);
  if (dev.length) out.push(`${dev.length}× ${dev[0]}`);
  const usb = text.match(/Operating over (USB \d)/); if (usb) out.push(usb[1]);
  const gps = [...new Set([...text.matchAll(/Found an internal GPSDO:\s*([^,\n]+)/g)].map((m) => m[1].trim()))];
  if (gps.length) out.push(`GPSDO ${gps.join(" / ")}`);
  const clk = [...text.matchAll(/Actually got clock rate\s*([\d.]+ MHz)/g)].pop();
  if (clk) out.push(`Master clock ${clk[1]}`);
  if (/MULTI_USRP/.test(text)) out.push("Dual-radio PPS sync");
  return out;
}

function parseCell(text: string): string | null {
  const chosen = text.match(/\*Found Cell_id:\s*(\d+)\s+(FDD|TDD)/);
  const any = [...text.matchAll(/Found Cell_id:\s*(\d+)\s+(FDD|TDD)/g)];
  const m = chosen ?? (any.length ? any[any.length - 1] : null);
  return m ? `PCI ${m[1]} · ${m[2]}` : null;
}

interface Parsed {
  runTag: string | null;
  config: Chip[];
  hardware: string[];
  cell: string | null;
  status: "ok" | "warn" | "error";
  counts: { warn: number; error: number };
  lines: { text: string; sev: Sev }[];
}

function parseLog(text: string): Parsed {
  const rawLines = text.split("\n");
  const lines = rawLines.map((text) => ({ text, sev: classify(text) }));
  const runHdr = rawLines.find((l) => /^#\s*LTESniffer run/i.test(l));
  const argvHdr = rawLines.find((l) => /argv:/i.test(l));
  let warn = 0, error = 0;
  for (const l of lines) { if (l.sev === "error") error++; else if (l.sev === "warn") warn++; }
  return {
    runTag: runHdr ? runHdr.replace(/^#\s*LTESniffer run\s*/i, "").trim() : null,
    config: argvHdr ? parseArgv(argvHdr) : [],
    hardware: parseHardware(text),
    cell: parseCell(text),
    status: error > 0 ? "error" : warn > 0 ? "warn" : "ok",
    counts: { warn, error },
    lines,
  };
}

const SEV_CLASS: Record<Sev, string> = {
  header: "text-accent font-semibold",
  error: "text-bad",
  warn: "text-warn",
  event: "text-slate-100",
  info: "text-muted",
};

// ── component ────────────────────────────────────────────────────────────────
export function LogHistoryPanel({ embedded = false }: { embedded?: boolean }) {
  const [runs, setRuns] = useState<RunLog[] | null>(null);
  const [sel, setSel] = useState<string | null>(null);   // selected run path
  const [selRun, setSelRun] = useState<string>("");       // selected run tag (for filename)
  const [text, setText] = useState<string>("");
  const [loadingText, setLoadingText] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [raw, setRaw] = useState(false);
  const [importantOnly, setImportantOnly] = useState(false);
  const [query, setQuery] = useState("");
  const [copied, setCopied] = useState(false);
  const preRef = useRef<HTMLPreElement>(null);

  function refresh() {
    api.logHistory().then((r) => setRuns(r.runs)).catch((e) => setErr(e.message));
  }
  useEffect(() => { refresh(); }, []);

  function openRun(path: string, run: string) {
    setSel(path); setSelRun(run); setLoadingText(true); setText("");
    api.logContent(path)
      .then((r) => {
        setText(r.text);
        requestAnimationFrame(() => {
          if (raw && preRef.current) preRef.current.scrollTop = preRef.current.scrollHeight;
        });
      })
      .catch((e) => setText(`Failed to load: ${e.message}`))
      .finally(() => setLoadingText(false));
  }

  const parsed = useMemo(() => (text ? parseLog(text) : null), [text]);

  const shownLines = useMemo(() => {
    if (!parsed) return [];
    const q = query.trim().toLowerCase();
    return parsed.lines.filter((l) => {
      if (importantOnly && (l.sev === "info")) return false;
      if (q && !l.text.toLowerCase().includes(q)) return false;
      return true;
    });
  }, [parsed, importantOnly, query]);

  async function copyAll() {
    try { await navigator.clipboard.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 1500); } catch { /* ignore */ }
  }
  function downloadRaw() {
    const blob = new Blob([text], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = `${selRun || "sniffer"}.log`; a.click();
    URL.revokeObjectURL(url);
  }

  const statusBadge = (s: "ok" | "warn" | "error") => {
    const map = {
      ok: { c: "text-ok bg-ok/10 border-ok/30", t: "Completed" },
      warn: { c: "text-warn bg-warn/10 border-warn/30", t: "Warnings" },
      error: { c: "text-bad bg-bad/10 border-bad/30", t: "Errors" },
    }[s];
    return <span className={`text-xs font-semibold rounded px-2 py-0.5 border ${map.c}`}>{map.t}</span>;
  };

  const body = (
    <div className="flex-1 min-h-0 grid grid-cols-[240px_1fr] gap-3">
      {/* Run list — newest first */}
      <div className="flex flex-col min-h-0 bg-bg border border-border rounded-lg">
        <div className="flex items-center justify-between px-3 py-2 border-b border-border">
          <span className="label">Runs</span>
          <button className="btn btn-secondary !px-2.5 !py-1 !text-xs" onClick={refresh} title="Reload run list">↻ Refresh</button>
        </div>
        <div className="flex-1 overflow-auto">
          {runs === null && <div className="text-muted text-sm p-3">Loading…</div>}
          {runs && runs.length === 0 && (
            <div className="text-muted text-sm p-3">No past runs yet. Start a capture to record one.</div>
          )}
          {runs?.map((r) => {
            const { date, time } = fmtRun(r.run);
            const active = sel === r.path;
            return (
              <button
                key={r.path}
                onClick={() => openRun(r.path, r.run)}
                className={`w-full text-left px-3 py-2.5 border-b border-border/40 ${active ? "bg-accent/15 text-accent" : "hover:bg-border/40 text-slate-200"}`}
              >
                <div className="font-mono text-sm">{time || r.run}</div>
                <div className="text-xs text-muted font-mono flex justify-between mt-0.5">
                  <span>{date}</span><span>{fmtBytes(r.size)}</span>
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* Right pane */}
      <div className="flex flex-col min-h-0 gap-3">
        {!sel && (
          <div className="flex-1 flex items-center justify-center bg-bg border border-border rounded-lg text-muted text-sm">
            Select a run on the left to view its log.
          </div>
        )}

        {sel && loadingText && (
          <div className="flex-1 flex items-center justify-center bg-bg border border-border rounded-lg text-muted text-sm">Loading…</div>
        )}

        {sel && !loadingText && parsed && (
          <>
            {/* Summary card */}
            <div className="bg-bg border border-border rounded-lg p-4 shrink-0">
              <div className="flex items-center gap-3 flex-wrap mb-3">
                {statusBadge(parsed.status)}
                <span className="text-slate-100 font-mono text-sm">{parsed.runTag ?? selRun}</span>
                {parsed.cell && (
                  <span className="text-xs text-accent bg-accent/10 border border-accent/25 rounded px-2 py-0.5">{parsed.cell}</span>
                )}
                <span className="ml-auto text-xs text-muted">
                  {parsed.counts.error > 0 && <span className="text-bad font-semibold">{parsed.counts.error} error{parsed.counts.error === 1 ? "" : "s"}</span>}
                  {parsed.counts.error > 0 && parsed.counts.warn > 0 && <span className="mx-1.5">·</span>}
                  {parsed.counts.warn > 0 && <span className="text-warn font-semibold">{parsed.counts.warn} warning{parsed.counts.warn === 1 ? "" : "s"}</span>}
                  {parsed.counts.error === 0 && parsed.counts.warn === 0 && <span className="text-ok">no problems detected</span>}
                </span>
              </div>

              {parsed.config.length > 0 && (
                <div className="flex flex-wrap gap-x-6 gap-y-2 mb-2">
                  {parsed.config.map((c) => (
                    <div key={c.label} className="flex flex-col">
                      <span className="text-[11px] uppercase tracking-wide text-muted">{c.label}</span>
                      <span className={`text-sm ${c.accent ? "text-accent font-medium" : "text-slate-100"}`}>{c.value}</span>
                    </div>
                  ))}
                </div>
              )}

              {parsed.hardware.length > 0 && (
                <div className="text-xs text-muted flex flex-wrap gap-x-2 gap-y-1 pt-1">
                  <span className="uppercase tracking-wide">Hardware</span>
                  {parsed.hardware.map((h, i) => (
                    <span key={i} className="text-slate-300 bg-border/40 rounded px-1.5 py-0.5">{h}</span>
                  ))}
                </div>
              )}
            </div>

            {/* Log toolbar */}
            <div className="flex items-center gap-2 flex-wrap shrink-0">
              <div className="inline-flex rounded-md border border-border overflow-hidden">
                <button
                  className={`px-3 py-1.5 text-sm transition-colors ${!importantOnly ? "bg-accent/15 text-accent" : "text-muted hover:bg-border/40"}`}
                  onClick={() => setImportantOnly(false)}>All lines</button>
                <button
                  className={`px-3 py-1.5 text-sm transition-colors border-l border-border ${importantOnly ? "bg-accent/15 text-accent" : "text-muted hover:bg-border/40"}`}
                  onClick={() => setImportantOnly(true)} title="Hide routine driver INFO — keep config, events, warnings, errors">
                  Important only
                </button>
              </div>
              <input
                className="input !w-56 !py-1.5"
                placeholder="Filter lines…"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
              />
              <span className="text-xs text-muted">{shownLines.length} / {parsed.lines.length} lines</span>
              <div className="ml-auto flex items-center gap-2">
                <button className={`px-3 py-1.5 text-sm rounded-md border transition-colors ${raw ? "border-accent text-accent bg-accent/10" : "border-border text-muted hover:bg-border/40"}`}
                        onClick={() => setRaw((v) => !v)} title="Toggle the exact, unprocessed log text">
                  {raw ? "◀ Structured" : "Raw text"}
                </button>
                <button className="btn btn-secondary !py-1.5" onClick={copyAll}>{copied ? "✓ Copied" : "⧉ Copy"}</button>
                <button className="btn btn-secondary !py-1.5" onClick={downloadRaw}>↓ Download</button>
              </div>
            </div>

            {/* Log viewer */}
            {raw ? (
              <pre
                ref={preRef}
                className="flex-1 bg-bg border border-border rounded-lg p-3 overflow-auto font-mono text-xs leading-relaxed whitespace-pre-wrap text-slate-300 min-h-0"
              >
                {text}
              </pre>
            ) : (
              <div className="flex-1 bg-bg border border-border rounded-lg overflow-auto min-h-0 font-mono text-xs leading-relaxed">
                {shownLines.length === 0 ? (
                  <div className="text-muted p-3">No lines match the current filter.</div>
                ) : (
                  shownLines.map((l, i) => (
                    <div key={i}
                      className={`px-3 py-0.5 whitespace-pre-wrap border-l-2 ${
                        l.sev === "error" ? "border-bad bg-bad/5" :
                        l.sev === "warn" ? "border-warn bg-warn/5" :
                        l.sev === "header" ? "border-accent" :
                        l.sev === "event" ? "border-border" : "border-transparent"
                      } ${SEV_CLASS[l.sev]}`}>
                      {l.text || " "}
                    </div>
                  ))
                )}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );

  if (embedded) {
    return (
      <div className="flex flex-col min-h-0 flex-1">
        {err && <div className="text-bad text-sm mb-2">{err}</div>}
        {body}
      </div>
    );
  }
  return (
    <div className="panel p-5 flex flex-col min-h-0">
      <h2 className="text-base font-semibold text-slate-100 mb-4">Log History</h2>
      {err && <div className="text-bad text-sm mb-2">{err}</div>}
      {body}
    </div>
  );
}
