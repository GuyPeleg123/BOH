import { useEffect, useState } from "react";
import { api } from "../lib/api";
import type { CaptureFile, DecryptEntry, DecryptResponse } from "../lib/types";

const LS_KEY = "ltesniffer-decrypt-entries";
const CIPHERS = ["EEA0", "EEA1", "EEA2", "EEA3"];
const INTEGS = ["EIA0", "EIA1", "EIA2", "EIA3"];
const HEX32 = /^[0-9a-fA-F]{32}$/;

interface FormEntry {
  rnti: string; // hex (with/without 0x) or decimal
  rrcenc_key: string;
  upenc_key: string;
  cipher_algo: string;
  integ_algo: string;
}

const blank = (): FormEntry => ({ rnti: "", rrcenc_key: "", upenc_key: "", cipher_algo: "EEA2", integ_algo: "EIA2" });

function loadSaved(): FormEntry[] {
  try {
    const arr = JSON.parse(localStorage.getItem(LS_KEY) ?? "");
    if (Array.isArray(arr) && arr.length) return arr.map((e) => ({ ...blank(), ...e }));
  } catch { /* ignore */ }
  return [blank()];
}

function parseRnti(s: string): number | null {
  const t = s.trim().replace(/^0x/i, "");
  if (!/^[0-9a-fA-F]+$/.test(t)) return null;
  const n = parseInt(t, 16);
  return Number.isFinite(n) && n >= 0 && n <= 0xffff ? n : null;
}

export function DecryptModal({ file, onClose, onDone }: { file: CaptureFile; onClose: () => void; onDone: () => void }) {
  const [entries, setEntries] = useState<FormEntry[]>(loadSaved);
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<DecryptResponse | null>(null);
  const [clientErr, setClientErr] = useState<string | null>(null);

  useEffect(() => {
    const h = (ev: KeyboardEvent) => { if (ev.key === "Escape") onClose(); };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [onClose]);

  const update = (i: number, patch: Partial<FormEntry>) =>
    setEntries((es) => es.map((e, j) => (j === i ? { ...e, ...patch } : e)));
  const addEntry = () => setEntries((es) => [...es, blank()]);
  const removeEntry = (i: number) => setEntries((es) => (es.length > 1 ? es.filter((_, j) => j !== i) : es));

  async function run() {
    setClientErr(null);
    setResult(null);
    const parsed: DecryptEntry[] = [];
    for (const e of entries) {
      const rnti = parseRnti(e.rnti);
      if (rnti == null) { setClientErr(`Invalid RNTI "${e.rnti}" — expect hex like 0x4A01 (0–0xFFFF)`); return; }
      if (!HEX32.test(e.rrcenc_key.trim())) { setClientErr(`RNTI ${e.rnti}: K_RRCenc must be exactly 32 hex chars`); return; }
      if (!HEX32.test(e.upenc_key.trim())) { setClientErr(`RNTI ${e.rnti}: K_UPenc must be exactly 32 hex chars`); return; }
      parsed.push({ rnti, rrcenc_key: e.rrcenc_key.trim(), upenc_key: e.upenc_key.trim(), cipher_algo: e.cipher_algo, integ_algo: e.integ_algo });
    }
    try { localStorage.setItem(LS_KEY, JSON.stringify(entries)); } catch { /* ignore */ }
    setRunning(true);
    try {
      const r = await api.decryptCapture(file.path, parsed);
      setResult(r);
      if (r.ok) onDone();
    } catch (e) {
      setClientErr(e instanceof Error ? e.message : String(e));
    } finally {
      setRunning(false);
    }
  }

  function downloadDecoded() {
    if (!result) return;
    const blob = new Blob([result.decoded_text], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = file.name.replace(/\.pcap$/i, "") + "_decrypted.txt";
    a.click();
    URL.revokeObjectURL(url);
  }

  const hint = (() => {
    if (!result) return null;
    if (!result.ok) return result.error || "tshark failed — see stderr below.";
    if (result.frames_rewritten === 0) return "No frames carried RNTI/UEId tags — is this a LTESniffer MAC-LTE pcap?";
    if (result.ndecoded === 0) return "No PDCP-LTE frames found in the capture — nothing to decrypt.";
    return "If packets below still show as ciphered/undecoded, the key or cipher algorithm is likely wrong — try the matching EEA/EIA, and capture from the connection start so the HFN lines up.";
  })();

  return (
    <div className="fixed inset-0 z-50 bg-black/60 flex items-center justify-center p-4" onClick={onClose}>
      <div className="panel w-full max-w-3xl max-h-[90vh] flex flex-col p-4" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center mb-3">
          <h2 className="text-sm font-semibold uppercase tracking-wide text-muted">
            Decrypt: <span className="text-slate-100 normal-case">{file.name}</span>
          </h2>
          <button className="btn !px-2 !py-0.5 !text-xs ml-auto" onClick={onClose}>✕ close</button>
        </div>

        <div className="overflow-auto flex-1 min-h-0">
          <table className="w-full text-xs">
            <thead className="text-[10px] uppercase text-muted">
              <tr className="border-b border-border">
                <th className="text-left px-1 py-1">RNTI (hex)</th>
                <th className="text-left px-1 py-1">K_RRCenc (32 hex)</th>
                <th className="text-left px-1 py-1">K_UPenc (32 hex)</th>
                <th className="text-left px-1 py-1">Cipher</th>
                <th className="text-left px-1 py-1">Integ</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {entries.map((e, i) => (
                <tr key={i} className="border-b border-border/30">
                  <td className="px-1 py-1"><input className="input !text-xs !w-24 font-mono" placeholder="0x4A01" value={e.rnti} onChange={(ev) => update(i, { rnti: ev.target.value })} /></td>
                  <td className="px-1 py-1"><input className="input !text-xs font-mono" placeholder="32 hex chars" value={e.rrcenc_key} onChange={(ev) => update(i, { rrcenc_key: ev.target.value })} /></td>
                  <td className="px-1 py-1"><input className="input !text-xs font-mono" placeholder="32 hex chars" value={e.upenc_key} onChange={(ev) => update(i, { upenc_key: ev.target.value })} /></td>
                  <td className="px-1 py-1"><select className="input !text-xs !w-auto" value={e.cipher_algo} onChange={(ev) => update(i, { cipher_algo: ev.target.value })}>{CIPHERS.map((c) => <option key={c} value={c}>{c}</option>)}</select></td>
                  <td className="px-1 py-1"><select className="input !text-xs !w-auto" value={e.integ_algo} onChange={(ev) => update(i, { integ_algo: ev.target.value })}>{INTEGS.map((c) => <option key={c} value={c}>{c}</option>)}</select></td>
                  <td className="px-1 py-1 text-right"><button className="text-bad text-sm px-1" title="remove" onClick={() => removeEntry(i)}>✕</button></td>
                </tr>
              ))}
            </tbody>
          </table>
          <button className="btn !px-2 !py-0.5 !text-xs mt-2" onClick={addEntry}>＋ Add UE</button>

          {clientErr && <div className="mt-3 text-bad text-xs font-mono border border-bad/40 rounded p-2">{clientErr}</div>}

          {result && (
            <div className="mt-3 text-xs">
              {result.ok ? (
                <div className="border border-ok/40 rounded p-2">
                  <div className="text-ok">✓ Decrypt run complete.</div>
                  <div className="text-muted mt-1">
                    UEId rewritten on {result.frames_rewritten} frames · {result.ndecoded} PDCP frames in decode ·
                    keyed pcap saved (now in Captures): <span className="font-mono text-slate-200 break-all">{result.keyed_pcap_path}</span>
                  </div>
                </div>
              ) : (
                <div className="border border-bad/40 rounded p-2 text-bad">✗ {result.error}</div>
              )}
              {result.note && <div className="text-warn mt-2">⚠ {result.note}</div>}
              {hint && <div className="text-muted mt-2">{hint}</div>}
              {result.stderr && (
                <pre className="mt-2 bg-bg border border-border rounded p-2 overflow-auto max-h-32 text-[10px] text-muted whitespace-pre-wrap">{result.stderr}</pre>
              )}
              {result.ok && (
                <div className="mt-2 flex gap-2">
                  <button className="btn btn-primary !px-2 !py-0.5 !text-xs" onClick={downloadDecoded}>↓ decoded .txt</button>
                </div>
              )}
              {result.ok && result.decoded_text && (
                <pre className="mt-2 bg-bg border border-border rounded p-2 overflow-auto max-h-64 text-[10px] text-slate-200 whitespace-pre-wrap font-mono">
                  {result.decoded_text.slice(0, 20000)}{result.decoded_text.length > 20000 ? "\n…(download for full)…" : ""}
                </pre>
              )}
              {result.ok && result.uat_text && (
                <details className="mt-2">
                  <summary className="text-muted text-[11px] cursor-pointer">Wireshark keys (.uat) — drop into ~/.config/wireshark/ then open the keyed pcap</summary>
                  <pre className="mt-1 bg-bg border border-border rounded p-2 overflow-auto max-h-32 text-[10px] text-slate-300 whitespace-pre-wrap font-mono">{result.uat_text}</pre>
                </details>
              )}
            </div>
          )}
        </div>

        <div className="flex items-center gap-2 mt-3 pt-2 border-t border-border">
          <span className="text-[11px] text-muted">Runs via tshark. Keys are remembered locally in this browser.</span>
          <button className="btn btn-primary !px-3 !py-1 !text-xs ml-auto" disabled={running} onClick={run}>
            {running ? "Decrypting…" : "Run Decrypt"}
          </button>
        </div>
      </div>
    </div>
  );
}
