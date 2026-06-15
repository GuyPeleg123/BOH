import { Fragment, useEffect, useState } from "react";
import { api } from "../lib/api";
import type { CaptureFile, DecryptEntry, DecryptResponse, OrganizeEntry, OrganizeResponse } from "../lib/types";

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
  kasme: string;       // optional: 64 hex (K_ASME) to derive keys from
  nas_count: string;   // optional: NAS uplink COUNT (decimal)
  derive: boolean;     // UI: show the K_ASME+NAS derive panel for this row
}

const HEX64 = /^[0-9a-fA-F]{64}$/;

const blank = (): FormEntry => ({ rnti: "", rrcenc_key: "", upenc_key: "", cipher_algo: "EEA2", integ_algo: "EIA2", kasme: "", nas_count: "", derive: false });

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

type OutMode = "decrypt" | "organize";
type KeyMatch = "auto" | "per-rnti";

export function DecryptModal({ file, onClose, onDone }: { file: CaptureFile; onClose: () => void; onDone: () => void }) {
  const [entries, setEntries] = useState<FormEntry[]>(loadSaved);
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<DecryptResponse | null>(null);
  const [organized, setOrganized] = useState<OrganizeResponse | null>(null);
  const [clientErr, setClientErr] = useState<string | null>(null);
  const [outMode, setOutMode] = useState<OutMode>("organize");
  const [keyMatch, setKeyMatch] = useState<KeyMatch>("auto");
  // In organize+auto, RNTI is optional and keys may be empty (split-only run).
  const rntiRequired = outMode === "decrypt" || keyMatch === "per-rnti";
  const keysRequired = outMode === "decrypt";

  useEffect(() => {
    const h = (ev: KeyboardEvent) => { if (ev.key === "Escape") onClose(); };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [onClose]);

  const update = (i: number, patch: Partial<FormEntry>) =>
    setEntries((es) => es.map((e, j) => (j === i ? { ...e, ...patch } : e)));
  const addEntry = () => setEntries((es) => [...es, blank()]);
  const removeEntry = (i: number) => setEntries((es) => (es.length > 1 ? es.filter((_, j) => j !== i) : es));

  // Derive K_RRCenc/K_UPenc from a row's K_ASME + NAS count and drop them into
  // the key fields, so the user sees exactly what will be used.
  async function deriveRow(i: number) {
    setClientErr(null);
    const e = entries[i];
    if (!HEX64.test(e.kasme.trim())) { setClientErr(`K_ASME must be exactly 64 hex chars`); return; }
    if (!/^\d+$/.test(e.nas_count.trim())) { setClientErr(`NAS count must be a non-negative integer`); return; }
    try {
      const r = await api.deriveKeys({ kasme: e.kasme.trim(), nas_count: parseInt(e.nas_count.trim(), 10), cipher_algo: e.cipher_algo, integ_algo: e.integ_algo });
      if (!r.ok) { setClientErr(r.error || "derivation failed"); return; }
      update(i, { rrcenc_key: r.rrcenc_key ?? "", upenc_key: r.upenc_key ?? "" });
    } catch (err) {
      setClientErr(err instanceof Error ? err.message : String(err));
    }
  }

  async function run() {
    setClientErr(null);
    setResult(null);
    setOrganized(null);

    // A row provides keys EITHER directly (K_RRCenc/K_UPenc) OR via a K_ASME +
    // NAS uplink count that the backend derives. A row counts as "filled" if it
    // has any of those, or an RNTI. In organize+auto, a fully blank set = split-only.
    const filled = entries.filter((e) => e.rrcenc_key.trim() || e.upenc_key.trim() || e.kasme.trim() || e.rnti.trim());
    const rows = keysRequired ? entries : filled;
    if (keysRequired && rows.length === 0) { setClientErr("Add at least one key."); return; }

    const organizeKeys: OrganizeEntry[] = [];
    const decryptKeys: DecryptEntry[] = [];
    for (const e of rows) {
      let rnti: number | null = null;
      if (e.rnti.trim() || rntiRequired) {
        rnti = parseRnti(e.rnti);
        if (rnti == null && rntiRequired) { setClientErr(`Invalid RNTI "${e.rnti}" — expect hex like 0x4A01 (0–0xFFFF)`); return; }
      }
      const haveKeys = e.rrcenc_key.trim() || e.upenc_key.trim();
      let payload: Partial<DecryptEntry>;
      if (haveKeys) {
        if (!HEX32.test(e.rrcenc_key.trim())) { setClientErr(`K_RRCenc must be exactly 32 hex chars`); return; }
        if (!HEX32.test(e.upenc_key.trim())) { setClientErr(`K_UPenc must be exactly 32 hex chars`); return; }
        payload = { rrcenc_key: e.rrcenc_key.trim(), upenc_key: e.upenc_key.trim() };
      } else if (e.kasme.trim()) {
        // derive from K_ASME + NAS count (backend does TS 33.401)
        if (!HEX64.test(e.kasme.trim())) { setClientErr(`K_ASME must be exactly 64 hex chars`); return; }
        if (!/^\d+$/.test(e.nas_count.trim())) { setClientErr(`NAS count must be a non-negative integer`); return; }
        payload = { kasme: e.kasme.trim(), nas_count: parseInt(e.nas_count.trim(), 10) };
      } else if (keysRequired) {
        setClientErr(`Provide K_RRCenc+K_UPenc, or a K_ASME + NAS count to derive them`); return;
      } else {
        continue; // organize+auto blank row → skip
      }
      const common = { cipher_algo: e.cipher_algo, integ_algo: e.integ_algo };
      organizeKeys.push({ rnti, ...payload, ...common });
      if (rnti != null) decryptKeys.push({ rnti, ...payload, ...common } as DecryptEntry);
    }

    try { localStorage.setItem(LS_KEY, JSON.stringify(entries)); } catch { /* ignore */ }
    setRunning(true);
    try {
      if (outMode === "organize") {
        const r = await api.organizeSession(file.path, organizeKeys, keyMatch);
        setOrganized(r);
        if (r.ok) onDone();
      } else {
        const r = await api.decryptCapture(file.path, decryptKeys);
        setResult(r);
        if (r.ok) onDone();
      }
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
            {outMode === "organize" ? "Decrypt & Split per UE" : "Decrypt"}: <span className="text-slate-100 normal-case">{file.name}</span>
          </h2>
          <button className="btn !px-2 !py-0.5 !text-xs ml-auto" onClick={onClose}>✕ close</button>
        </div>

        <div className="flex flex-wrap items-center gap-x-4 gap-y-2 mb-3 text-xs">
          <div className="flex items-center gap-2">
            <span className="text-muted uppercase text-[10px]">Output</span>
            <label className="flex items-center gap-1 cursor-pointer">
              <input type="radio" name="outmode" checked={outMode === "organize"} onChange={() => setOutMode("organize")} />
              <span>Decrypt &amp; split per UE</span>
            </label>
            <label className="flex items-center gap-1 cursor-pointer">
              <input type="radio" name="outmode" checked={outMode === "decrypt"} onChange={() => setOutMode("decrypt")} />
              <span>Decrypt to single file</span>
            </label>
          </div>
          {outMode === "organize" && (
            <div className="flex items-center gap-2">
              <span className="text-muted uppercase text-[10px]">Keys</span>
              <label className="flex items-center gap-1 cursor-pointer">
                <input type="radio" name="keymatch" checked={keyMatch === "auto"} onChange={() => setKeyMatch("auto")} />
                <span>Auto-match to UEs</span>
              </label>
              <label className="flex items-center gap-1 cursor-pointer">
                <input type="radio" name="keymatch" checked={keyMatch === "per-rnti"} onChange={() => setKeyMatch("per-rnti")} />
                <span>By RNTI</span>
              </label>
            </div>
          )}
        </div>
        <p className="text-[11px] text-muted mb-2">
          {outMode === "organize"
            ? (keyMatch === "auto"
                ? "Splits the capture into one pcap per UE (named by TMSI/IMSI when known). Keys below are optional — each is auto-matched to whichever UE it cleanly decrypts. Leave keys empty to just split."
                : "Splits per UE and decrypts each using the key whose RNTI matches that UE.")
            : "Decrypts the whole capture per-RNTI into a single readable text + keyed pcap."}
        </p>

        <div className="overflow-auto flex-1 min-h-0">
          <table className="w-full text-xs">
            <thead className="text-[10px] uppercase text-muted">
              <tr className="border-b border-border">
                <th className="text-left px-1 py-1">RNTI (hex){!rntiRequired && <span className="text-muted normal-case"> ·opt</span>}</th>
                <th className="text-left px-1 py-1">K_RRCenc (32 hex)</th>
                <th className="text-left px-1 py-1">K_UPenc (32 hex)</th>
                <th className="text-left px-1 py-1">Cipher</th>
                <th className="text-left px-1 py-1">Integ</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {entries.map((e, i) => (
                <Fragment key={i}>
                  <tr className="border-b border-border/30">
                    <td className="px-1 py-1"><input className="input !text-xs !w-24 font-mono" placeholder="0x4A01" value={e.rnti} onChange={(ev) => update(i, { rnti: ev.target.value })} /></td>
                    <td className="px-1 py-1"><input className="input !text-xs font-mono" placeholder="32 hex chars" value={e.rrcenc_key} onChange={(ev) => update(i, { rrcenc_key: ev.target.value })} /></td>
                    <td className="px-1 py-1"><input className="input !text-xs font-mono" placeholder="32 hex chars" value={e.upenc_key} onChange={(ev) => update(i, { upenc_key: ev.target.value })} /></td>
                    <td className="px-1 py-1"><select className="input !text-xs !w-auto" value={e.cipher_algo} onChange={(ev) => update(i, { cipher_algo: ev.target.value })}>{CIPHERS.map((c) => <option key={c} value={c}>{c}</option>)}</select></td>
                    <td className="px-1 py-1"><select className="input !text-xs !w-auto" value={e.integ_algo} onChange={(ev) => update(i, { integ_algo: ev.target.value })}>{INTEGS.map((c) => <option key={c} value={c}>{c}</option>)}</select></td>
                    <td className="px-1 py-1 text-right whitespace-nowrap">
                      <button className={`text-sm px-1 ${e.derive ? "text-primary" : "text-muted"}`} title="Derive keys from K_ASME + NAS count" onClick={() => update(i, { derive: !e.derive })}>🔑</button>
                      <button className="text-bad text-sm px-1" title="remove" onClick={() => removeEntry(i)}>✕</button>
                    </td>
                  </tr>
                  {e.derive && (
                    <tr className="border-b border-border/30 bg-bg/40">
                      <td />
                      <td colSpan={5} className="px-1 pb-2">
                        <div className="flex flex-wrap items-end gap-2">
                          <label className="flex flex-col text-[10px] text-muted">K_ASME (64 hex)
                            <input className="input !text-xs font-mono !w-[34rem] max-w-full" placeholder="64 hex chars" value={e.kasme} onChange={(ev) => update(i, { kasme: ev.target.value })} />
                          </label>
                          <label className="flex flex-col text-[10px] text-muted">NAS UL count
                            <input className="input !text-xs font-mono !w-28" placeholder="e.g. 0" value={e.nas_count} onChange={(ev) => update(i, { nas_count: ev.target.value })} />
                          </label>
                          <button className="btn btn-primary !px-2 !py-0.5 !text-xs" onClick={() => deriveRow(i)}>Derive → keys</button>
                          <span className="text-[10px] text-muted">cipher/integ come from this row's dropdowns. You can also just submit — the server derives.</span>
                        </div>
                      </td>
                    </tr>
                  )}
                </Fragment>
              ))}
            </tbody>
          </table>
          <div className="flex items-center gap-3 mt-2">
            <button className="btn !px-2 !py-0.5 !text-xs" onClick={addEntry}>＋ Add UE</button>
            <span className="text-[10px] text-muted">Don't have K_RRCenc/K_UPenc? Click 🔑 on a row to derive them from K_ASME + NAS uplink count.</span>
          </div>

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

          {organized && (
            <div className="mt-3 text-xs">
              {organized.ok ? (
                <div className="border border-ok/40 rounded p-2">
                  <div className="text-ok">✓ Decrypted & split — {organized.ues.length} UE{organized.ues.length === 1 ? "" : "s"} found.</div>
                  <div className="text-muted mt-1">
                    Folder: <span className="font-mono text-slate-200 break-all">{organized.folder}</span>
                  </div>
                </div>
              ) : (
                <div className="border border-bad/40 rounded p-2 text-bad">✗ {organized.error}</div>
              )}
              {organized.note && <div className="text-warn mt-2">⚠ {organized.note}</div>}
              {organized.ok && organized.ues.length > 0 && (
                <table className="w-full mt-2 text-[11px] font-mono">
                  <thead className="text-[10px] uppercase text-muted">
                    <tr className="border-b border-border">
                      <th className="text-left px-1 py-1">UE (sub-pcap)</th>
                      <th className="text-left px-1 py-1">RNTI</th>
                      <th className="text-right px-1 py-1">Frames</th>
                      <th className="text-left px-1 py-1">Key matched</th>
                    </tr>
                  </thead>
                  <tbody>
                    {organized.ues.map((u) => (
                      <tr key={u.rnti} className="border-b border-border/30">
                        <td className="px-1 py-1 text-slate-100">
                          {u.identity ?? `rnti-${u.rnti_hex.replace(/^0x/i, "").toLowerCase()}`}
                          <span className="text-muted"> {u.sub_pcap.split("/").pop()}</span>
                        </td>
                        <td className="px-1 py-1 text-muted">{u.rnti_hex}</td>
                        <td className="px-1 py-1 text-right">{u.frames}</td>
                        <td className="px-1 py-1">
                          {u.matched_key
                            ? <span className="text-ok">{u.matched_key}{u.score ? ` (+${u.score})` : ""}</span>
                            : <span className="text-muted">—</span>}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
              {organized.ok && organized.ues.length === 0 && (
                <div className="text-muted mt-2">No recurring C-RNTIs (real UEs) found in this capture to split out.</div>
              )}
            </div>
          )}
        </div>

        <div className="flex items-center gap-2 mt-3 pt-2 border-t border-border">
          <span className="text-[11px] text-muted">Runs via tshark. Keys are remembered locally in this browser.</span>
          <button className="btn btn-primary !px-3 !py-1 !text-xs ml-auto" disabled={running} onClick={run}>
            {running
              ? (outMode === "organize" ? "Decrypting…" : "Decrypting…")
              : (outMode === "organize" ? "Decrypt & Split" : "Run Decrypt")}
          </button>
        </div>
      </div>
    </div>
  );
}
