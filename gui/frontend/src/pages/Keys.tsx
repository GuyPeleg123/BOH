import { useEffect, useMemo, useState } from "react";
import { api } from "../lib/api";
import type { KeyEntry, KeysResponse, CipherAlgo, IntegAlgo } from "../lib/types";

type Mode = "kenb" | "kasme";

const CIPHER_OPTS: ("" | CipherAlgo)[] = ["", "EEA0", "EEA1", "EEA2", "EEA3"];
const INTEG_OPTS:  ("" | IntegAlgo)[]  = ["", "EIA0", "EIA1", "EIA2", "EIA3"];

interface Draft {
  label: string;
  rntiText: string;        // hex or decimal
  mode: Mode;
  kenb: string;
  kasme: string;
  nasCountText: string;
  cipher: "" | CipherAlgo;
  integ:  "" | IntegAlgo;
  hfnHintText: string;
}

function blankDraft(): Draft {
  return {
    label: "",
    rntiText: "",
    mode: "kenb",
    kenb: "",
    kasme: "",
    nasCountText: "",
    cipher: "",
    integ:  "",
    hfnHintText: "0",
  };
}

function parseRnti(s: string): number | null {
  const t = s.trim();
  if (!t) return null;
  const n = t.toLowerCase().startsWith("0x")
    ? parseInt(t.slice(2), 16)
    : /^[0-9]+$/.test(t) ? parseInt(t, 10) : NaN;
  if (!Number.isFinite(n) || n < 0 || n > 0xFFFF) return null;
  return n;
}

function entryToDraft(e: KeyEntry): Draft {
  return {
    label: e.label ?? "",
    rntiText: `0x${e.rnti.toString(16).padStart(4, "0")}`,
    mode: e.kenb ? "kenb" : "kasme",
    kenb: e.kenb ?? "",
    kasme: e.kasme ?? "",
    nasCountText: e.nas_count != null ? String(e.nas_count) : "",
    cipher: (e.cipher_algo ?? "") as "" | CipherAlgo,
    integ:  (e.integ_algo  ?? "") as "" | IntegAlgo,
    hfnHintText: String(e.hfn_hint ?? 0),
  };
}

function draftToEntry(d: Draft): { ok: true; entry: KeyEntry } | { ok: false; err: string } {
  const rnti = parseRnti(d.rntiText);
  if (rnti == null) return { ok: false, err: "RNTI must be 0..0xFFFF (decimal or 0x-prefixed hex)" };

  const isHex64 = (s: string) => /^[0-9a-fA-F]{64}$/.test(s);

  if (d.mode === "kenb") {
    if (!isHex64(d.kenb)) return { ok: false, err: "K_eNB must be exactly 64 hex characters" };
  } else {
    if (!isHex64(d.kasme))     return { ok: false, err: "KASME must be exactly 64 hex characters" };
    if (!/^[0-9]+$/.test(d.nasCountText.trim()))
      return { ok: false, err: "NAS uplink count must be a non-negative integer" };
  }
  if ((d.cipher && !d.integ) || (!d.cipher && d.integ))
    return { ok: false, err: "Specify both cipher and integrity algorithms, or neither" };

  const hfn = d.hfnHintText.trim() === "" ? 0 : parseInt(d.hfnHintText, 10);
  if (!Number.isFinite(hfn) || hfn < 0)
    return { ok: false, err: "HFN hint must be a non-negative integer" };

  return {
    ok: true,
    entry: {
      rnti,
      label: d.label.trim() || undefined,
      kenb: d.mode === "kenb" ? d.kenb : undefined,
      kasme: d.mode === "kasme" ? d.kasme : undefined,
      nas_count: d.mode === "kasme" ? parseInt(d.nasCountText, 10) : undefined,
      cipher_algo: (d.cipher || undefined) as CipherAlgo | undefined,
      integ_algo:  (d.integ  || undefined) as IntegAlgo  | undefined,
      hfn_hint: hfn,
    },
  };
}

export function KeysPage() {
  const [resp, setResp] = useState<KeysResponse | null>(null);
  const [draft, setDraft] = useState<Draft>(blankDraft);
  const [editingIdx, setEditingIdx] = useState<number | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [status, setStatus] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const refresh = () => api.getKeys().then(setResp).catch((e) => setErr(e.message));

  useEffect(() => {
    refresh();
  }, []);

  function set<K extends keyof Draft>(k: K, v: Draft[K]) {
    setDraft((d) => ({ ...d, [k]: v }));
    setErr(null);
  }

  function startNew() {
    setEditingIdx(null);
    setDraft(blankDraft());
    setErr(null);
  }

  function startEdit(i: number) {
    if (!resp) return;
    setEditingIdx(i);
    setDraft(entryToDraft(resp.entries[i]));
    setErr(null);
  }

  async function saveEntry() {
    const parsed = draftToEntry(draft);
    if (!parsed.ok) {
      setErr(parsed.err);
      return;
    }
    const current = resp?.entries ?? [];
    const next =
      editingIdx == null
        ? [...current, parsed.entry]
        : current.map((e, i) => (i === editingIdx ? parsed.entry : e));
    await persist(next, editingIdx == null ? "added" : "updated");
    startNew();
  }

  async function deleteEntry(i: number) {
    if (!resp) return;
    if (!confirm(`Delete keys for RNTI 0x${resp.entries[i].rnti.toString(16)} ?`)) return;
    const next = resp.entries.filter((_, j) => j !== i);
    await persist(next, "removed");
  }

  async function persist(entries: KeyEntry[], action: string) {
    setBusy(true);
    setErr(null);
    try {
      const r = await api.putKeys(entries);
      setStatus(`${action} · ${r.n_entries} key(s) on disk at ${r.path}`);
      setTimeout(() => setStatus(null), 2500);
      await refresh();
    } catch (e: any) {
      setErr(e?.message ?? String(e));
    } finally {
      setBusy(false);
    }
  }

  async function saveAndRestart() {
    await persist(resp?.entries ?? [], "saved");
    try {
      await fetch("/api/capture/restart", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "null",
      });
      setStatus("saved & restarted");
      setTimeout(() => setStatus(null), 2500);
    } catch (e: any) {
      setErr(e?.message ?? String(e));
    }
  }

  const editingExisting = editingIdx != null;
  const validity = useMemo(() => draftToEntry(draft), [draft]);

  return (
    <div className="p-4 max-w-6xl mx-auto h-full overflow-auto">
      <div className="flex items-center gap-3 mb-2">
        <h1 className="text-lg font-semibold">Decryption Keys</h1>
        <span className="text-xs text-muted ml-auto">
          {resp ? `${resp.entries.length} loaded` : "…"} ·
          file: <span className="font-mono text-slate-300">{resp?.path ?? "?"}</span>
        </span>
      </div>
      <p className="text-sm text-muted mb-4 max-w-3xl">
        Keys are written to a JSON file passed to LTESniffer via <code className="font-mono text-slate-200">-K</code>.
        For each RNTI provide <strong>either</strong> the K_eNB directly, <strong>or</strong> KASME + the NAS uplink count
        that produced K_eNB. Optional cipher / integrity algorithms activate
        security immediately (otherwise the sniffer waits for RRC SecurityModeCommand).
      </p>

      <div className="grid gap-4 md:grid-cols-[1fr_22rem]">
        {/* Table of entries */}
        <div className="panel p-3 min-h-[12rem]">
          <div className="flex items-center justify-between mb-2">
            <h2 className="text-sm font-semibold uppercase tracking-wide text-muted">Loaded keys</h2>
            <div className="flex gap-2">
              <button className="btn !px-2 !py-0.5 !text-xs" onClick={refresh}>↻ refresh</button>
              <button className="btn btn-primary !px-2 !py-0.5 !text-xs" disabled={busy} onClick={saveAndRestart}>
                Save & restart capture
              </button>
            </div>
          </div>
          <div className="overflow-auto">
            <table className="w-full text-xs font-mono">
              <thead className="text-[10px] uppercase tracking-wide text-muted">
                <tr className="border-b border-border">
                  <th className="text-left  px-2 py-1.5">RNTI</th>
                  <th className="text-left  px-2 py-1.5">Label</th>
                  <th className="text-left  px-2 py-1.5">Source</th>
                  <th className="text-left  px-2 py-1.5">Algos</th>
                  <th className="text-right px-2 py-1.5">HFN</th>
                  <th className="text-right px-2 py-1.5 w-28">Actions</th>
                </tr>
              </thead>
              <tbody>
                {(resp?.entries ?? []).map((e, i) => (
                  <tr key={i} className="border-b border-border/30">
                    <td className="px-2 py-1 text-slate-100">0x{e.rnti.toString(16).padStart(4, "0")}</td>
                    <td className="px-2 py-1 text-muted truncate max-w-[10rem]">{e.label ?? "—"}</td>
                    <td className="px-2 py-1">
                      {e.kenb ? (
                        <span className="px-1.5 py-0.5 rounded bg-accent/20 text-accent text-[10px] uppercase">K_eNB</span>
                      ) : (
                        <span className="px-1.5 py-0.5 rounded bg-warn/20 text-warn text-[10px] uppercase">
                          KASME · n={e.nas_count}
                        </span>
                      )}
                    </td>
                    <td className="px-2 py-1 text-muted">
                      {e.cipher_algo && e.integ_algo ? `${e.cipher_algo} / ${e.integ_algo}` : "—"}
                    </td>
                    <td className="px-2 py-1 text-right">{e.hfn_hint ?? 0}</td>
                    <td className="px-2 py-1 text-right">
                      <button className="btn !px-2 !py-0.5 !text-[10px]" onClick={() => startEdit(i)}>edit</button>
                      <button className="btn btn-danger !px-2 !py-0.5 !text-[10px] ml-1" onClick={() => deleteEntry(i)}>del</button>
                    </td>
                  </tr>
                ))}
                {(resp?.entries.length ?? 0) === 0 && (
                  <tr><td colSpan={6} className="text-center text-muted py-6">No keys yet. Add one →</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Add / edit form */}
        <div className="panel p-3">
          <div className="flex items-center justify-between mb-2">
            <h2 className="text-sm font-semibold uppercase tracking-wide text-muted">
              {editingExisting ? `Edit RNTI ${draft.rntiText}` : "Add a key"}
            </h2>
            {editingExisting && (
              <button className="btn !px-2 !py-0.5 !text-xs" onClick={startNew}>+ new</button>
            )}
          </div>
          <div className="space-y-3">
            <label className="block">
              <div className="label mb-1">RNTI <span className="text-muted normal-case">(decimal or 0x-hex)</span></div>
              <input className="input font-mono" placeholder="0x1234" value={draft.rntiText}
                     onChange={(e) => set("rntiText", e.target.value)} />
            </label>
            <label className="block">
              <div className="label mb-1">Label <span className="text-muted normal-case">(optional)</span></div>
              <input className="input" placeholder="e.g. test phone, Pixel 6"
                     value={draft.label} onChange={(e) => set("label", e.target.value)} />
            </label>
            <div>
              <div className="label mb-1">Key source</div>
              <div className="flex gap-2 mb-2">
                <button className={`btn !px-2 !py-0.5 !text-xs ${draft.mode === "kenb" ? "btn-primary" : ""}`}
                        onClick={() => set("mode", "kenb")}>K_eNB (direct)</button>
                <button className={`btn !px-2 !py-0.5 !text-xs ${draft.mode === "kasme" ? "btn-primary" : ""}`}
                        onClick={() => set("mode", "kasme")}>KASME + NAS count</button>
              </div>
              {draft.mode === "kenb" ? (
                <label className="block">
                  <div className="label mb-1">K_eNB <span className="text-muted normal-case">(64 hex chars)</span></div>
                  <textarea className="input font-mono break-all leading-snug resize-y" rows={2}
                            placeholder="aabb…" value={draft.kenb}
                            onChange={(e) => set("kenb", e.target.value.replace(/\s+/g, ""))} />
                  <div className="text-[10px] text-muted mt-0.5">{draft.kenb.length}/64</div>
                </label>
              ) : (
                <>
                  <label className="block">
                    <div className="label mb-1">KASME <span className="text-muted normal-case">(64 hex chars)</span></div>
                    <textarea className="input font-mono break-all leading-snug resize-y" rows={2}
                              placeholder="aabb…" value={draft.kasme}
                              onChange={(e) => set("kasme", e.target.value.replace(/\s+/g, ""))} />
                    <div className="text-[10px] text-muted mt-0.5">{draft.kasme.length}/64</div>
                  </label>
                  <label className="block mt-2">
                    <div className="label mb-1">NAS uplink count</div>
                    <input className="input font-mono" type="number" min={0} value={draft.nasCountText}
                           onChange={(e) => set("nasCountText", e.target.value)} />
                  </label>
                </>
              )}
            </div>
            <div className="grid grid-cols-2 gap-2">
              <label className="block">
                <div className="label mb-1">Cipher</div>
                <select className="input" value={draft.cipher} onChange={(e) => set("cipher", e.target.value as any)}>
                  {CIPHER_OPTS.map((o) => <option key={o} value={o}>{o || "(unset)"}</option>)}
                </select>
              </label>
              <label className="block">
                <div className="label mb-1">Integrity</div>
                <select className="input" value={draft.integ} onChange={(e) => set("integ", e.target.value as any)}>
                  {INTEG_OPTS.map((o) => <option key={o} value={o}>{o || "(unset)"}</option>)}
                </select>
              </label>
            </div>
            <label className="block">
              <div className="label mb-1">HFN hint <span className="text-muted normal-case">(mid-session join)</span></div>
              <input className="input font-mono" type="number" min={0} value={draft.hfnHintText}
                     onChange={(e) => set("hfnHintText", e.target.value)} />
            </label>

            {err && <div className="text-xs text-bad font-mono">{err}</div>}
            {!err && !validity.ok && draft.rntiText && (
              <div className="text-xs text-warn font-mono">{validity.err}</div>
            )}
            {status && <div className="text-xs text-ok">{status}</div>}

            <div className="flex gap-2 pt-1">
              <button className="btn btn-primary" disabled={busy || !validity.ok} onClick={saveEntry}>
                {editingExisting ? "Update key" : "+ Add key"}
              </button>
              {editingExisting && (
                <button className="btn" onClick={startNew}>Cancel</button>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
