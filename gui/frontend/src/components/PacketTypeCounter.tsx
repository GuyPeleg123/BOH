import { useState, useMemo, useEffect } from "react";
import { useStore } from "../lib/store";

const DEFAULTS = [
  "MeasurementReport",
  "SecurityModeCommand",
  "SecurityModeComplete",
  "AttachRequest",
  "AttachAccept",
  "AttachComplete",
  "TAURequest",
  "TAUAccept",
  "IdentityRequest",
  "IdentityResponse",
  "AuthenticationRequest",
  "UECapabilityInformation",
  "DetachRequest",
];

const LS_KEY = "ltesniffer-packet-types";

// MAC-level frame types decoded from the per-subframe `sf` stream (classified
// by RNTI) plus MIB. These are always-present built-ins — they're radio-layer
// frame types, not NAS/RRC messages, so they can't be removed from the table.
// These are derived from the DCI *grant* stream: one count per grant the eNB
// scheduled (seen in the downlink), NOT per frame we actually decoded. Labelled
// "grants (scheduled)" so they're never mistaken for captured frames — a UL
// grant is a transmit opportunity assigned to a UE; whether we received and
// decoded that PUSCH is a separate thing (see the "captured (pcap)" rows).
const MAC_TYPES: { key: keyof AppFrameTypes; label: string }[] = [
  { key: "mib", label: "MIB" },
  { key: "sib", label: "SIB (system information)" },
  { key: "paging", label: "Paging" },
  { key: "rar", label: "RAR (random access)" },
  { key: "dl_data", label: "DL grants (scheduled)" },
  { key: "ul_data", label: "UL grants (scheduled)" },
];

// Local alias so the keys above are type-checked against the store shape.
type AppFrameTypes = {
  mib: number; sib: number; paging: number; rar: number; dl_data: number; ul_data: number;
};

type SortDir = "desc" | "asc";

interface Row {
  /** Display label */
  name: string;
  count: number;
  /** Built-in MAC frame types can't be removed; NAS/RRC custom types can. */
  builtin: boolean;
  /** Removal key for custom types (the tracked `from` string). */
  removeKey?: string;
  /** Optional hover tooltip explaining what the row counts. */
  hint?: string;
}

function loadTypes(): string[] {
  try {
    const s = localStorage.getItem(LS_KEY);
    if (s) return JSON.parse(s);
  } catch {}
  return DEFAULTS.slice();
}

function saveTypes(types: string[]) {
  try { localStorage.setItem(LS_KEY, JSON.stringify(types)); } catch {}
}

export function PacketTypeCounter() {
  const identities = useStore((s) => s.identities);
  const frameTypes = useStore((s) => s.frameTypes);
  // Ground truth: frames that actually decoded (CRC-OK) and were written to the
  // pcap, split by direction. These come from the backend polling the pcap on
  // disk — NOT from the grant stream — so they match `tshark` exactly.
  const pcapUl = useStore((s) => s.pcapUl);
  const pcapDl = useStore((s) => s.pcapDl);
  const [types, setTypes] = useState<string[]>(loadTypes);
  const [input, setInput] = useState("");
  const [sortDir, setSortDir] = useState<SortDir>("desc");

  useEffect(() => { saveTypes(types); }, [types]);

  // Count occurrences of each tracked NAS/RRC type from the identity `from`
  // field. Also track all unseen types observed at runtime for discovery.
  const { counts, observed } = useMemo(() => {
    const counts = new Map<string, number>();
    const observed = new Set<string>();
    for (const id of identities) {
      if (!id.from) continue;
      observed.add(id.from);
      counts.set(id.from, (counts.get(id.from) ?? 0) + 1);
    }
    return { counts, observed };
  }, [identities]);

  // Unseen types visible in data but not yet in the tracked list.
  const suggestions = useMemo(
    () => Array.from(observed).filter((t) => !types.includes(t)),
    [observed, types],
  );

  // Merge always-present MAC frame types (from the `sf`/`mib` stream) with the
  // tracked NAS/RRC message types (from `identity` events) into one table,
  // then sort by count in the chosen direction. MAC built-ins sort first only
  // by their count like everything else — a stable secondary order keeps the
  // table from jittering when counts tie.
  const rows = useMemo<Row[]>(() => {
    const macRows: Row[] = MAC_TYPES.map((m) => ({
      name: m.label,
      count: frameTypes[m.key] ?? 0,
      builtin: true,
    }));
    // Real decoded/captured frames from the pcap (direction-split), restricted
    // to C-RNTI (dedicated per-UE traffic: CCCH/DCCH/DTCH). Broadcast/paging/
    // RACH are excluded here because they already have their own rows above and
    // would otherwise swamp the per-UE signal (a real DL capture is ~76%
    // paging+SIB). Shown alongside the "grants (scheduled)" rows so the gap
    // between what the tower scheduled and what we actually received is visible.
    const dedicatedHint =
      "Per-UE traffic only (CCCH / DCCH / DTCH — C-RNTI). Excludes SIB, paging and RAR, " +
      "which are counted in their own rows above. The 'Frames' tile still shows the full total.";
    const capturedRows: Row[] = [
      { name: "DL data captured (pcap)", count: pcapDl, builtin: true, hint: dedicatedHint },
      { name: "UL data captured (pcap)", count: pcapUl, builtin: true, hint: dedicatedHint },
    ];
    const nasRows: Row[] = types.map((t) => ({
      name: t,
      count: counts.get(t) ?? 0,
      builtin: false,
      removeKey: t,
    }));
    const all = [...macRows, ...capturedRows, ...nasRows];
    const dir = sortDir === "desc" ? -1 : 1;
    all.sort((a, b) => {
      if (a.count !== b.count) return dir * (a.count - b.count);
      // Tie-break: built-ins before custom, then alphabetical — stable & readable.
      if (a.builtin !== b.builtin) return a.builtin ? -1 : 1;
      return a.name.localeCompare(b.name);
    });
    return all;
  }, [frameTypes, pcapUl, pcapDl, types, counts, sortDir]);

  function remove(t: string) {
    setTypes((prev) => prev.filter((x) => x !== t));
  }

  function addType(t: string) {
    const trimmed = t.trim();
    if (!trimmed || types.includes(trimmed)) return;
    setTypes((prev) => [...prev, trimmed]);
  }

  function handleAdd() {
    addType(input);
    setInput("");
  }

  // Total counts only the tracked NAS/RRC message types — the MAC built-ins
  // (esp. MIB/SIB at broadcast rates) would otherwise dominate and obscure it.
  const total = rows.reduce((s, r) => (r.builtin ? s : s + r.count), 0);

  return (
    <div className="panel p-3 flex flex-col min-h-0" style={{ maxHeight: "280px" }}>
      <div className="flex items-center gap-2 mb-2 flex-wrap">
        <span className="label flex-1">
          Packet type counters
          {total > 0 && (
            <span className="ml-2 text-ok font-mono text-xs">{total.toLocaleString()} total</span>
          )}
        </span>
        <div className="flex gap-1">
          <input
            className="bg-bg border border-border rounded px-2 py-0.5 text-xs font-mono text-slate-200 w-48 focus:outline-none focus:border-accent"
            placeholder="Add message type…"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter") handleAdd(); }}
            list="pkt-type-suggestions"
          />
          {/* datalist drives the browser's native autocomplete from observed types */}
          <datalist id="pkt-type-suggestions">
            {suggestions.map((s) => <option key={s} value={s} />)}
          </datalist>
          <button className="btn !px-3 !py-1.5 !text-sm btn-primary" onClick={handleAdd}>+</button>
        </div>
      </div>

      <div className="flex-1 overflow-auto bg-bg border border-border rounded">
        <table className="w-full text-xs font-mono">
          <thead className="sticky top-0 bg-bg text-[10px] uppercase tracking-wide text-muted">
            <tr className="border-b border-border">
              <th className="px-2 py-1.5 text-left">Message type</th>
              <th
                className="px-2 py-1.5 text-right cursor-pointer select-none hover:text-slate-200"
                onClick={() => setSortDir((d) => (d === "desc" ? "asc" : "desc"))}
                title="Sort by count"
              >
                Count <span className="text-[8px]">{sortDir === "desc" ? "▼" : "▲"}</span>
              </th>
              <th className="px-2 py-1.5 w-8"></th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={(r.builtin ? "mac:" : "nas:") + r.name} className="border-b border-border/30 hover:bg-panel/50">
                <td className="px-2 py-1 text-slate-100" title={r.hint}>
                  {r.name}
                  {r.hint && <span className="ml-1 text-muted cursor-help" title={r.hint}>ⓘ</span>}
                  {r.builtin && <span className="ml-1.5 text-[9px] uppercase text-muted">MAC</span>}
                </td>
                <td className={`px-2 py-1 text-right font-semibold tabular-nums ${r.count > 0 ? "text-ok" : "text-muted"}`}>
                  {r.count > 0 ? r.count.toLocaleString() : "—"}
                </td>
                <td className="px-2 py-1 text-center">
                  {r.builtin ? (
                    <span className="text-muted/40 leading-none" title="Built-in MAC frame type">·</span>
                  ) : (
                    <button
                      className="text-muted hover:text-bad transition-colors leading-none"
                      onClick={() => remove(r.removeKey!)}
                      title="Remove from table"
                    >×</button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {suggestions.length > 0 && (
        <div className="mt-1.5 flex items-center gap-1.5 flex-wrap text-[10px]">
          <span className="text-muted">Seen in data:</span>
          {suggestions.map((s) => (
            <button
              key={s}
              onClick={() => addType(s)}
              className="px-1.5 py-0.5 rounded border border-border text-muted hover:border-accent hover:text-accent transition-colors"
            >
              {s}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
