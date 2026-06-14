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
  const [types, setTypes] = useState<string[]>(loadTypes);
  const [input, setInput] = useState("");

  useEffect(() => { saveTypes(types); }, [types]);

  // Count occurrences of each tracked type from identity `from` field.
  // Also track all unseen types observed at runtime so user can discover them.
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

  const totalTracked = types.reduce((s, t) => s + (counts.get(t) ?? 0), 0);

  return (
    <div className="panel p-3 flex flex-col min-h-0" style={{ maxHeight: "280px" }}>
      <div className="flex items-center gap-2 mb-2 flex-wrap">
        <span className="label flex-1">
          Packet type counters
          {totalTracked > 0 && (
            <span className="ml-2 text-ok font-mono text-xs">{totalTracked.toLocaleString()} total</span>
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
          <button className="btn !px-2 !py-0.5 !text-xs btn-primary" onClick={handleAdd}>+</button>
        </div>
      </div>

      <div className="flex-1 overflow-auto bg-bg border border-border rounded">
        <table className="w-full text-xs font-mono">
          <thead className="sticky top-0 bg-bg text-[10px] uppercase tracking-wide text-muted">
            <tr className="border-b border-border">
              <th className="px-2 py-1.5 text-left">Message type</th>
              <th className="px-2 py-1.5 text-right">Count</th>
              <th className="px-2 py-1.5 w-8"></th>
            </tr>
          </thead>
          <tbody>
            {types.map((t) => {
              const n = counts.get(t) ?? 0;
              return (
                <tr key={t} className="border-b border-border/30 hover:bg-panel/50">
                  <td className="px-2 py-1 text-slate-100">{t}</td>
                  <td className={`px-2 py-1 text-right font-semibold tabular-nums ${n > 0 ? "text-ok" : "text-muted"}`}>
                    {n > 0 ? n.toLocaleString() : "—"}
                  </td>
                  <td className="px-2 py-1 text-center">
                    <button
                      className="text-muted hover:text-bad transition-colors leading-none"
                      onClick={() => remove(t)}
                      title="Remove from table"
                    >×</button>
                  </td>
                </tr>
              );
            })}
            {types.length === 0 && (
              <tr>
                <td colSpan={3} className="text-center text-muted py-4">
                  No types tracked — type a message name above and press +
                </td>
              </tr>
            )}
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
