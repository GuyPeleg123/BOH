import { useStore } from "../lib/store";



const kindBadge: Record<string, string> = {
  imsi: "bg-bad/20 text-bad border-bad/40",
  tmsi: "bg-warn/20 text-warn border-warn/40",
  guti: "bg-warn/20 text-warn border-warn/40",
  ue_capa: "bg-accent/20 text-accent border-accent/40",
  identity_map: "bg-ok/20 text-ok border-ok/40",
};

export function IdentitiesPanel({ embedded = false }: { embedded?: boolean }) {
  const identities = useStore((s) => s.identities);
  const state = { identities };

  const body = (
    <div className="flex-1 overflow-auto">
      {state.identities.length === 0 ? (
        <div className="text-sm text-muted text-center py-6">
          None yet. Enable API mode (-z) to collect IMSI / UECapa.
        </div>
      ) : (
        <table className="w-full text-xs font-mono">
          <thead className="text-[10px] uppercase tracking-wide text-muted">
            <tr className="border-b border-border">
              <th className="px-2 py-1.5 text-left">Kind</th>
              <th className="px-2 py-1.5 text-right">RNTI</th>
              <th className="px-2 py-1.5 text-left">Value</th>
              <th className="px-2 py-1.5 text-left">From</th>
            </tr>
          </thead>
          <tbody>
            {state.identities.map((id, i) => (
              <tr key={i} className="border-b border-border/40">
                <td className="px-2 py-1">
                  <span className={`px-1.5 py-0.5 rounded border text-[10px] uppercase ${kindBadge[id.kind] ?? "border-border text-muted"}`}>
                    {id.kind}
                  </span>
                </td>
                <td className="px-2 py-1 text-right">{id.rnti}</td>
                <td className="px-2 py-1 text-slate-100">{id.value}</td>
                <td className="px-2 py-1 text-muted">{id.from}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );

  if (embedded) return body;

  return (
    <div className="panel p-4 flex flex-col min-h-0">
      <h2 className="text-sm font-semibold uppercase tracking-wide text-muted mb-3">
        Identities ({state.identities.length})
      </h2>
      {body}
    </div>
  );
}
