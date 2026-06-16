import { useEffect, useState } from "react";
import { api } from "../lib/api";
import type { CapturesResponse, CaptureFile } from "../lib/types";
import { useStore } from "../lib/store";
import { DecryptModal } from "./DecryptModal";



function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(2)} MB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

function fmtAge(epochSec: number): string {
  const ageSec = Date.now() / 1000 - epochSec;
  if (ageSec < 60) return `${Math.floor(ageSec)}s ago`;
  if (ageSec < 3600) return `${Math.floor(ageSec / 60)}m ago`;
  if (ageSec < 86400) return `${Math.floor(ageSec / 3600)}h ago`;
  return `${Math.floor(ageSec / 86400)}d ago`;
}

export function CapturesPanel({ embedded = false }: { embedded?: boolean }) {
  const lifecycle = useStore((s) => s.lifecycle);
  const state = { lifecycle };
  const [resp, setResp] = useState<CapturesResponse | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [decryptTarget, setDecryptTarget] = useState<CaptureFile | null>(null);
  const [decryptOpen, setDecryptOpen] = useState(false);

  function refresh() {
    api.captures().then(setResp).catch((e) => setErr(e.message));
  }

  useEffect(() => {
    refresh();
    const i = setInterval(refresh, 3000);
    return () => clearInterval(i);
  }, []);

  // Bump the refresh once a capture starts/stops so freshly-rotated files appear
  useEffect(() => { refresh(); }, [state.lifecycle]);

  const body = (
    <div className="flex flex-col min-h-0 flex-1">
      <div className="flex items-center gap-3 mb-2 flex-wrap text-xs">
        <span className="text-muted">
          Active dir: <span className="font-mono text-slate-200">{resp?.captures_dir ?? "…"}</span>
        </span>
        <span className="text-muted">
          Searching: <span className="font-mono text-slate-300">{resp?.roots.length ?? 0} root(s)</span>
        </span>
        <button className="btn !px-2 !py-0.5 !text-xs ml-auto" title="Pick any pcap on the machine to decrypt (opens in the captures folder)"
                onClick={() => { setDecryptTarget(null); setDecryptOpen(true); }}>🔓 Decrypt a file…</button>
        <button className="btn !px-2 !py-0.5 !text-xs" onClick={refresh}>↻ refresh</button>
      </div>
      <div className="flex-1 overflow-auto bg-bg border border-border rounded">
        <table className="w-full text-xs font-mono">
          <thead className="sticky top-0 bg-bg z-10 text-[10px] uppercase text-muted">
            <tr className="border-b border-border">
              <th className="text-left px-2 py-1.5">File</th>
              <th className="text-left px-2 py-1.5">Source</th>
              <th className="text-right px-2 py-1.5">Size</th>
              <th className="text-right px-2 py-1.5">Modified</th>
              <th className="text-right px-2 py-1.5 w-24">Download</th>
              <th className="text-right px-2 py-1.5 w-24">Decrypt</th>
            </tr>
          </thead>
          <tbody>
            {(resp?.captures ?? []).map((c) => (
              <tr key={c.path} className="border-b border-border/30 hover:bg-panel/50">
                <td className="px-2 py-1">
                  <div className="flex items-center gap-2">
                    {c.active && (
                      <span className="inline-block w-1.5 h-1.5 rounded-full bg-ok animate-pulse" title="Active capture directory" />
                    )}
                    <span className="text-slate-100">{c.name}</span>
                  </div>
                  <div className="text-[10px] text-muted truncate">{c.path}</div>
                </td>
                <td className="px-2 py-1 text-muted truncate max-w-[260px]">{c.source}</td>
                <td className="px-2 py-1 text-right">{fmtBytes(c.size)}</td>
                <td className="px-2 py-1 text-right text-muted">{fmtAge(c.mtime)}</td>
                <td className="px-2 py-1 text-right">
                  {c.size > 0 ? (
                    <a className="btn !px-2 !py-0.5 !text-xs btn-primary" href={api.downloadCaptureUrl(c.path)} download={c.name}>
                      ↓ pcap
                    </a>
                  ) : (
                    <span className="text-muted text-[10px]">empty</span>
                  )}
                </td>
                <td className="px-2 py-1 text-right">
                  {c.size > 0 ? (
                    <button className="btn !px-2 !py-0.5 !text-xs" title="Decrypt with PDCP keys" onClick={() => { setDecryptTarget(c); setDecryptOpen(true); }}>
                      🔓 decrypt
                    </button>
                  ) : (
                    <span className="text-muted text-[10px]">—</span>
                  )}
                </td>
              </tr>
            ))}
            {resp && resp.captures.length === 0 && (
              <tr>
                <td colSpan={6} className="text-center text-muted py-6">
                  No pcap files in <span className="font-mono">{resp.captures_dir}</span> or its known siblings.
                  Start a capture to generate one.
                </td>
              </tr>
            )}
            {err && (
              <tr>
                <td colSpan={6} className="text-center text-bad py-4 font-mono text-xs">{err}</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      {decryptOpen && (
        <DecryptModal file={decryptTarget} onClose={() => setDecryptOpen(false)} onDone={refresh} />
      )}
    </div>
  );

  if (embedded) return body;
  return (
    <div className="panel p-4 flex flex-col min-h-0">
      <h2 className="text-sm font-semibold uppercase tracking-wide text-muted mb-3">Captures</h2>
      {body}
    </div>
  );
}
