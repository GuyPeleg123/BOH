import { useEffect, useState } from "react";
import { api } from "../lib/api";
import type { BrowseResponse } from "../lib/types";

function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(2)} MB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

/**
 * Pick a pcap to decrypt. Opens in the captures (pcap) folder by default, but
 * can navigate to any directory on the machine. onPick gets the absolute path
 * + display name of the chosen capture file.
 */
export function FileBrowser({
  startPath,
  onPick,
  onClose,
}: {
  startPath?: string | null;
  onPick: (path: string, name: string) => void;
  onClose: () => void;
}) {
  const [resp, setResp] = useState<BrowseResponse | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [manual, setManual] = useState("");

  function go(path?: string) {
    setErr(null);
    api.browseFs(path).then((r) => {
      setResp(r);
      setManual(r.cwd ?? "");
      if (r.error) setErr(r.error);
    }).catch((e) => setErr(e.message));
  }

  // First load: open at startPath's directory if given, else the captures dir.
  useEffect(() => { go(startPath ?? undefined); /* eslint-disable-next-line */ }, []);

  useEffect(() => {
    const h = (ev: KeyboardEvent) => { if (ev.key === "Escape") onClose(); };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [onClose]);

  return (
    <div className="fixed inset-0 z-[60] bg-black/60 flex items-center justify-center p-4" onClick={onClose}>
      <div className="panel w-full max-w-2xl max-h-[85vh] flex flex-col p-4" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center mb-2">
          <h2 className="text-sm font-semibold uppercase tracking-wide text-muted">Select a pcap</h2>
          <button className="btn !px-2 !py-0.5 !text-xs ml-auto" onClick={onClose}>✕ close</button>
        </div>

        {/* path bar: up, manual path, jump to captures default */}
        <div className="flex items-center gap-2 mb-2">
          <button className="btn !px-2 !py-0.5 !text-xs" title="Up one level"
                  disabled={!resp?.parent} onClick={() => resp?.parent && go(resp.parent)}>↑ up</button>
          <input
            className="input !text-xs font-mono flex-1"
            value={manual}
            spellCheck={false}
            onChange={(e) => setManual(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter") go(manual.trim() || undefined); }}
            placeholder="/path/to/folder"
          />
          <button className="btn !px-2 !py-0.5 !text-xs" onClick={() => go(manual.trim() || undefined)}>Go</button>
          {resp?.default && (
            <button className="btn !px-2 !py-0.5 !text-xs" title="Jump to the captures folder"
                    onClick={() => go(resp.default!)}>📁 captures</button>
          )}
        </div>

        {err && <div className="text-bad text-xs font-mono border border-bad/40 rounded p-2 mb-2">{err}</div>}

        <div className="flex-1 overflow-auto bg-bg border border-border rounded">
          <table className="w-full text-xs font-mono">
            <tbody>
              {(resp?.entries ?? []).map((e) => (
                <tr
                  key={e.path}
                  className="border-b border-border/30 hover:bg-panel/50 cursor-pointer"
                  onClick={() => (e.is_dir ? go(e.path) : onPick(e.path, e.name))}
                  onDoubleClick={() => (!e.is_dir ? onPick(e.path, e.name) : undefined)}
                >
                  <td className="px-2 py-1 text-slate-100">
                    {e.is_dir ? "📁" : "📄"} {e.name}{e.is_dir ? "/" : ""}
                  </td>
                  <td className="px-2 py-1 text-right text-muted w-28">{e.is_dir ? "" : fmtBytes(e.size)}</td>
                  <td className="px-2 py-1 text-right w-16">
                    {!e.is_dir && (
                      <button className="btn btn-primary !px-2 !py-0.5 !text-[10px]"
                              onClick={(ev) => { ev.stopPropagation(); onPick(e.path, e.name); }}>pick</button>
                    )}
                  </td>
                </tr>
              ))}
              {resp && resp.entries.length === 0 && !err && (
                <tr><td className="text-center text-muted py-6">No pcap files or subfolders here.</td></tr>
              )}
            </tbody>
          </table>
        </div>
        <p className="text-[10px] text-muted mt-2">
          Showing folders and capture files (.pcap/.pcapng/.cap). Click a folder to enter, a file to pick.
        </p>
      </div>
    </div>
  );
}
