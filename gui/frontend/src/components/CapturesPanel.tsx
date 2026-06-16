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

// ── folder tree (mirrors the on-disk layout under each capture root) ─────────
interface FolderNode {
  name: string;
  path: string;
  folders: FolderNode[];
  files: CaptureFile[];
}

function buildForest(captures: CaptureFile[], roots: string[]): FolderNode[] {
  // Longest root first so a file under captures_dir doesn't match a shorter root.
  const sortedRoots = [...roots].sort((a, b) => b.length - a.length);
  const tops = new Map<string, FolderNode>();
  const child = (parent: FolderNode, name: string, path: string) => {
    let c = parent.folders.find((f) => f.name === name);
    if (!c) { c = { name, path, folders: [], files: [] }; parent.folders.push(c); }
    return c;
  };
  for (const f of captures) {
    let root = sortedRoots.find((r) => f.path === r || f.path.startsWith(r.endsWith("/") ? r : r + "/"));
    if (!root) { const i = f.path.lastIndexOf("/"); root = i <= 0 ? "/" : f.path.slice(0, i); }
    let top = tops.get(root);
    if (!top) { top = { name: root, path: root, folders: [], files: [] }; tops.set(root, top); }
    const rel = f.path.slice(root.length).replace(/^\/+/, "");
    const segs = rel.split("/").filter(Boolean);
    segs.pop(); // drop filename
    let cur = top;
    let acc = root;
    for (const seg of segs) { acc = acc + "/" + seg; cur = child(cur, seg, acc); }
    cur.files.push(f);
  }
  return [...tops.values()];
}

function countFiles(n: FolderNode): number {
  return n.files.length + n.folders.reduce((s, c) => s + countFiles(c), 0);
}
function latestMtime(n: FolderNode): number {
  return Math.max(0, ...n.files.map((f) => f.mtime), ...n.folders.map(latestMtime));
}
function hasActive(n: FolderNode): boolean {
  return n.files.some((f) => f.active) || n.folders.some(hasActive);
}

export function CapturesPanel({ embedded = false }: { embedded?: boolean }) {
  const lifecycle = useStore((s) => s.lifecycle);
  const state = { lifecycle };
  const [resp, setResp] = useState<CapturesResponse | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [decryptTarget, setDecryptTarget] = useState<CaptureFile | null>(null);
  const [decryptOpen, setDecryptOpen] = useState(false);
  const [view, setView] = useState<"tree" | "flat">("tree");
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [seeded, setSeeded] = useState(false);

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

  const forest = resp ? buildForest(resp.captures, resp.roots) : [];

  // Seed expansion once: open the top-level roots so the run folders are visible.
  useEffect(() => {
    if (!seeded && resp && forest.length) {
      setExpanded(new Set(forest.map((t) => t.path)));
      setSeeded(true);
    }
  }, [resp, seeded, forest]);

  const toggle = (p: string) =>
    setExpanded((s) => { const n = new Set(s); n.has(p) ? n.delete(p) : n.add(p); return n; });

  function fileRow(c: CaptureFile, depth: number) {
    return (
      <div key={c.path}
        className="flex items-center gap-2 border-b border-border/20 hover:bg-panel/50 py-1 pr-2"
        style={{ paddingLeft: 8 + depth * 16 }}>
        {c.active
          ? <span className="inline-block w-1.5 h-1.5 rounded-full bg-ok animate-pulse shrink-0" title="Active capture" />
          : <span className="w-1.5 shrink-0" />}
        <span className="shrink-0">📄</span>
        <span className="text-slate-100 truncate" title={c.path}>{c.name}</span>
        <span className="text-muted text-[10px] ml-auto shrink-0 w-20 text-right">{fmtBytes(c.size)}</span>
        <span className="text-muted text-[10px] shrink-0 w-16 text-right">{fmtAge(c.mtime)}</span>
        <span className="shrink-0 w-16 text-right">
          {c.size > 0
            ? <a className="btn !px-1.5 !py-0.5 !text-[10px] btn-primary" href={api.downloadCaptureUrl(c.path)} download={c.name}>↓</a>
            : <span className="text-muted text-[10px]">empty</span>}
        </span>
        <span className="shrink-0 w-16 text-right">
          {c.size > 0
            ? <button className="btn !px-1.5 !py-0.5 !text-[10px]" title="Decrypt with PDCP keys"
                      onClick={() => { setDecryptTarget(c); setDecryptOpen(true); }}>🔓</button>
            : <span className="text-muted text-[10px]">—</span>}
        </span>
      </div>
    );
  }

  function folderRows(n: FolderNode, depth: number, isTop: boolean): JSX.Element {
    const open = expanded.has(n.path);
    const subfolders = [...n.folders].sort((a, b) => latestMtime(b) - latestMtime(a));
    const files = [...n.files].sort((a, b) => b.mtime - a.mtime);
    return (
      <div key={n.path}>
        <div className="flex items-center gap-2 border-b border-border/30 hover:bg-panel/40 py-1 pr-2 cursor-pointer"
          style={{ paddingLeft: 8 + depth * 16 }} onClick={() => toggle(n.path)}>
          <span className="text-muted w-3 shrink-0">{open ? "▾" : "▸"}</span>
          {hasActive(n)
            ? <span className="inline-block w-1.5 h-1.5 rounded-full bg-ok animate-pulse shrink-0" title="Contains an active capture" />
            : <span className="w-1.5 shrink-0" />}
          <span className="shrink-0">📁</span>
          <span className="text-slate-200 truncate" title={n.path}>{isTop ? n.path : n.name}</span>
          <span className="text-muted text-[10px] shrink-0">({countFiles(n)} pcap{countFiles(n) === 1 ? "" : "s"})</span>
          <span className="text-muted text-[10px] ml-auto shrink-0">{fmtAge(latestMtime(n))}</span>
        </div>
        {open && (
          <div>
            {subfolders.map((c) => folderRows(c, depth + 1, false))}
            {files.map((f) => fileRow(f, depth + 1))}
          </div>
        )}
      </div>
    );
  }

  const flat = (resp?.captures ?? []);

  const body = (
    <div className="flex flex-col min-h-0 flex-1">
      <div className="flex items-center gap-3 mb-2 flex-wrap text-xs">
        <span className="text-muted">
          Active dir: <span className="font-mono text-slate-200">{resp?.captures_dir ?? "…"}</span>
        </span>
        <span className="text-muted">
          Searching: <span className="font-mono text-slate-300">{resp?.roots.length ?? 0} root(s)</span>
        </span>
        <div className="ml-auto flex items-center gap-1">
          <button className={`btn !px-2 !py-0.5 !text-xs ${view === "tree" ? "btn-primary" : ""}`} onClick={() => setView("tree")}>🗂 Tree</button>
          <button className={`btn !px-2 !py-0.5 !text-xs ${view === "flat" ? "btn-primary" : ""}`} onClick={() => setView("flat")}>☰ Flat</button>
        </div>
        <button className="btn !px-2 !py-0.5 !text-xs" title="Pick any pcap on the machine to decrypt (opens in the captures folder)"
                onClick={() => { setDecryptTarget(null); setDecryptOpen(true); }}>🔓 Decrypt a file…</button>
        <button className="btn !px-2 !py-0.5 !text-xs" onClick={refresh}>↻ refresh</button>
      </div>

      <div className="flex-1 overflow-auto bg-bg border border-border rounded text-xs font-mono">
        {/* header row */}
        <div className="flex items-center gap-2 sticky top-0 bg-bg z-10 border-b border-border text-[10px] uppercase text-muted py-1.5 px-2">
          <span>Name</span>
          <span className="ml-auto w-20 text-right">Size</span>
          <span className="w-16 text-right">Modified</span>
          <span className="w-16 text-right">DL</span>
          <span className="w-16 text-right">Decrypt</span>
        </div>

        {view === "tree"
          ? forest.map((t) => folderRows(t, 0, true))
          : flat.map((c) => fileRow(c, 0))}

        {resp && resp.captures.length === 0 && (
          <div className="text-center text-muted py-6">
            No pcap files in <span className="font-mono">{resp.captures_dir}</span> or its known siblings.
            Start a capture to generate one.
          </div>
        )}
        {err && <div className="text-center text-bad py-4 font-mono">{err}</div>}
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
