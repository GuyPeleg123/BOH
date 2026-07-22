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

  const expandAll = () => {
    const all = new Set<string>();
    const walk = (n: FolderNode) => { all.add(n.path); n.folders.forEach(walk); };
    forest.forEach(walk);
    setExpanded(all);
  };
  const collapseAll = () => setExpanded(new Set(forest.map((t) => t.path)));

  // Indent step per tree depth (px). Bigger than before for clearer nesting.
  const INDENT = 20;

  function fileRow(c: CaptureFile, depth: number) {
    const empty = c.size === 0;
    return (
      <div key={c.path}
        className="group flex items-center gap-3 border-b border-border/20 hover:bg-panel/70 py-2.5 pr-3 transition-colors"
        style={{ paddingLeft: 12 + depth * INDENT }}>
        {c.active
          ? <span className="inline-block w-2.5 h-2.5 rounded-full bg-ok animate-pulse shrink-0" title="Active capture" />
          : <span className="w-2.5 shrink-0" />}
        <span className="shrink-0 text-lg leading-none">📄</span>
        <span className="text-slate-100 font-mono text-sm truncate" title={c.path}>{c.name}</span>
        {c.active && (
          <span className="shrink-0 text-[11px] font-semibold text-ok bg-ok/10 border border-ok/30 rounded px-1.5 py-0.5">
            LIVE
          </span>
        )}
        <span className={`ml-auto shrink-0 w-28 text-right text-sm tabular-nums ${empty ? "text-muted" : "text-slate-300"}`}>
          {empty ? "—" : fmtBytes(c.size)}
        </span>
        <span className="shrink-0 w-24 text-right text-sm text-muted tabular-nums">{fmtAge(c.mtime)}</span>
        <div className="shrink-0 flex items-center justify-end gap-2 w-[210px]">
          {empty ? (
            <span className="text-muted text-xs italic pr-2">writing…</span>
          ) : (
            <>
              <a className="btn btn-secondary !px-3 !py-1.5 !text-xs !gap-1.5"
                 href={api.downloadCaptureUrl(c.path)} download={c.name} title="Download this pcap">
                <span aria-hidden>↓</span><span className="hidden lg:inline">Download</span>
              </a>
              <button className="btn btn-primary !px-3 !py-1.5 !text-xs !gap-1.5"
                      title="Decrypt with PDCP keys"
                      onClick={() => { setDecryptTarget(c); setDecryptOpen(true); }}>
                <span aria-hidden>🔓</span><span className="hidden lg:inline">Decrypt</span>
              </button>
            </>
          )}
        </div>
      </div>
    );
  }

  function folderRows(n: FolderNode, depth: number, isTop: boolean): JSX.Element {
    const open = expanded.has(n.path);
    const subfolders = [...n.folders].sort((a, b) => latestMtime(b) - latestMtime(a));
    const files = [...n.files].sort((a, b) => b.mtime - a.mtime);
    const count = countFiles(n);
    return (
      <div key={n.path}>
        <div className={`flex items-center gap-3 border-b border-border/40 hover:bg-panel/60 py-2.5 pr-3 cursor-pointer transition-colors ${isTop ? "bg-panel/40" : ""}`}
          style={{ paddingLeft: 12 + depth * INDENT }} onClick={() => toggle(n.path)}>
          <span className="text-muted w-4 shrink-0 text-sm select-none">{open ? "▾" : "▸"}</span>
          {hasActive(n)
            ? <span className="inline-block w-2.5 h-2.5 rounded-full bg-ok animate-pulse shrink-0" title="Contains an active capture" />
            : <span className="w-2.5 shrink-0" />}
          <span className="shrink-0 text-lg leading-none">{open ? "📂" : "📁"}</span>
          <span className={`truncate ${isTop ? "font-mono text-sm text-slate-200" : "text-sm font-medium text-slate-100"}`} title={n.path}>
            {isTop ? n.path : n.name}
          </span>
          <span className="shrink-0 text-[11px] text-muted bg-border/50 rounded-full px-2 py-0.5 tabular-nums">
            {count} pcap{count === 1 ? "" : "s"}
          </span>
          <span className="text-muted text-sm ml-auto shrink-0 tabular-nums">{fmtAge(latestMtime(n))}</span>
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

  const flat = [...(resp?.captures ?? [])].sort((a, b) => b.mtime - a.mtime);
  const totalCount = resp?.captures.length ?? 0;
  const totalSize = (resp?.captures ?? []).reduce((s, c) => s + c.size, 0);

  const body = (
    <div className="flex flex-col min-h-0 flex-1">
      {/* toolbar */}
      <div className="flex items-center gap-3 mb-3 flex-wrap">
        <div className="flex items-center gap-x-5 gap-y-1 text-sm flex-wrap">
          <span className="text-muted">
            Active dir <span className="font-mono text-slate-200 ml-1">{resp?.captures_dir ?? "…"}</span>
          </span>
          <span className="text-muted">
            <span className="text-slate-200 font-semibold tabular-nums">{totalCount}</span> pcap{totalCount === 1 ? "" : "s"}
            <span className="mx-1.5 text-border">·</span>
            <span className="text-slate-200 tabular-nums">{fmtBytes(totalSize)}</span>
            <span className="mx-1.5 text-border">·</span>
            <span className="tabular-nums">{resp?.roots.length ?? 0}</span> root{(resp?.roots.length ?? 0) === 1 ? "" : "s"}
          </span>
        </div>

        <div className="ml-auto flex items-center gap-2 flex-wrap">
          {/* view toggle — segmented control */}
          <div className="inline-flex rounded-md border border-border overflow-hidden">
            <button
              className={`px-3 py-1.5 text-sm transition-colors ${view === "tree" ? "bg-accent/15 text-accent" : "text-muted hover:bg-border/40"}`}
              onClick={() => setView("tree")}>🗂 Tree</button>
            <button
              className={`px-3 py-1.5 text-sm transition-colors border-l border-border ${view === "flat" ? "bg-accent/15 text-accent" : "text-muted hover:bg-border/40"}`}
              onClick={() => setView("flat")}>☰ Flat</button>
          </div>

          {view === "tree" && (
            <div className="inline-flex rounded-md border border-border overflow-hidden">
              <button className="px-3 py-1.5 text-sm text-muted hover:bg-border/40 transition-colors"
                      title="Expand every folder" onClick={expandAll}>⊕ Expand</button>
              <button className="px-3 py-1.5 text-sm text-muted hover:bg-border/40 transition-colors border-l border-border"
                      title="Collapse to the top-level roots" onClick={collapseAll}>⊖ Collapse</button>
            </div>
          )}

          <button className="btn btn-secondary" title="Pick any pcap on the machine to decrypt (opens in the captures folder)"
                  onClick={() => { setDecryptTarget(null); setDecryptOpen(true); }}>🔓 Decrypt a file…</button>
          <button className="btn btn-secondary" title="Reload the capture list now" onClick={refresh}>↻ Refresh</button>
        </div>
      </div>

      {/* listing */}
      <div className="flex-1 overflow-auto bg-bg border border-border rounded-lg">
        {/* header row */}
        <div className="flex items-center gap-3 sticky top-0 bg-bg/95 backdrop-blur z-10 border-b border-border text-xs uppercase tracking-wide text-muted font-semibold py-2.5 px-3">
          <span className="pl-8">Name</span>
          <span className="ml-auto w-28 text-right">Size</span>
          <span className="w-24 text-right">Modified</span>
          <span className="w-[210px] text-right pr-2">Actions</span>
        </div>

        {view === "tree"
          ? forest.map((t) => folderRows(t, 0, true))
          : flat.map((c) => fileRow(c, 0))}

        {resp && resp.captures.length === 0 && (
          <div className="text-center text-muted py-12 px-4">
            <div className="text-3xl mb-2">📭</div>
            <div className="text-sm">
              No pcap files in <span className="font-mono text-slate-300">{resp.captures_dir}</span> or its known siblings.
            </div>
            <div className="text-xs mt-1">Start a capture to generate one.</div>
          </div>
        )}
        {err && <div className="text-center text-bad py-4 font-mono text-sm">{err}</div>}
      </div>

      {decryptOpen && (
        <DecryptModal file={decryptTarget} onClose={() => setDecryptOpen(false)} onDone={refresh} />
      )}
    </div>
  );

  if (embedded) return body;
  return (
    <div className="panel p-5 flex flex-col min-h-0">
      <h2 className="text-base font-semibold text-slate-100 mb-4">Captures</h2>
      {body}
    </div>
  );
}
