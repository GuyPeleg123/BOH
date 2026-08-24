import { useEffect, useState, useMemo } from "react";

const GUIDE_PATH = "/api/help";

export function HelpPage() {
  const [text, setText] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [query, setQuery] = useState("");

  useEffect(() => {
    let cancelled = false;
    fetch(GUIDE_PATH)
      .then((r) => (r.ok ? r.text() : Promise.reject(new Error(`${r.status} ${r.statusText}`))))
      .then((t) => { if (!cancelled) setText(t); })
      .catch((e) => { if (!cancelled) setErr(e?.message ?? String(e)); });
    return () => { cancelled = true; };
  }, []);

  const sections = useMemo(() => {
    if (!text) return [];
    const out: { title: string; line: number }[] = [];
    const lines = text.split("\n");
    for (let i = 0; i < lines.length; i++) {
      const m = lines[i].match(/^(\d+(?:\.\d+)?)\.\s+([A-Z][A-Z0-9 &\-—\/()]+)\s*$/);
      if (m) out.push({ title: `${m[1]}. ${m[2]}`, line: i });
    }
    return out;
  }, [text]);

  const highlighted = useMemo(() => {
    if (!text || !query.trim()) return text ?? "";
    const q = query.trim();
    const esc = q.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    return text.replace(new RegExp(esc, "gi"), (m) => `\x00${m}\x01`);
  }, [text, query]);

  return (
    <div className="h-full overflow-hidden flex flex-col p-4 gap-3">
      <div className="flex items-center gap-3 flex-wrap">
        <h1 className="text-xl font-semibold">User Guide</h1>
        <input
          className="input !text-xs !py-1 !px-2 w-64"
          placeholder="search the guide…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
        <a className="btn btn-secondary !px-3.5 !py-1.5 !text-sm" href={GUIDE_PATH} download="LTESniffer_USER_GUIDE.txt">
          ⬇ Download .txt
        </a>
        <a className="btn btn-secondary !px-3.5 !py-1.5 !text-sm" href={GUIDE_PATH} target="_blank" rel="noopener">
          ↗ Open raw
        </a>
        <span className="text-[10px] text-muted ml-auto font-mono">{GUIDE_PATH}</span>
      </div>

      {err && <div className="panel p-3 text-bad text-sm">Failed to load: {err}</div>}
      {!text && !err && <div className="text-muted text-sm">Loading…</div>}

      {text && (
        <div className="flex-1 min-h-0 grid grid-cols-[220px_1fr] gap-3">
          <nav className="panel overflow-auto p-2 text-xs">
            <div className="label mb-1">Sections</div>
            <ul className="flex flex-col gap-0.5">
              {sections.map((s) => (
                <li key={s.line}>
                  <a
                    className="block px-1.5 py-0.5 rounded hover:bg-border text-slate-200 truncate"
                    href={`#section-${s.line}`}
                    title={s.title}
                  >
                    {s.title}
                  </a>
                </li>
              ))}
            </ul>
          </nav>
          <pre className="panel overflow-auto p-4 text-[12px] leading-[1.4] font-mono whitespace-pre text-slate-200">
            {highlighted.split("\n").map((line, i) => {
              const isHeading = /^\d+(?:\.\d+)?\.\s+[A-Z]/.test(line);
              const parts = line.split(/\x00|\x01/);
              return (
                <div
                  key={i}
                  id={isHeading ? `section-${i}` : undefined}
                  className={isHeading ? "text-cyan-300 font-semibold mt-2" : undefined}
                >
                  {parts.map((p, j) =>
                    j % 2 === 1
                      ? <mark key={j} className="bg-yellow-500/40 text-slate-50 rounded px-0.5">{p}</mark>
                      : <span key={j}>{p}</span>
                  )}
                </div>
              );
            })}
          </pre>
        </div>
      )}
    </div>
  );
}
