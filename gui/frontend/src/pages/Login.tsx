import { useEffect, useRef, useState } from "react";
import { api } from "../lib/api";

interface Props {
  onAuthenticated: (username: string) => void;
}

export function LoginPage({ onAuthenticated }: Props) {
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [busy, setBusy]         = useState(false);
  const [err, setErr]           = useState<string | null>(null);
  const passRef = useRef<HTMLInputElement | null>(null);

  // Auto-focus the password field — username defaults to "admin" which is
  // right ~100% of the time on first start.
  useEffect(() => { passRef.current?.focus(); }, []);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (busy) return;
    setBusy(true); setErr(null);
    try {
      const r = await api.login(username.trim(), password);
      onAuthenticated(r.username);
    } catch (e: any) {
      const msg = e?.message ?? String(e);
      setErr(/^401/.test(msg) ? "Invalid username or password." : msg);
      setTimeout(() => passRef.current?.select(), 0);
    } finally {
      setBusy(false);
    }
  }

  return (
    // bg-bg is the canonical dark background (defined in tailwind.config.js).
    // The previous version used "bg-base" / "text-text" / "border-line" which
    // aren't in the config — Tailwind silently dropped them, so the page
    // rendered with the default white-on-white browser look.
    <div className="flex items-center justify-center min-h-screen bg-bg text-slate-100 px-4">
      <form
        onSubmit={submit}
        className="w-full max-w-sm flex flex-col gap-4 p-7 rounded-xl border border-border bg-panel shadow-2xl"
      >
        <div className="flex items-center gap-3 pb-1">
          {/* Same logo as the StatusBar — quick mark for brand consistency. */}
          <svg width="28" height="28" viewBox="0 0 16 16" aria-hidden>
            <path
              d="M2 12 L5 6 L8 10 L11 4 L14 8"
              stroke="#6cb6ff" strokeWidth="1.5" fill="none"
            />
          </svg>
          <div className="flex flex-col leading-tight">
            <span className="text-lg font-semibold tracking-tight">LTESniffer</span>
            <span className="text-[11px] text-muted -mt-0.5">Operator dashboard</span>
          </div>
        </div>

        <label className="flex flex-col gap-1.5">
          <span className="label">Username</span>
          <input
            type="text"
            className="input"
            autoComplete="username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            disabled={busy}
          />
        </label>

        <label className="flex flex-col gap-1.5">
          <span className="label">Password</span>
          <input
            ref={passRef}
            type="password"
            className="input"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            disabled={busy}
          />
        </label>

        {err && (
          <div className="text-xs text-bad bg-bad/10 border border-bad/30 px-2.5 py-1.5 rounded-md">
            {err}
          </div>
        )}

        <button
          type="submit"
          className="btn btn-primary justify-center !py-2 !text-sm"
          disabled={busy || !username || !password}
        >
          {busy ? "Signing in…" : "Sign in"}
        </button>

        <div className="text-[10.5px] text-muted leading-relaxed pt-3 border-t border-border/60 space-y-1">
          <p>
            <span className="text-slate-300 font-semibold">First time?</span> The auto-generated
            password was printed once to the backend's stderr on first start.
          </p>
          <p>
            <span className="text-slate-300 font-semibold">Forgot it?</span>{" "}
            <code className="font-mono text-[10px]">rm ~/.config/ltesniffer-gui/auth.json</code>{" "}
            and restart the backend — a new one prints to stderr.
          </p>
        </div>
      </form>
    </div>
  );
}
