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
      // Don't reload — let the parent swap to the dashboard without
      // throwing away the React tree.
      onAuthenticated(r.username);
    } catch (e: any) {
      const msg = e?.message ?? String(e);
      // The server returns 401 "invalid credentials" — surface that cleanly.
      setErr(/^401/.test(msg) ? "Invalid username or password." : msg);
      // Refocus password so user can correct & retry without mouse.
      setTimeout(() => passRef.current?.select(), 0);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex items-center justify-center h-screen bg-base text-text">
      <form
        onSubmit={submit}
        className="w-full max-w-sm flex flex-col gap-3 p-6 rounded-lg border border-line bg-panel shadow"
      >
        <div className="flex items-center gap-2 text-xl font-semibold">
          <span>🔒 LTESniffer GUI</span>
        </div>
        <div className="text-xs text-muted -mt-2">
          Sign in to continue. Credentials are in <code>~/.config/ltesniffer-gui/auth.json</code> on the backend host.
        </div>

        <label className="flex flex-col gap-1 text-xs">
          <span className="text-muted">Username</span>
          <input
            type="text"
            className="input"
            autoComplete="username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            disabled={busy}
          />
        </label>

        <label className="flex flex-col gap-1 text-xs">
          <span className="text-muted">Password</span>
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
          <div className="text-xs text-bad bg-bad/10 px-2 py-1 rounded font-mono">
            {err}
          </div>
        )}

        <button
          type="submit"
          className="btn mt-1"
          disabled={busy || !username || !password}
        >
          {busy ? "Signing in…" : "Sign in"}
        </button>

        <div className="text-[10px] text-muted leading-snug pt-2 border-t border-line/50">
          First time? The password was printed once to the backend's stderr on first start.
          Forgot it? <code>rm ~/.config/ltesniffer-gui/auth.json</code> and restart the backend
          — a new one prints to stderr.
        </div>
      </form>
    </div>
  );
}
