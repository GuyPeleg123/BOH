import { useCallback, useEffect, useState } from "react";
import { Routes, Route, Navigate } from "react-router-dom";
import { StoreProvider } from "./lib/store";
import { StatusBar } from "./components/StatusBar";
import { Dashboard } from "./pages/Dashboard";
import { ConfigPage } from "./pages/Config";
import { KeysPage } from "./pages/Keys";
import { HelpPage } from "./pages/Help";
import { LoginPage } from "./pages/Login";
import { CapturesPage } from "./pages/CapturesPage";
import { LogHistoryPage } from "./pages/LogHistoryPage";
import { UEsPage } from "./pages/UEsPage";
import { SessionsPage } from "./pages/SessionsPage";
import { api, setAuthLostHandler } from "./lib/api";

type AuthState =
  | { kind: "checking" }
  | { kind: "anon" }
  | { kind: "authed"; username: string };

export default function App() {
  const [auth, setAuth] = useState<AuthState>({ kind: "checking" });

  // Probe whoami on mount — cheap cookie-only round-trip. 200 → authed,
  // 401 → show login. Any other error (network down etc.) we treat as anon
  // since we can't render the dashboard without a working API anyway.
  useEffect(() => {
    let cancelled = false;
    api.whoami()
      .then((r) => { if (!cancelled) setAuth({ kind: "authed", username: r.username }); })
      .catch(() => { if (!cancelled) setAuth({ kind: "anon" }); });
    return () => { cancelled = true; };
  }, []);

  // Any 401 from a regular API call (session expired, password changed in
  // another tab, etc.) flips us back to the Login page. api.ts wires this up.
  useEffect(() => {
    setAuthLostHandler(() => setAuth({ kind: "anon" }));
  }, []);

  const onAuthenticated = useCallback((username: string) => {
    setAuth({ kind: "authed", username });
  }, []);

  if (auth.kind === "checking") {
    return (
      <div className="flex flex-col items-center justify-center h-screen gap-3 text-muted">
        {/* Brand mark, gently pulsing, so the cold-start moment reads as
            "LTESniffer is coming up" rather than a blank dark screen. */}
        <svg width="40" height="40" viewBox="0 0 16 16" aria-hidden className="animate-pulse">
          <path d="M2 12 L5 6 L8 10 L11 4 L14 8" stroke="#6cb6ff" strokeWidth="1.5" fill="none" />
        </svg>
        <span className="text-sm tracking-wide">Connecting to LTESniffer…</span>
      </div>
    );
  }
  if (auth.kind === "anon") {
    return <LoginPage onAuthenticated={onAuthenticated} />;
  }

  return (
    <StoreProvider>
      <div className="flex flex-col h-screen">
        <StatusBar />
        <main className="flex-1 min-h-0 overflow-hidden">
          <Routes>
            <Route path="/"            element={<Dashboard />} />
            <Route path="/ues"         element={<UEsPage />} />
            <Route path="/sessions"    element={<SessionsPage />} />
            <Route path="/config"      element={<ConfigPage />} />
            <Route path="/keys"        element={<KeysPage />} />
            <Route path="/captures"    element={<CapturesPage />} />
            <Route path="/log-history" element={<LogHistoryPage />} />
            <Route path="/help"        element={<HelpPage />} />
            {/* Unknown path (stale bookmark, typo) → home, not a blank pane. */}
            <Route path="*"       element={<Navigate to="/" replace />} />
          </Routes>
        </main>
      </div>
    </StoreProvider>
  );
}
