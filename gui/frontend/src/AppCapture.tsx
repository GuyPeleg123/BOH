import { useCallback, useEffect, useState } from "react";
import { Routes, Route, Navigate } from "react-router-dom";
import { StoreProvider } from "./lib/store";
import { StatusBar, type NavTab } from "./components/StatusBar";
import { Dashboard } from "./pages/Dashboard";
import { ConfigPage } from "./pages/Config";
import { LoginPage } from "./pages/Login";
import { api, setAuthLostHandler } from "./lib/api";

// The capture instance: sniffs LTE, forwards the live pcap to a decrypt
// instance over the network. Deliberately just Dashboard + Config — every
// analysis page (UEs/Sessions/Captures/Log History/Help) lives on the
// decrypt instance instead (see AppDecrypt.tsx), which is where the pcaps
// end up.
const TABS: NavTab[] = [
  { path: "/", label: "Dashboard" },
  { path: "/config", label: "Config" },
];

type AuthState =
  | { kind: "checking" }
  | { kind: "anon" }
  | { kind: "authed"; username: string };

export default function AppCapture() {
  const [auth, setAuth] = useState<AuthState>({ kind: "checking" });

  useEffect(() => {
    let cancelled = false;
    api.whoami()
      .then((r) => { if (!cancelled) setAuth({ kind: "authed", username: r.username }); })
      .catch(() => { if (!cancelled) setAuth({ kind: "anon" }); });
    return () => { cancelled = true; };
  }, []);

  useEffect(() => {
    setAuthLostHandler(() => setAuth({ kind: "anon" }));
  }, []);

  const onAuthenticated = useCallback((username: string) => {
    setAuth({ kind: "authed", username });
  }, []);

  if (auth.kind === "checking") {
    return (
      <div className="flex flex-col items-center justify-center h-screen gap-3 text-muted">
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
        <StatusBar tabs={TABS} linkKind="forward" />
        <main className="flex-1 min-h-0 overflow-hidden">
          <Routes>
            <Route path="/"       element={<Dashboard />} />
            <Route path="/config" element={<ConfigPage />} />
            <Route path="*"  element={<Navigate to="/" replace />} />
          </Routes>
        </main>
      </div>
    </StoreProvider>
  );
}
