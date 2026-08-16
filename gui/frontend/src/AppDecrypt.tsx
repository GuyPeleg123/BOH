import { useCallback, useEffect, useState } from "react";
import { Routes, Route, Navigate } from "react-router-dom";
import { StoreProvider } from "./lib/store";
import { StatusBar, type NavTab } from "./components/StatusBar";
import { UEsPage } from "./pages/UEsPage";
import { SessionsPage } from "./pages/SessionsPage";
import { CapturesPage } from "./pages/CapturesPage";
import { LogHistoryPage } from "./pages/LogHistoryPage";
import { ReceiveConfigPage } from "./pages/ReceiveConfig";
import { HelpPage } from "./pages/Help";
import { LoginPage } from "./pages/Login";
import { api, setAuthLostHandler } from "./lib/api";

// The decrypt/analysis instance: receives pcaps pushed over the network by
// a capture instance (pcap_receive.py) and analyzes them. No Dashboard here
// — this instance never runs a capture itself, see AppCapture.tsx for that.
// Its Config page is a different, much smaller thing than the capture
// instance's: just the receive bind/port, not RF/USRP settings.
const TABS: NavTab[] = [
  { path: "/",            label: "UEs" },
  { path: "/sessions",    label: "Sessions" },
  { path: "/config",      label: "Config" },
  { path: "/captures",    label: "Captures" },
  { path: "/log-history", label: "Log History" },
  { path: "/help",        label: "Help" },
];

type AuthState =
  | { kind: "checking" }
  | { kind: "anon" }
  | { kind: "authed"; username: string };

export default function AppDecrypt() {
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
        <StatusBar tabs={TABS} showCaptureStatus={false} linkKind="receive" />
        <main className="flex-1 min-h-0 overflow-hidden">
          <Routes>
            <Route path="/"            element={<UEsPage />} />
            <Route path="/sessions"    element={<SessionsPage />} />
            <Route path="/config"      element={<ReceiveConfigPage />} />
            <Route path="/captures"    element={<CapturesPage />} />
            <Route path="/log-history" element={<LogHistoryPage />} />
            <Route path="/help"        element={<HelpPage />} />
            <Route path="*"       element={<Navigate to="/" replace />} />
          </Routes>
        </main>
      </div>
    </StoreProvider>
  );
}
