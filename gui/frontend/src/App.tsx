import { useCallback, useEffect, useState } from "react";
import { Routes, Route } from "react-router-dom";
import { StoreProvider } from "./lib/store";
import { StatusBar } from "./components/StatusBar";
import { Dashboard } from "./pages/Dashboard";
import { ConfigPage } from "./pages/Config";
import { KeysPage } from "./pages/Keys";
import { HelpPage } from "./pages/Help";
import { LoginPage } from "./pages/Login";
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
      <div className="flex items-center justify-center h-screen text-muted text-sm">
        Loading…
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
            <Route path="/"       element={<Dashboard />} />
            <Route path="/config" element={<ConfigPage />} />
            <Route path="/keys"   element={<KeysPage />} />
            <Route path="/help"   element={<HelpPage />} />
          </Routes>
        </main>
      </div>
    </StoreProvider>
  );
}
