import { Routes, Route } from "react-router-dom";
import { StoreProvider } from "./lib/store";
import { StatusBar } from "./components/StatusBar";
import { Dashboard } from "./pages/Dashboard";
import { ConfigPage } from "./pages/Config";
import { KeysPage } from "./pages/Keys";
import { HelpPage } from "./pages/Help";

export default function App() {
  return (
    <StoreProvider>
      <div className="flex flex-col h-screen">
        <StatusBar />
        <main className="flex-1 min-h-0">
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
