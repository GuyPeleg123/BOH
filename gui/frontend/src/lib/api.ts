import type { SnifferConfig, USRPDevice, RuntimeState, CapturesResponse, KnownCellsResponse, BrowseResponse, SessionsResponse, CellIdResponse, PinCellResponse, ForwardStatus, ReceiveStatus } from "./types";

// ---- Session-cookie auth ---------------------------------------------------
//
// The SPA renders an in-app <Login> form when there's no valid session. POST
// /api/login → server validates bcrypt creds and sets an HttpOnly Secure
// SameSite=Strict cookie. The browser auto-includes that cookie on every
// subsequent same-origin request — REST and WebSocket — without any JS help.
//
// On 401 from any API call, we fire a window-level "auth-lost" event; the
// React app listens for it and swaps to the Login route.

let _onAuthLost: (() => void) | null = null;
export function setAuthLostHandler(fn: () => void): void { _onAuthLost = fn; }

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const headers: Record<string, string> = {
    "content-type": "application/json",
    ...((init?.headers as Record<string, string>) ?? {}),
  };
  const res = await fetch(path, {
    ...init,
    headers,
    // "include" forces the session cookie even on cross-origin (vite dev
    // server → backend) — same-origin requests would include it anyway.
    credentials: "include",
  });
  if (res.status === 401) {
    // Session expired / never authenticated. Tell the React app so it can
    // render the Login page. Don't reload — preserve any in-flight UI state.
    if (_onAuthLost && !path.endsWith("/api/whoami") && !path.endsWith("/api/login")) {
      _onAuthLost();
    }
    throw new Error("401: re-authenticating");
  }
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const j = await res.json();
      detail = j.detail ?? detail;
    } catch {}
    throw new Error(`${res.status}: ${detail}`);
  }
  return res.json();
}

export const api = {
  get: <T>(path: string) => req<T>(path),
  // ── auth (the only /api/* the SPA may hit unauthenticated) ──
  whoami: () => req<{ username: string }>("/api/whoami"),
  login:  (username: string, password: string) =>
    req<{ ok: boolean; username: string }>("/api/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    }),
  logout: () => req<{ ok: boolean }>("/api/logout", { method: "POST" }),
  health: () => req<{ ok: boolean; mock: boolean }>("/api/health"),
  getConfig: () => req<SnifferConfig>("/api/config"),
  putConfig: (cfg: SnifferConfig) =>
    req<SnifferConfig>("/api/config", {
      method: "PUT",
      body: JSON.stringify(cfg),
    }),
  status: () => req<{ state: RuntimeState; mock: boolean }>("/api/status"),
  forwardStatus: () => req<ForwardStatus>("/api/forward/status"),
  receiveStatus: () => req<ReceiveStatus>("/api/receive/status"),
  cellId: () => req<CellIdResponse>("/api/cell-id"),
  pinCell: () => req<PinCellResponse>("/api/pin-cell", { method: "POST" }),
  pinCellStop: () => req<{ ok: boolean }>("/api/pin-cell/stop", { method: "POST" }),
  start: (cfg?: SnifferConfig) =>
    req<{ ok: boolean; state: RuntimeState }>("/api/capture/start", {
      method: "POST",
      body: cfg ? JSON.stringify(cfg) : "null",
    }),
  denseTest: () =>
    req<{ ok: boolean; state: RuntimeState }>("/api/capture/dense-test", { method: "POST" }),
  stop: () => req<{ ok: boolean; state: RuntimeState }>("/api/capture/stop", { method: "POST" }),
  restart: (cfg?: SnifferConfig) =>
    req<{ ok: boolean; state: RuntimeState }>("/api/capture/restart", {
      method: "POST",
      body: cfg ? JSON.stringify(cfg) : "null",
    }),
  usrps: () => req<{ devices: USRPDevice[] }>("/api/usrps"),
  gpsdoProbe: () =>
    req<{ devices: Array<USRPDevice & { gpsdo: boolean }>; message: string }>("/api/usrps/gpsdo"),
  getKnownCells: () => req<KnownCellsResponse>("/api/known-cells"),
  loadKnownCell: (idx: number) =>
    req<{ ok: boolean; loaded: string; config: SnifferConfig }>(
      `/api/known-cells/${idx}/load`, { method: "POST" }),
  saveCurrentAsKnownCell: (body: { label: string; notes?: string; pci?: number | null; bandwidth_mhz?: number | null }) =>
    req<{ ok: boolean; idx: number }>(
      "/api/known-cells/save-current", { method: "POST", body: JSON.stringify(body) }),
  deleteKnownCell: (idx: number) =>
    req<{ ok: boolean; removed_label: string; n_remaining: number }>(
      `/api/known-cells/${idx}`, { method: "DELETE" }),
  captures: () => req<CapturesResponse>("/api/captures"),
  browseFs: (path?: string) =>
    req<BrowseResponse>(`/api/fs/browse${path ? `?path=${encodeURIComponent(path)}` : ""}`),
  openWireshark: () =>
    req<{ ok: boolean; pid: number; fifo: string }>(
      "/api/wireshark/open", { method: "POST" }),
  downloadCaptureUrl: (path: string) =>
    `/api/captures/download?path=${encodeURIComponent(path)}`,
  analyzeSessions: (path: string | null) =>
    req<SessionsResponse>("/api/sessions", {
      method: "POST",
      body: JSON.stringify({ path }),
    }),
  logHistory: () =>
    req<{ runs: RunLog[] }>("/api/logs/history"),
  logContent: (path: string) =>
    req<{ path: string; text: string }>(`/api/logs/content?path=${encodeURIComponent(path)}`),
};

export interface RunLog {
  run: string;            // timestamped run tag (= start date/time)
  started: string | null; // ISO start time, or null for a non-standard name
  path: string;
  size: number;
  mtime: number;
}
