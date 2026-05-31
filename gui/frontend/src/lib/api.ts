import type { SnifferConfig, USRPDevice, RuntimeState, CapturesResponse, KeyEntry, KeysResponse, KnownCellsResponse } from "./types";

// ---- HTTP Basic Auth over HTTPS --------------------------------------------
//
// The browser handles the auth UI natively: on the first request that comes
// back with `WWW-Authenticate: Basic`, Firefox/Chrome pop a username/password
// dialog. Once the user enters credentials, the browser caches them for the
// origin and auto-includes `Authorization: Basic <b64>` on every subsequent
// request — REST AND WebSocket — for as long as the tab/window lives.
//
// That means there is nothing for the SPA to do for auth: no token, no
// localStorage, no URL fragment, no JS-side login form. fetch() just works,
// and a 401 here means the browser-cached creds are wrong (next page-load
// the browser will re-prompt).

// kept exported so the WS connector doesn't have to know the auth model —
// today it returns null (browser handles WS auth via cached Basic creds);
// if we ever need a cookie/token, this is the seam.
export function getTokenForWS(): string | null {
  return null;
}

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const headers: Record<string, string> = {
    "content-type": "application/json",
    ...((init?.headers as Record<string, string>) ?? {}),
  };
  const res = await fetch(path, {
    ...init,
    headers,
    // Send the browser-cached Basic Auth credentials on cross-origin fetches
    // too (e.g. vite dev server proxying to backend). Same-origin requests
    // include them by default.
    credentials: "same-origin",
  });
  if (res.status === 401) {
    // Browser-cached Basic creds are wrong; force a hard reload so the
    // browser re-issues the auth dialog. No JS prompt — we want the
    // native dialog so the password manager can offer to save the creds.
    if (typeof window !== "undefined") {
      window.location.reload();
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
  health: () => req<{ ok: boolean; mock: boolean }>("/api/health"),
  getConfig: () => req<SnifferConfig>("/api/config"),
  putConfig: (cfg: SnifferConfig) =>
    req<SnifferConfig>("/api/config", {
      method: "PUT",
      body: JSON.stringify(cfg),
    }),
  status: () => req<{ state: RuntimeState; mock: boolean }>("/api/status"),
  start: (cfg?: SnifferConfig) =>
    req<{ ok: boolean; state: RuntimeState }>("/api/capture/start", {
      method: "POST",
      body: cfg ? JSON.stringify(cfg) : "null",
    }),
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
  getKeys: () => req<KeysResponse>("/api/keys"),
  putKeys: (entries: KeyEntry[]) =>
    req<{ ok: boolean; path: string; wired_into_config: boolean; n_entries: number }>(
      "/api/keys",
      { method: "PUT", body: JSON.stringify({ entries }) }
    ),
  captures: () => req<CapturesResponse>("/api/captures"),
  openWireshark: () =>
    req<{ ok: boolean; pid: number; fifo: string }>(
      "/api/wireshark/open", { method: "POST" }),
  downloadCaptureUrl: (path: string) =>
    `/api/captures/download?path=${encodeURIComponent(path)}`,
};
