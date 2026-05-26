import type { SnifferConfig, USRPDevice, RuntimeState, CapturesResponse, KeyEntry, KeysResponse } from "./types";

// ---- bearer-token handling --------------------------------------------------
//
// On loopback the backend doesn't require a token, but if the operator opens
// the GUI from another host they need one. We:
//   1. Look for ?token=<hex> in the current URL, persist it to localStorage,
//      then strip it from the visible URL.
//   2. Attach the token as Authorization: Bearer <hex> on every REST call.
//   3. Append ?token=<hex> to the WS URL (store.ts handles that side).
// A 401 from any REST call clears the cached token and prompts.

const TOKEN_KEY = "ltesniffer_gui_token";

function _captureTokenFromUrl(): void {
  try {
    const u = new URL(window.location.href);
    const tok = u.searchParams.get("token");
    if (tok && /^[0-9a-fA-F]{32,128}$/.test(tok)) {
      localStorage.setItem(TOKEN_KEY, tok);
      u.searchParams.delete("token");
      window.history.replaceState({}, "", u.toString());
    }
  } catch {}
}

function getToken(): string | null {
  _captureTokenFromUrl();
  try {
    return localStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

export function setToken(t: string | null): void {
  try {
    if (t) localStorage.setItem(TOKEN_KEY, t);
    else localStorage.removeItem(TOKEN_KEY);
  } catch {}
}

export function getTokenForWS(): string | null {
  return getToken();
}

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const tok = getToken();
  const headers: Record<string, string> = {
    "content-type": "application/json",
    ...((init?.headers as Record<string, string>) ?? {}),
  };
  if (tok) headers["authorization"] = `Bearer ${tok}`;
  const res = await fetch(path, { ...init, headers });
  if (res.status === 401) {
    // Likely stale / wrong token — prompt user.
    const supplied = window.prompt(
      "GUI requires a bearer token (see ~/.config/ltesniffer-gui/token on the backend host).\nPaste the 64-hex token here:",
      tok ?? "",
    );
    if (supplied && supplied.trim()) {
      setToken(supplied.trim());
      return req<T>(path, init);  // retry once with new token
    }
    setToken(null);
    throw new Error("401: missing or invalid bearer token");
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
  getKeys: () => req<KeysResponse>("/api/keys"),
  putKeys: (entries: KeyEntry[]) =>
    req<{ ok: boolean; path: string; wired_into_config: boolean; n_entries: number }>(
      "/api/keys",
      { method: "PUT", body: JSON.stringify({ entries }) }
    ),
  captures: () => req<CapturesResponse>("/api/captures"),
  downloadCaptureUrl: (path: string) =>
    `/api/captures/download?path=${encodeURIComponent(path)}`,
};
