import type { SnifferConfig, USRPDevice, RuntimeState, CapturesResponse, KeyEntry, KeysResponse } from "./types";

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    headers: { "content-type": "application/json" },
    ...init,
  });
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
