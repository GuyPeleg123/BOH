import React, { createContext, useContext, useEffect, useReducer, useRef } from "react";
import type { Event, RuntimeState } from "./types";

const SF_HISTORY = 300;          // ring buffer for waterfall
const LOG_HISTORY = 500;
const RECENT_DCI = 200;          // live packet feed depth
const METRIC_WINDOW_MS = 5_000;  // sliding window for rate metrics
const FLUSH_HZ = 15;             // max state-update rate to the UI

export interface RNTIStats {
  rnti: number;
  first_seen: number;
  last_seen: number;
  dl_count: number;
  ul_count: number;
  dl_rb_total: number;
  ul_rb_total: number;
  dl_tbs_total: number;
  ul_tbs_total: number;
  last_mcs_dl?: number;
  last_mcs_ul?: number;
  last_fmt?: string;
}

export interface IdentityRecord {
  ts: number;
  sfn: number;
  kind: string;
  rnti: number;
  value: string;
  from: string;
}

export interface DCIRecord {
  ts: number;
  sfn: number;
  sf: number;
  dir: "dl" | "ul";
  rnti: number;
  fmt: string;
  mcs: number;
  nprb: number;
  tbs: number;
  ndi: number;
  harq?: number;
  hex: string;
}

export interface RateSample {
  ts: number;
  dci: number;
  tbs: number;
  rb: number;
}

export interface AppState {
  connected: boolean;
  lifecycle: "stopped" | "running";
  pid: number | null;
  argv: string[];
  mock: boolean;
  cell: Extract<Event, { t: "cell" }> | null;
  hello: Extract<Event, { t: "hello" }> | null;
  mib: Extract<Event, { t: "mib" }> | null;
  latestSf: Extract<Event, { t: "sf" }> | null;
  sfHistory: Extract<Event, { t: "sf" }>[];
  rntis: Map<number, RNTIStats>;
  stats: Extract<Event, { t: "stats" }> | null;
  identities: IdentityRecord[];
  logs: { ts: number; level: string; msg: string; source?: string }[];
  recentDci: DCIRecord[];                // newest-first
  totals: { dci: number; dci_dl: number; dci_ul: number; tbs: number; rb: number; sf: number };
  rateSamples: RateSample[];             // for sliding-window rates
  monotonic: number;                     // last-seen event ts (sniffer side)
}

const initial: AppState = {
  connected: false,
  lifecycle: "stopped",
  pid: null,
  argv: [],
  mock: false,
  cell: null,
  hello: null,
  mib: null,
  latestSf: null,
  sfHistory: [],
  rntis: new Map(),
  stats: null,
  identities: [],
  logs: [],
  recentDci: [],
  totals: { dci: 0, dci_dl: 0, dci_ul: 0, tbs: 0, rb: 0, sf: 0 },
  rateSamples: [],
  monotonic: 0,
};

type Action =
  | { type: "connected"; value: boolean }
  | { type: "events"; evs: Event[] }
  | { type: "runtime"; state: RuntimeState }
  | { type: "mock"; value: boolean }
  | { type: "reset" };

function reduce(s: AppState, a: Action): AppState {
  switch (a.type) {
    case "connected":
      return { ...s, connected: a.value };
    case "mock":
      return { ...s, mock: a.value };
    case "reset":
      return { ...initial, connected: s.connected, mock: s.mock };
    case "runtime":
      return {
        ...s,
        lifecycle: a.state.running ? "running" : s.lifecycle,
        pid: a.state.pid ?? s.pid,
        argv: a.state.argv && a.state.argv.length ? a.state.argv : s.argv,
      };
    case "events":
      return applyEvents(s, a.evs);
  }
}

function applyEvents(prev: AppState, evs: Event[]): AppState {
  // Apply a *batch* of events with a single new state object (one re-render).
  let s = prev;
  let rntis: Map<number, RNTIStats> | null = null;
  let sfHistory = s.sfHistory;
  let recentDci = s.recentDci;
  let totals = s.totals;
  let rateSamples = s.rateSamples;
  let cell = s.cell;
  let hello = s.hello;
  let mib = s.mib;
  let stats = s.stats;
  let logs = s.logs;
  let identities = s.identities;
  let latestSf = s.latestSf;
  let lifecycle = s.lifecycle;
  let pid = s.pid;
  let argv = s.argv;
  let monotonic = s.monotonic;

  let sfAppended = 0;
  let dciAppended = 0;
  let newDcis: DCIRecord[] = [];
  let addedRntis = false;
  let logsAppended = 0;
  let identitiesAppended = 0;

  for (const ev of evs) {
    if ("ts" in ev) monotonic = Math.max(monotonic, (ev as any).ts ?? 0);
    switch (ev.t) {
      case "hello":
        hello = ev;
        break;
      case "cell":
        cell = ev;
        break;
      case "mib":
        mib = ev;
        break;
      case "stats":
        stats = ev;
        break;
      case "sf": {
        sfHistory = sfHistory === s.sfHistory ? sfHistory.slice() : sfHistory;
        sfHistory.push(ev);
        if (sfHistory.length > SF_HISTORY) sfHistory.splice(0, sfHistory.length - SF_HISTORY);
        latestSf = ev;
        sfAppended++;

        if (!rntis) rntis = new Map(s.rntis);
        let batchDci = 0, batchTbs = 0, batchRb = 0, batchDl = 0, batchUl = 0;
        for (const d of ev.dl) {
          let r = rntis.get(d.rnti);
          if (!r) { r = newRntiStats(d.rnti, ev.ts); rntis.set(d.rnti, r); addedRntis = true; }
          r.last_seen = ev.ts;
          r.dl_count += 1;
          r.dl_rb_total += d.nprb;
          r.dl_tbs_total += d.tbs;
          r.last_mcs_dl = d.mcs;
          r.last_fmt = d.fmt;
          batchDci++; batchDl++; batchTbs += d.tbs; batchRb += d.nprb;
          newDcis.push({
            ts: ev.ts, sfn: ev.sfn, sf: ev.sf, dir: "dl",
            rnti: d.rnti, fmt: d.fmt, mcs: d.mcs, nprb: d.nprb, tbs: d.tbs,
            ndi: d.ndi, harq: d.harq, hex: d.hex,
          });
          dciAppended++;
        }
        for (const d of ev.ul) {
          let r = rntis.get(d.rnti);
          if (!r) { r = newRntiStats(d.rnti, ev.ts); rntis.set(d.rnti, r); addedRntis = true; }
          r.last_seen = ev.ts;
          r.ul_count += 1;
          r.ul_rb_total += d.nprb;
          r.ul_tbs_total += d.tbs;
          r.last_mcs_ul = d.mcs;
          batchDci++; batchUl++; batchTbs += d.tbs; batchRb += d.nprb;
          newDcis.push({
            ts: ev.ts, sfn: ev.sfn, sf: ev.sf, dir: "ul",
            rnti: d.rnti, fmt: d.fmt, mcs: d.mcs, nprb: d.nprb, tbs: d.tbs,
            ndi: d.ndi, hex: d.hex,
          });
          dciAppended++;
        }
        totals = totals === s.totals ? { ...totals } : totals;
        totals.dci += batchDci;
        totals.dci_dl += batchDl;
        totals.dci_ul += batchUl;
        totals.tbs += batchTbs;
        totals.rb += batchRb;
        totals.sf += 1;

        if (batchDci || batchRb) {
          rateSamples = rateSamples === s.rateSamples ? rateSamples.slice() : rateSamples;
          rateSamples.push({ ts: ev.ts, dci: batchDci, tbs: batchTbs, rb: batchRb });
        }
        break;
      }
      case "identity":
        identities = identities === s.identities ? identities.slice() : identities;
        identities.unshift({ ts: ev.ts, sfn: ev.sfn, kind: ev.kind, rnti: ev.rnti, value: ev.value, from: ev.from });
        if (identities.length > 200) identities.length = 200;
        identitiesAppended++;
        break;
      case "log":
        logs = logs === s.logs ? logs.slice() : logs;
        logs.push({ ts: ev.ts, level: ev.level, msg: ev.msg, source: (ev as any).source });
        if (logs.length > LOG_HISTORY) logs.splice(0, logs.length - LOG_HISTORY);
        logsAppended++;
        break;
      case "bye":
        logs = logs === s.logs ? logs.slice() : logs;
        logs.push({ ts: ev.ts, level: "info", msg: `sniffer exiting (${ev.reason})` });
        if (logs.length > LOG_HISTORY) logs.splice(0, logs.length - LOG_HISTORY);
        logsAppended++;
        break;
      case "lifecycle":
        if (ev.event === "started") {
          // Hard reset, but keep ws-connected flag.
          rntis = new Map();
          sfHistory = [];
          recentDci = [];
          totals = { dci: 0, dci_dl: 0, dci_ul: 0, tbs: 0, rb: 0, sf: 0 };
          rateSamples = [];
          cell = null;
          hello = null;
          mib = null;
          stats = null;
          identities = [];
          latestSf = null;
          monotonic = 0;
          lifecycle = "running";
          pid = ev.pid ?? null;
          argv = ev.argv ?? [];
          addedRntis = true;
        } else {
          lifecycle = "stopped";
          pid = null;
          logs = logs === s.logs ? logs.slice() : logs;
          logs.push({ ts: monotonic, level: "info", msg: `process exited (code=${ev.exit_code ?? "?"})` });
          if (logs.length > LOG_HISTORY) logs.splice(0, logs.length - LOG_HISTORY);
          logsAppended++;
        }
        break;
    }
  }

  if (newDcis.length) {
    recentDci = recentDci === s.recentDci ? recentDci.slice() : recentDci;
    // Newest first; reverse the in-order list and prepend.
    for (let i = newDcis.length - 1; i >= 0; i--) recentDci.unshift(newDcis[i]);
    if (recentDci.length > RECENT_DCI) recentDci.length = RECENT_DCI;
  }

  if (rateSamples !== s.rateSamples && rateSamples.length > 0) {
    const cutoff = monotonic - METRIC_WINDOW_MS / 1000;
    while (rateSamples.length && rateSamples[0].ts < cutoff) rateSamples.shift();
  }

  if (
    sfAppended === 0 && dciAppended === 0 && logsAppended === 0 && identitiesAppended === 0 &&
    !addedRntis && cell === s.cell && hello === s.hello && mib === s.mib && stats === s.stats &&
    lifecycle === s.lifecycle
  ) {
    return s;
  }

  return {
    ...s,
    cell, hello, mib, stats,
    latestSf, sfHistory,
    rntis: rntis ?? s.rntis,
    identities, logs, recentDci,
    totals, rateSamples,
    lifecycle, pid, argv,
    monotonic,
  };
}

function newRntiStats(rnti: number, ts: number): RNTIStats {
  return {
    rnti,
    first_seen: ts,
    last_seen: ts,
    dl_count: 0,
    ul_count: 0,
    dl_rb_total: 0,
    ul_rb_total: 0,
    dl_tbs_total: 0,
    ul_tbs_total: 0,
  };
}

interface StoreCtx {
  state: AppState;
  dispatch: React.Dispatch<Action>;
}

const Ctx = createContext<StoreCtx | null>(null);

export function StoreProvider({ children }: { children: React.ReactNode }) {
  const [state, dispatch] = useReducer(reduce, initial);
  const wsRef = useRef<WebSocket | null>(null);
  const pendingRef = useRef<Event[]>([]);
  const flushTimerRef = useRef<number | null>(null);

  useEffect(() => {
    // Bootstrap runtime state from REST so we don't depend on the WS replay
    // including the `lifecycle:started` event.
    fetch("/api/status")
      .then((r) => r.json())
      .then((j) => {
        dispatch({ type: "runtime", state: j.state });
        if (typeof j.mock === "boolean") dispatch({ type: "mock", value: j.mock });
      })
      .catch(() => {});
    fetch("/api/health")
      .then((r) => r.json())
      .then((j) => {
        if (typeof j.mock === "boolean") dispatch({ type: "mock", value: j.mock });
      })
      .catch(() => {});
  }, []);

  useEffect(() => {
    let cancelled = false;
    let retry = 1000;

    const flush = () => {
      if (pendingRef.current.length === 0) {
        flushTimerRef.current = null;
        return;
      }
      const batch = pendingRef.current;
      pendingRef.current = [];
      dispatch({ type: "events", evs: batch });
      flushTimerRef.current = window.setTimeout(flush, 1000 / FLUSH_HZ);
    };

    function connect() {
      if (cancelled) return;
      const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
      // Inject bearer token via ?token= for the WS handshake (headers can't be
      // set on the browser-side WebSocket constructor).
      // Lazy import to avoid a circular dep: api.ts imports types only.
      const tok = (() => {
        try {
          return (window as any).localStorage?.getItem?.("ltesniffer_gui_token") || null;
        } catch { return null; }
      })();
      const qs = tok ? `?token=${encodeURIComponent(tok)}` : "";
      const url = `${proto}//${window.location.host}/api/events${qs}`;
      const ws = new WebSocket(url);
      wsRef.current = ws;

      ws.onopen = () => {
        retry = 1000;
        dispatch({ type: "connected", value: true });
      };
      ws.onclose = () => {
        dispatch({ type: "connected", value: false });
        if (!cancelled) setTimeout(connect, retry);
        retry = Math.min(retry * 2, 10000);
      };
      ws.onerror = () => {
        try { ws.close(); } catch {}
      };
      ws.onmessage = (m) => {
        try {
          const ev = JSON.parse(m.data) as Event | { t: "replay"; events: Event[] };
          // Server may batch the replay-on-connect into one envelope; unwrap it
          // so the reducer sees the inner events in order.
          if (ev && (ev as any).t === "replay" && Array.isArray((ev as any).events)) {
            for (const inner of (ev as any).events as Event[]) pendingRef.current.push(inner);
          } else {
            pendingRef.current.push(ev as Event);
          }
          if (flushTimerRef.current == null) {
            flushTimerRef.current = window.setTimeout(flush, 1000 / FLUSH_HZ);
          }
        } catch {}
      };
    }

    connect();
    return () => {
      cancelled = true;
      if (flushTimerRef.current) window.clearTimeout(flushTimerRef.current);
      wsRef.current?.close();
    };
  }, []);

  return React.createElement(Ctx.Provider, { value: { state, dispatch } }, children);
}

export function useStore(): StoreCtx {
  const v = useContext(Ctx);
  if (!v) throw new Error("useStore outside provider");
  return v;
}

// Derived selectors

export function useRates(state: AppState): { dci: number; tbs: number; rb: number } {
  const samples = state.rateSamples;
  if (samples.length < 2) return { dci: 0, tbs: 0, rb: 0 };
  const span = samples[samples.length - 1].ts - samples[0].ts;
  if (span <= 0) return { dci: 0, tbs: 0, rb: 0 };
  let dci = 0, tbs = 0, rb = 0;
  for (const s of samples) { dci += s.dci; tbs += s.tbs; rb += s.rb; }
  return { dci: dci / span, tbs: tbs / span, rb: rb / span };
}
