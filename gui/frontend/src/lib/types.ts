// Event types — mirror gui/PROTOCOL.md.

export interface DCIDL {
  rnti: number;
  fmt: string;
  mcs: number;
  nprb: number;
  tbs: number;
  ndi: number;
  harq: number;
  ncce: number;
  L: number;
  hist: number;
  hex: string;
}

export interface DCIUL extends Omit<DCIDL, "harq"> {}

export type Event =
  | { t: "hello"; ts: number; version: number; args: Record<string, any> }
  | {
      t: "cell";
      ts: number;
      pci: number;
      nof_prb: number;
      nof_ports: number;
      cp: string;
      mode: string;
      dl_freq: number;
      ul_freq: number;
      sample_rate: number;
    }
  | { t: "mib"; ts: number; sfn: number; sfn_offset: number }
  | { t: "sf_tick"; ts: number; sfn: number; sf: number; cfi: number; dl_n: number; ul_n: number }
  | {
      t: "sf";
      ts: number;
      sfn: number;
      sf: number;
      cfi: number;
      dl: DCIDL[];
      ul: DCIUL[];
      rb_dl: number[];
      rb_ul: number[];
      pwr_dl: number[];
      pwr_min?: number;
      pwr_max?: number;
    }
  | { t: "log"; ts: number; level: string; msg: string; source?: string }
  | {
      t: "stats";
      ts: number;
      sfn: number;
      sf_processed: number;
      sf_skipped: number;
      nof_rnti: number;
      rb_dl_total: number;
      rb_ul_total: number;
      cfo_hz: number;
    }
  | {
      t: "identity";
      ts: number;
      sfn: number;
      kind: string;
      rnti: number;
      value: string;
      from: string;
    }
  | { t: "bye"; ts: number; reason: string }
  | { t: "lifecycle"; event: "started" | "exited"; pid?: number; argv?: string[]; exit_code?: number };

export interface SnifferConfig {
  rf_freq: number;
  ul_freq: number;
  rf_gain: number;
  rf_nof_rx_ant: number;
  rf_args: string;
  usrp_a_args: string;
  usrp_b_args: string;
  decimate: number;
  cpu_affinity: number;
  sniffer_mode: number;
  api_mode: number;
  cell_search: boolean;
  cell_id: number;
  nof_prb: number;
  target_rnti: number;
  nof_sniffer_thread: number;
  skip_secondary_meta_formats: boolean;
  dci_format_split_ratio: number;
  dci_format_split_update_interval_ms: number;
  enable_shortcut_discovery: boolean;
  rnti_histogram_threshold: number;
  mcs_tracking_mode: number;
  en_debug: boolean;
  dci_file_name: string;
  stats_file_name: string;
  keys_file: string;
  pcap_stream_fifo: string;
  binary_path: string;
  captures_dir: string;
  sudo: boolean;
}

export interface CaptureFile {
  path: string;
  name: string;
  size: number;
  mtime: number;
  source: string;
  active: boolean;
}

export interface CapturesResponse {
  captures: CaptureFile[];
  roots: string[];
  captures_dir: string;
}

export type CipherAlgo = "EEA0" | "EEA1" | "EEA2" | "EEA3";
export type IntegAlgo = "EIA0" | "EIA1" | "EIA2" | "EIA3";

export interface KeyEntry {
  rnti: number;                  // 0..0xFFFF, displayed in hex in UI
  kenb?: string | null;          // 64 hex chars
  kasme?: string | null;         // 64 hex chars
  nas_count?: number | null;     // required iff kasme set, no kenb
  cipher_algo?: CipherAlgo | null;
  integ_algo?: IntegAlgo | null;
  hfn_hint?: number;             // 0 default
  label?: string | null;
}

export interface KeysResponse {
  entries: KeyEntry[];
  path: string;
  exists: boolean;
}

export interface KnownCell {
  label: string;
  dl_freq_mhz: number;
  ul_freq_mhz: number;
  bandwidth_mhz: number | null;
  nof_prb: number;
  pci: number | null;
  sniffer_mode: number;
  usrp_a_args: string;
  usrp_b_args: string;
  rf_gain: number;
  last_success_iso: string;
  notes: string;
}

export interface KnownCellsResponse {
  cells: KnownCell[];
  path: string;
}

export interface USRPDevice {
  type?: string;
  serial?: string;
  name?: string;
  product?: string;
  [key: string]: string | undefined;
}

export interface RuntimeState {
  running: boolean;
  pid: number | null;
  started_at: number | null;
  exit_code: number | null;
  last_error: string | null;
  argv: string[];
  mock?: boolean;
}
