#pragma once

#include <stdint.h>
#include <string>
#include "Sniffer_dependency.h"

/*
 * Args — global configuration struct for LTESniffer.
 *
 * Every field in this struct corresponds to one or more CLI flags parsed by
 * ArgManager::parseArgs().  Fields are plain value types (no raw pointers to
 * heap memory) so the struct can be safely copied.
 */
struct Args {
  // No pointer members! Avoid shallow copies

  /* -n  : number of subframes to process before exiting; 0 = run forever */
  uint32_t    nof_subframes;

  /* --cpu-affinity : bitmask of CPU cores the main thread may run on;
   *                  -1 = no affinity constraint */
  int         cpu_affinity;

  /* -E  : when true, display an ASCII resource-block (PRB) occupancy plot */
  bool        enable_ASCII_PRB_plot;

  /* (no short flag) : when true, display an ASCII per-subframe power plot */
  bool        enable_ASCII_power_plot;

  /* (no short flag) : when true, skip carrier-frequency-offset (CFO)
   *                   correction in ue_sync */
  bool        disable_cfo;

  /* -t  : fixed timing offset in samples applied before synchronisation */
  uint32_t    time_offset;

  /* -l  : force a specific N_id_2 (0–2) for PSS detection; -1 = auto-select */
  int         force_N_id_2;

  /* -i  : path to a pre-recorded IQ sample file for offline decoding;
   *        empty string = live RF capture */
  std::string input_file_name = "";

  /* -D  : output file path for decoded DCI records; empty = stdout */
  std::string dci_file_name = "";

  /* -E  : output CSV file path for per-subframe statistics */
  std::string stats_file_name = "";

  /* -O  : sample offset into the IQ file (file mode only) */
  int         file_offset_time;

  /* -o  : frequency offset correction (Hz) applied when reading from file */
  double      file_offset_freq;

  /* -p  : number of Physical Resource Blocks (PRBs) for the target cell,
   *        e.g. 100 for a 20 MHz channel */
  uint32_t    nof_prb;

  /* (file mode) : PRB count embedded in the IQ file header */
  uint32_t    file_nof_prb;

  /* -P  : number of MIMO ports declared in the IQ file */
  uint32_t    file_nof_ports;

  /* -c  : physical cell ID embedded in the IQ file */
  uint32_t    file_cell_id;

  /* -w  : when true, wrap around to the beginning of the IQ file on EOF */
  bool        file_wrap;

  /* -a  : RF device arguments forwarded verbatim to UHD / srsRAN RF layer,
   *        e.g. "num_recv_frames=512,recv_frame_size=4096" */
  std::string rf_args;

  /* -A  : number of receive antennas to open on the RF device (1 or 2) */
  uint32_t    rf_nof_rx_ant;

  /* -f  : downlink centre frequency in Hz (mandatory in RF mode) */
  double      rf_freq;

  /* -g  : receive gain in dB; -1 activates automatic gain control (AGC) */
  double      rf_gain;

  /* -Y  : decimation factor applied to the received sample stream (0 = off) */
  int         decimate;

  /* -W  : number of parallel SubframeWorker threads for PDCCH/PDSCH decoding */
  int         nof_sniffer_thread;

  /* -I  : physical cell ID to use when cell search (-C) is disabled */
  uint32_t    cell_id = 0;

  /* -u  : uplink centre frequency in Hz; required when sniffer_mode = UL_DL_MODE */
  double      ul_freq = 0;

  /* -m  : operating mode — 0 = DL_MODE (downlink only), 1 = UL_DL_MODE (uplink and downlink) */
  int         sniffer_mode = DL_MODE;

  /* -d  : when true, print verbose debug messages to stdout */
  bool        en_debug = false;

  // other config args

  /* -T  : interval in milliseconds between DCI format search budget rebalancing
   *        (splits search time between primary and secondary DCI formats) */
  uint32_t    dci_format_split_update_interval_ms;

  /* -S  : fraction [0.0–1.0] of the per-subframe DCI search budget allocated
   *        to the primary DCI format; remainder goes to secondary formats */
  double      dci_format_split_ratio;

  /* -s  : when true, skip decoding of lower-priority (secondary) DCI meta-formats
   *        to reduce CPU load at the cost of some decode coverage */
  bool        skip_secondary_meta_formats;

  /* -L  (disable flag) : RNTI shortcut discovery pre-populates the RNTI manager
   *                       with likely active RNTIs to speed up blind decoding;
   *                       passing -L disables this optimisation */
  bool        enable_shortcut_discovery;

  /* -H  : minimum number of histogram hits an RNTI must accumulate before it is
   *        promoted to the active RNTI set (filters false positives) */
  uint32_t    rnti_histogram_threshold;

  /* -F  : output PCAP file name (overrides the default mode-based name) */
  std::string pcap_file;

  /* (no short flag) : HARQ retransmission tracking mode:
   *                    0 = disabled, 1 = enabled */
  int         harq_mode;

  /* -R  : RNTI used as a filter for certain internal operations;
   *        defaults to SRSRAN_SIRNTI (system information RNTI) */
  uint16_t    rnti;

  /* -q  : MCS / 256-QAM tracking mode — 1 = enabled (recommended),
   *        0 = disabled */
  int         mcs_tracking_mode;

  /* -v  : srsRAN internal verbose level (each -v increments the level) */
  int         verbose;

  /* (no short flag) : RF device type string passed to srsRAN RF open,
   *                    e.g. "uhd" or "zmq" */
  char*       rf_dev;

  //char* rf_args;

  /* (no short flag) : when non-zero, use CFO estimate from channel estimation
   *                    (chest) feedback in SubframeWorkers to correct the RF
   *                    centre frequency in subsequent subframes */
  int         enable_cfo_ref;

  /* (no short flag) : channel estimator interpolation algorithm name passed to
   *                    srsran_chest_dl_str2estimator_alg(); default "interpolate" */
  std::string estimator_alg;

  /* -C  : when true, perform automatic PSS/MIB cell search before decoding;
   *        when false, the cell is configured manually via -I and -p */
  bool        cell_search = false;

  /* -r  : target RNTI — when non-zero, only traffic for this specific RNTI is
   *        fully decoded (all other RNTIs are skipped); 0 = decode all */
  uint16_t    target_rnti = 0;

  /* -z  : security API mode:
   *         -1 = API disabled (default)
   *          0 = identity mapping only
   *          1 = IMSI collection
   *          2 = UE capability profiling
   *          3 = all API functions enabled */
  int         api_mode    = -1; //api functions, 0: identity mapping, 1: UECapa, 2: IMSI

  /* -K  : path to JSON key file for the key-attaching feature.
   *        When set, LTESniffer will decrypt PDCP traffic for the listed RNTIs
   *        and write plaintext IP packets to a companion pcap file. */
  std::string keys_file   = "";
};

/*
 * ArgManager — static utility class for CLI argument handling.
 *
 * All methods are static; the class cannot be instantiated.  Typical usage:
 *
 *   Args args;
 *   ArgManager::defaultArgs(args);   // fill safe defaults
 *   ArgManager::parseArgs(args, argc, argv);  // override from CLI
 *
 * parseArgs() calls defaultArgs() internally, so calling defaultArgs() first
 * is optional but harmless.
 */
class ArgManager {
public:
  static void defaultArgs(Args& args);
  static void usage(Args& args, const std::string& prog);
  static void parseArgs(Args& args, int argc, char **argv);
private:
  ArgManager() = delete;  // static only
};
