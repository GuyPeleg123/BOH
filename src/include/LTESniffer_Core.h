/*
 * Copyright (c) 2019 Robert Falkenberg.
 *
 * This file is part of FALCON 
 * (see https://github.com/falkenber9/falcon).
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * A copy of the GNU Affero General Public License can be found in
 * the LICENSE file in the top-level directory of this distribution
 * and at http://www.gnu.org/licenses/.
 */
#pragma once

#include <map>

#include "ArgManager.h"
#include "KeyAttaching.h"
#include "falcon/common/SignalManager.h"
#include "include/SubframeWorker.h"
#include "include/ThreadSafeQueue.h"
#include "include/WorkerThread.h"
#include "Sniffer_dependency.h"
#include "MCSTracking.h"
#include "ULSchedule.h"
#include "srsran/common/mac_pcap.h"
#include "Phy.h"
#include "PcapWriter.h"
#include "HARQ.h"
#include <ctime>
#include <iostream>
#include <boost/program_options.hpp>
#include <boost/program_options/parsers.hpp>
#include "srsue/hdr/ue.h"
#include "falcon/prof/Lifetime.h"

using namespace srsue;
namespace bpo = boost::program_options;

// include C-only headers
#ifdef __cplusplus
    extern "C" {
#endif

#include "srsran/phy/utils/debug.h"
#include "falcon/phy/falcon_ue/falcon_ue_dl.h"
#include "srsran/srsran.h"
#include "srsran/phy/rf/rf.h"
#include "srsran/phy/rf/rf_utils.h"

#ifdef __cplusplus
}
#undef I // Fix complex.h #define I nastiness when using C++
#endif
using namespace srsran;

#define UL_SNIFFER_UL_MAX_OFFSET 200
#define UL_SNIFFER_UL_OFFSET_32 32
#define UL_SNIFFER_UL_OFFSET_64 64

typedef struct {
  cf_t* ta_temp_buffer;
  cf_t  ta_last_sample[UL_SNIFFER_UL_MAX_OFFSET];
  int   cnt =  0;
  int   sf_sample_size;

} UL_Sniffer_ta_buffer_t;

static SRSRAN_AGC_CALLBACK(srsran_rf_set_rx_gain_th_wrapper_)
{
  srsran_rf_set_rx_gain_th((srsran_rf_t*)h, gain_db);
}

/* srsran_rf_recv_wrapper — see LTESniffer_Core.cc for full documentation.
 * Registered as the ue_sync receive callback; reads IQ samples from the RF
 * device into the SubframeWorker buffers on every ue_sync iteration. */
int srsran_rf_recv_wrapper( void* h,
                            cf_t* data_[SRSRAN_MAX_PORTS],
                            uint32_t nsamples,
                            srsran_timestamp_t* t);

/*
 * LTESniffer_Core — top-level runtime controller for a passive LTE capture
 * session.
 *
 * Responsibilities
 * ----------------
 *   - Opens the RF front-end (or IQ file) and configures the receive chain.
 *   - Runs optional automatic PSS/SSS/MIB cell search.
 *   - Initialises srsRAN ue_sync for continuous LTE frame synchronisation.
 *   - Drives the subframe state machine (DECODE_MIB → DECODE_PDSCH).
 *   - Dispatches time-aligned subframe buffers to a pool of SubframeWorker
 *     threads (managed by Phy) for blind PDCCH / PDSCH / PUSCH decoding.
 *   - Collects decoded MAC PDUs and writes them to a PCAP file via PcapWriter.
 *   - Maintains MCS-tracking and HARQ retransmission databases.
 *   - Handles OS signals (SIGINT / SIGTERM) to initiate a clean shutdown.
 *
 * The class is non-copyable.  Create exactly one instance per capture session
 * and call run() from the main thread; call stop() from a signal handler or
 * another thread to request a graceful exit.
 */
class LTESniffer_Core : public SignalHandler {
public:
  LTESniffer_Core(const Args& args);
  LTESniffer_Core(const LTESniffer_Core&) = delete; //prevent copy
  LTESniffer_Core& operator=(const LTESniffer_Core&) = delete; //prevent copy
  virtual ~LTESniffer_Core() override;
  
  RNTIManager &getRNTIManager();
  void setDCIConsumer(std::shared_ptr<SubframeInfoConsumer> consumer);
  void resetDCIConsumer();
  void refreshShortcutDiscovery(bool val);
  void setRNTIThreshold(int val);
  void print_api_header();
  bool run();
  void stop();
private:

  void handleSignal() override;

  Args                    args;             // full copy of CLI arguments passed to the constructor
  int                     nof_workers;      // number of SubframeWorker threads (= args.nof_sniffer_thread)
  int                     sniffer_mode;     // -m : DL_MODE=0 or UL_MODE=1
  int                     api_mode    ;     // -z : security API mode (-1=off, 0–3=various levels)
  bool                    go_exit = false;  // set to true by stop()/handleSignal() to break the main loop
  enum receiver_state     { DECODE_MIB, DECODE_PDSCH} state; // current subframe processing state
  std::mutex              harq_map_mutex;   // protects concurrent access to the HARQ database
  Phy                     *phy;             // owns the SubframeWorker pool and common PHY state
  LTESniffer_pcap_writer  pcapwriter;       // writes decoded MAC PDUs to a PCAP file
  srsran::mac_pcap        mac_pcap;         // srsRAN MAC PCAP helper (backup / API path)
  int                     mcs_tracking_mode; // -q : 0=disabled, 1=enabled MCS/256-QAM tracking
  MCSTracking             mcs_tracking;     // per-RNTI MCS and 256-QAM modulation tracker
  ULSchedule              ulsche;           // uplink scheduling oracle (maps DL DCI to UL grants)
  UL_Sniffer_ta_buffer_t  ta_buffer;        // temporary IQ buffer used to receive UL samples
                                            //   slightly ahead of the DL timing reference
  std::atomic<float>      est_cfo;          // latest CFO estimate fed back from SubframeWorkers
                                            //   (chest-based); used to steer the RF centre frequency
  UL_HARQ                 ul_harq;          // uplink HARQ process tracker
  HARQ                    harq;             // downlink HARQ retransmission tracker
  int                     harq_mode;        // 0=HARQ disabled, 1=HARQ tracking enabled
  KeyStore                key_store_;       // PDCP decryption engine (empty unless -K flag given)
};
