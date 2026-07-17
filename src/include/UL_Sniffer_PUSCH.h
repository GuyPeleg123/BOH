#pragma once
#include "KeyAttaching.h"
#include "DCICollection.h"
#include "PcapWriter.h"
#include "ULSchedule.h"
#include "SubframePower.h"
#include "MCSTracking.h"
#include "Sniffer_dependency.h"
#include "srsran/phy/common/phy_common.h"
#include "srsran/interfaces/ue_interfaces.h"
#include "srsran/asn1/rrc/ul_ccch_msg.h"
#include "srsran/asn1/rrc/ul_dcch_msg.h"
#include "srsran/rlc/rlc_common.h"
#include "srsran/rlc/rlc_am_lte.h"
#include "srsran/asn1/liblte_common.h"
#include "srsran/asn1/liblte_mme.h"
#include "srsran/asn1/s1ap.h"
#include "srsran/mac/pdu.h"
#include <sstream>

using namespace asn1;
using namespace asn1::s1ap;
using namespace rrc;

#include <iostream>
#include <fstream>
#include <unordered_map>

// include C-only headers
#ifdef __cplusplus
    extern "C" {
#endif

#include "srsran/phy/phch/pusch_cfg.h"
#include "srsran/phy/enb/enb_ul.h"
#include "srsran/phy/ue/ue_ul.h"
#include "falcon/phy/falcon_phch/dl_sniffer_pdsch.h"

#ifdef __cplusplus
}
#undef I // Fix complex.h #define I nastiness when using C++
#endif

const static int prach_buffer_sz = 128 * 1024;

class PUSCH_Decoder
{
public:
    PUSCH_Decoder(srsran_enb_ul_t &enb_ul,
                  srsran_ul_sf_cfg_t &ul_sf,
                  ULSchedule *ulsche,
                  cf_t** original_buffer,
                  cf_t** buffer_offset,
                  srsran_ul_cfg_t    &ul_cfg,
                  LTESniffer_pcap_writer *pcapwriter,
                  MCSTracking *mcstracking,
                  bool en_debug);
    ~PUSCH_Decoder();

    void init_pusch_decoder(std::vector<DCI_UL> dci_ul,
                            std::vector<DCI_UL> rar_dci_ul,
                            srsran_ul_sf_cfg_t &ul_sf,
                            SubframePower* sf_power);
    void decode();

    /* Grant-keyed raw-IQ capture of the NOMINAL-window decode (env UL_IQ_REC).
       Called once per grant right after the pass-1 decode, before any offset
       retry mutates sf_symbols, so the stored IQ + config + result form a
       self-consistent set that the offline replay tool reproduces exactly. */
    void maybe_capture_iq(DCI_UL &decoding_mem, bool crc,
                          float nominal_snr, float nominal_ta_us,
                          bool offset_retry_enabled);

    int  decode_rrc_connection_request(DCI_UL &decoding_mem, uint8_t* sdu_ptr, int length);
    int  decode_ul_dcch(DCI_UL &decoding_mem, uint8_t* sdu_ptr, int length);
    int  decode_nas_ul(DCI_UL &decoding_mem, uint8_t* sdu_ptr, int length);
    // void decode_IMSI_attach(DCI_UL &decoding_mem, uint8_t* sdu_ptr, int length);
    
    /*Investigate UL grant before decoding it*/
    int  check_valid_prb_ul(uint32_t nof_prb);
    int  investigate_valid_ul_grant(DCI_UL &decoding_mem);

    void decode_run(std::string info, DCI_UL &decoding_mem, std::string mod, float falcon_signal_power);

    void set_configed() { configed = true;}
    bool get_configed() { return configed;}

    std::string modulation_mode_string(int mode, bool max_64qam);
    std::string modulation_mode_string_256(int idx);
    void print_debug(DCI_UL &decoding_mem, 
                     std::string offset_name, 
                     std::string modulation_mode,
                     float signal_pw,
                     double noise,
                     double falcon_sgl_pwr);
    void print_ul_grant(srsran_pusch_grant_t& grant);
    void print_uci(srsran_uci_value_t *uci);
    void print_success(DCI_UL &decoding_mem, std::string offset_name, int table);
    void print_api(uint32_t tti, uint16_t rnti, int ident, std::string value, int msg);

    void set_rach_config(srsran_prach_cfg_t prach_cfg_);

    void work_prach(); 

    void set_ul_harq (UL_HARQ *ul_harq_) { ul_harq = ul_harq_;  }
    void set_target_rnti(uint16_t rnti)  { target_rnti = rnti;  }
    void set_debug_mode(bool en_debug_)  { en_debug = en_debug_;}
    void set_api_mode(int api_mode_)     { api_mode = api_mode_;}
    void set_key_store(KeyStore* ks)     { key_store_ = ks;     }
    void set_decoder(std::string a_b){
        if (a_b == "a"){
            decoder_a = true;
            debug_str = "A";
        }else if (a_b == "b"){
            decoder_b = true;
            debug_str = "B";
        }
    }
private:
    /* Run the full per-grant MCS-table decode sequence on whatever symbols are
       currently in enb_ul.sf_symbols. Returns true if CRC passed. Used by both
       the nominal pass and the FFT-window-offset retry pass. Internal to the
       decode() call sequence — must not be called out of order. */
    bool decode_grant(DCI_UL &decoding_mem);

    /* Re-run the UL FFT on a window shifted by sample_offset samples relative to
       the nominal subframe start, writing into enb_ul.sf_symbols. Reads from the
       clean pre-FFT snapshot in sf_buffer_offset[0]. Returns false if the offset
       would read outside the available buffer. */
    bool refft_at_offset(int sample_offset);

    /* Env-gated (UL_SYNC_ADAPTER) grant-specific UplinkSyncAdapter fallback: runs
       the staged per-UE timing/CFO estimator on the pre-FFT snapshot and, if it
       accepts, decodes on the corrected symbols. Uses a PRIVATE enb_ul scratch so
       the wide search never touches the shared raw buffer. Lazily initialized. */
    void ensure_sync_adapter();
    class UplinkSyncAdapter* sync_adapter_ = nullptr;
    srsran_enb_ul_t*         adapter_enb_ul_ = nullptr;
    std::vector<cf_t>        adapter_in_buf_;

    /* HARQ soft-combining (env UL_HARQ_COMBINE). Persistent per-(RNTI, HARQ
       process) rx softbuffers: on a NEW transmission the buffer is reset; on a
       retransmission the soft bits ACCUMULATE across TTIs (srsRAN de-rate-matches
       additively), so a grant that fails single-shot can decode once combined.
       Applied to the NOMINAL-window decode only; the offset-retry / adapter use
       the default scratch buffer so alternate-window probes never pollute HARQ. */
    srsran_softbuffer_rx_t* harq_get(uint16_t rnti, uint32_t pid, bool is_new_tx);
    std::unordered_map<uint64_t, srsran_softbuffer_rx_t*> harq_buffers_;
    // Per-(RNTI,HARQ-process) last DCI0 NDI. A grant whose NDI matches the stored
    // value for its process is a RETRANSMISSION of the same TB (NDI only toggles
    // on new data); that is how we detect retx (the is_retx field is unused).
    std::unordered_map<uint64_t, int> harq_last_ndi_;
    srsran_softbuffer_rx_t* default_sb_ = nullptr;
    bool harq_on_       = false;
    bool harq_no_reset_ = false;   // read by decode_run to skip the per-call reset

    bool        decoder_a = false;
    bool        decoder_b = false;
    std::string debug_str = "";
    uint16_t target_rnti    = -1;
    bool en_debug           = false;
    int api_mode            = -1;
    bool configed           = false;
    ULSchedule              *ulsche;
    cf_t                    **original_buffer   = {nullptr};
    cf_t                    **buffer_offset    = {nullptr};
    SubframePower           *sf_power;

    std::vector<DCI_UL>     dci_ul;       // owned copies (were raw pointers into ULSchedule's map)
    std::vector<DCI_UL>     rar_dci_ul;
    int                     valid_ul_grant      = SRSRAN_ERROR;

    srsran_enb_ul_t         &enb_ul;
    srsran_ul_sf_cfg_t      &ul_sf;
    LTESniffer_pcap_writer  *pcapwriter;
    srsran_pusch_res_t      pusch_res           = {};
    srsran_ul_cfg_t         &ul_cfg;

    /*variables for prach*/
    srsran_prach_cfg_t      prach_cfg           = {};
    srsran_prach_t          prach               = {};
    uint32_t                prach_indices[165]  = {};
    float                   prach_offsets[165]  = {};
    float                   prach_p2avg[165]    = {};
    uint32_t                nof_sf = 0;
    bool                    prach_detection_enabled = true;
    cf_t                    samples[prach_buffer_sz] = {};
    UL_HARQ                 *ul_harq; //on developing
    MCSTracking             *mcstracking;
    KeyStore*               key_store_          = nullptr;

    /*Backup*/
    int                     multi_ul_offset;

    /* Nominal-window frequency-domain symbols, saved once per subframe after the
       top FFT so the offset-retry pass can restore enb_ul.sf_symbols for the
       next grant without re-running the (in-place, non-repeatable) FFT. */
    cf_t*                   sf_symbols_nominal  = nullptr;
    uint32_t                sf_symbols_len      = 0;

    /* UL 2-RX selection diversity (env UL_DIVERSITY): antenna-1 frequency-domain
       symbols, FFT'd once per subframe from original_buffer[1] so a CRC-failed
       grant can retry on the second UL antenna. */
    bool                    ul_diversity        = false;
    cf_t*                   sf_symbols_ant1     = nullptr;
};


