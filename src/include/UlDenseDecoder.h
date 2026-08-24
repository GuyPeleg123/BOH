#pragma once
/* UlDenseDecoder — calibrated-window uplink PUSCH decode (from-scratch path).
 *
 * Written BESIDE the legacy PUSCH_Decoder, not replacing it. Enabled by env
 * UL_DENSE2=1 (GUI "Dense Test" button); when off, nothing here runs and the
 * legacy path is bit-for-bit unchanged.
 *
 * Sole novel job: place the UL FFT window correctly for a PASSIVE monitor. The
 * uplink has no sync beacon, so radio B inherits DL timing plus a FIXED,
 * uncalibrated group-delay offset (measured ~ -725 samples on this rig). This
 * class self-calibrates that fixed offset from strong clean DMRS locks, then
 * decodes each grant at (C_fixed + per-UE geometric residual). See
 * docs/UlDenseDecoder.md.
 *
 * Reuses srsRAN's canonical decode primitives unchanged (enb_ul FFT, chest,
 * pusch_decode); does NOT call into PUSCH_Decoder's private methods.
 */
#include "DCICollection.h"
#include "PcapWriter.h"
#include "ULSchedule.h"
#include "SubframePower.h"
#include "MCSTracking.h"
#include "Sniffer_dependency.h"

#include <cstdint>
#include <vector>
#include <deque>
#include <unordered_map>

#ifdef __cplusplus
extern "C" {
#endif
#include "srsran/phy/enb/enb_ul.h"
#include "srsran/phy/phch/pusch_cfg.h"
#ifdef __cplusplus
}
#undef I
#endif

class UlDenseDecoder
{
public:
    UlDenseDecoder(srsran_enb_ul_t   &enb_ul,
                   srsran_ul_sf_cfg_t &ul_sf,
                   srsran_ul_cfg_t    &ul_cfg,
                   ULSchedule         *ulsche,
                   cf_t              **original_buffer,   // [1] = radio B (UL)
                   cf_t              **scratch_buffer,     // snapshot / working pair
                   LTESniffer_pcap_writer *pcapwriter,
                   MCSTracking        *mcstracking);
    ~UlDenseDecoder();

    static bool enabled();          // reads UL_DENSE2 once

    /* Mirror of PUSCH_Decoder::init_pusch_decoder — give this subframe's grants. */
    void init(std::vector<DCI_UL> dci_ul,
              std::vector<DCI_UL> rar_dci_ul,
              srsran_ul_sf_cfg_t &ul_sf,
              SubframePower *sf_power);

    /* Decode all grants of the current subframe with calibrated windowing. */
    void decode();

    void set_target_rnti(uint16_t rnti) { target_rnti_ = rnti; }

private:
    // --- window mechanics -------------------------------------------------
    void snapshot_raw();                       // clean pre-FFT copy of radio B
    bool fft_at_offset(int sample_offset);     // re-FFT shifted window -> sf_symbols
    float chest_snr_at(int sample_offset,      // FFT+chest at offset, return snr_db
                       srsran_pusch_cfg_t &pusch);

    // --- decode -----------------------------------------------------------
    bool build_pusch_cfg(DCI_UL &g, srsran_pusch_cfg_t &pusch); // grant -> cfg (std table)
    float grant_energy_db(DCI_UL &g);          // chest-free allocated-RB power over floor
    bool decode_current(DCI_UL &g, srsran_pusch_cfg_t &pusch);  // chest+decode+zero-guard+pcap

    // --- calibration state ------------------------------------------------
    int   window_origin(uint16_t rnti);        // C_fixed + delta_ue (+ TA prior)
    void  observe_lock(uint16_t rnti, int off, float snr, bool distinct);
    int   c_fixed_ = 0;                        // shared fixed calibration offset (samples)
    bool  c_seeded_ = false;                   // false until enough strong locks
    std::deque<int> c_samples_;                // recent strong-lock offsets -> robust median
    std::unordered_map<uint16_t,float> delta_ue_;   // per-RNTI geometric residual (EMA, samples)

    // --- config (env) -----------------------------------------------------
    float min_energy_db_ = 3.0f;
    float boot_gate_db_  = 8.0f;               // only >= this energy pays for the wide bootstrap scan
    int   pos_guard_     = 40;                  // reject CRC at window offset > this (real UL arrives <= DL ref; +offset is geometrically impossible => noise false positive)
    int   boot_range_    = 900;
    int   fine_range_    = 150;
    int   fine_step_     = 6;
    float lock_snr_db_   = 6.0f;
    int   forced_c_      = INT32_MIN;          // UL_DENSE2_CAL override (disabled sentinel)

    // --- borrowed handles -------------------------------------------------
    srsran_enb_ul_t    &enb_ul_;
    srsran_ul_sf_cfg_t &ul_sf_;
    srsran_ul_cfg_t    &ul_cfg_;
    ULSchedule         *ulsche_;
    cf_t              **original_buffer_;
    cf_t              **scratch_buffer_;        // [0]=pristine snapshot, [1]=working
    LTESniffer_pcap_writer *pcapwriter_;
    MCSTracking        *mcstracking_;
    SubframePower      *sf_power_ = nullptr;

    // --- HARQ soft-combining (env UL_DENSE2_HARQ) ------------------------
    // Persistent per-(RNTI, HARQ process) rx softbuffers. New transmission (DCI0
    // NDI toggled) resets the buffer; a retransmission ACCUMULATES soft bits so a
    // grant that fails single-shot can decode once combined. Applied to the
    // PRIMARY-window decode only; alternate-window candidates use own_sb_ so they
    // never pollute HARQ state. Mirrors the legacy PUSCH_Decoder HARQ path.
    srsran_softbuffer_rx_t* harq_get(uint16_t rnti, uint32_t pid, bool is_new_tx);
    std::unordered_map<uint64_t, srsran_softbuffer_rx_t*> harq_buffers_;
    std::unordered_map<uint64_t, int> harq_last_ndi_;
    bool harq_on_       = true;
    bool harq_no_reset_ = false;                    // set per-decode: retx => don't reset

    std::vector<DCI_UL> dci_ul_;
    std::vector<DCI_UL> rar_dci_ul_;
    srsran_pusch_res_t  pusch_res_ = {};
    srsran_softbuffer_rx_t *own_sb_ = nullptr;      // this decoder's private rx softbuffer
    cf_t*               nominal_sym_ = nullptr;     // nominal-window FFT symbols, saved once/subframe + reused for every grant's nominal decode (shared, like legacy)
    uint32_t            nominal_sym_len_ = 0;

    // ---- 2-RX maximal-ratio combining (env UL_DENSE2_MRC) -----------------
    // Coherently combines the two UL antennas at the nominal window before decode
    // (the "equivalent single antenna" pre-combine, so srsran_pusch_decode is
    // reused unchanged). Right technique for an UNBALANCED pair (ant0=LNA,
    // ant1=no LNA): coherent combining still extracts the weaker antenna's SNR,
    // whereas selection diversity would just always pick ant0. Needs rf_b opened
    // with 2 channels (UL_DIVERSITY / nof_rx_ant=2); ant1 samples in original_buffer_[1].
    bool  mrc_on_       = false;
    cf_t* sf_sym_ant1_  = nullptr;                  // ant1 nominal-window FFT symbols
    cf_t* ce0_          = nullptr;                  // saved ant0 channel estimate
    bool  mrc_decode(DCI_UL &g, srsran_pusch_cfg_t &pusch);   // chest both ants + MRC + decode
    bool  decode_tb(DCI_UL &g, srsran_pusch_cfg_t &pusch);    // pusch_decode + guards + pcap (chest already done)

    // ---- per-UE CFO correction (env UL_DENSE2_CFO) ------------------------
    // srsRAN's UL chest ESTIMATES per-grant CFO (chest_res.cfo_hz from the two
    // DMRS symbols) but NEVER applies it — the data symbols stay rotated relative
    // to the DMRS-based channel estimate, so a UE with residual frequency offset
    // (Doppler / imperfect DL-lock) fails decode at good DMRS SINR. This is the
    // eNB-vs-passive gap (the eNB closed-loop tracks each UE's frequency). We
    // estimate CFO from the nominal chest, de-rotate every OFDM symbol by its true
    // time phase, re-chest, and decode. A/B (UL_DENSE2_CFO_DIAG) counts grants CFO
    // recovers that the uncorrected decode cannot.
    bool  cfo_on_ = false;
    cf_t* cfo_work_ = nullptr;                               // de-rotated symbol scratch
    bool  cfo_decode(DCI_UL &g, srsran_pusch_cfg_t &pusch);
    srsran_softbuffer_rx_t* mrc_dry_sb_ = nullptr;           // scratch for the ant0-alone A/B dry decode
    uint8_t* mrc_dry_data_ = nullptr;
    uint16_t            target_rnti_ = 0xFFFF;
    bool                cfg_read_ = false;
    void read_env_once();
};
