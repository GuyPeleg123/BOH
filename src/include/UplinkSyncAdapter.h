/* UplinkSyncAdapter — grant-specific, UE-specific uplink synchronization adapter.
 *
 * Sits between the raw pre-FFT uplink IQ snapshot and the existing srsRAN
 * FFT -> channel-estimation -> equalization -> soft-demod -> turbo -> CRC path.
 * For every scheduled PUSCH burst it estimates and corrects the ACTUAL arrival
 * timing at the monitor (integer + fractional), the residual CFO and the DMRS
 * phase evolution BEFORE the final FFT / PUSCH processing, and classifies the
 * estimate (validated / plausible / noise-peak / invalid) so the live path never
 * steers itself onto an unvalidated noise peak.
 *
 * Design goals, per the task spec:
 *   - Reuse the validated pipeline; do NOT rebuild the receiver. The adapter is
 *     inserted immediately before the final FFT + PUSCH processing.
 *   - The known network Timing Advance is a PRIOR only, never the final monitor
 *     timing (the monitor is not at the eNodeB antenna; UE->monitor propagation
 *     differs from UE->eNodeB, so per-UE monitor offsets must be estimated from
 *     the received waveform itself).
 *   - Grant-specific and preferably UE-specific: a bounded per-RNTI timing state
 *     is maintained and only updated from CONFIDENT observations.
 *
 * Operating model: the adapter borrows an already-initialized srsran_enb_ul_t
 * (for the FFT + srsRAN channel estimator) and a srsran_refsignal_ul_t (for the
 * exact DMRS reference), plus scratch buffers. run() operates on a pristine
 * time-domain snapshot and leaves the corrected frequency-domain symbols in
 * enb_ul.sf_symbols, so the caller decodes exactly as it does today. Offline
 * (ul_iq_replay / ul_sync_test) and live (UL_Sniffer_PUSCH) share this class.
 */
#ifndef UPLINK_SYNC_ADAPTER_H
#define UPLINK_SYNC_ADAPTER_H

#include <cstdint>
#include <string>
#include <vector>
#include <complex>
#include <unordered_map>

#ifdef __cplusplus
extern "C" {
#endif
#include "srsran/srsran.h"
#ifdef __cplusplus
}
#undef I
#endif

/* ---- Configuration of the staged synchronization + decode adapter ---- */

enum class TimingMode {
    NOMINAL = 0,       // no adapter timing change (Test 1 regression / A-B baseline)
    INTEGER,           // grant-specific integer timing only
    INTEGER_FRAC,      // integer + fractional timing
    FULL               // integer + fractional + CFO + phase
};
enum class CfoMode      { OFF = 0, PER_SUBFRAME };
enum class PhaseMode    { OFF = 0, PER_SLOT, LINEAR };

struct UplinkSyncConfig {
    // Search window (samples at the cell sample rate). Default ±1024 @ 23.04 Msps
    // ~= ±44.4 us. Configurable per spec.
    int      search_range   = 1024;
    int      coarse_step    = 16;    // coarse acquisition step (samples)
    int      max_candidates = 5;     // top coarse candidates kept for fine search
    int      fine_range     = 16;    // ±fine_range @ 1-sample around each candidate

    TimingMode timing_mode  = TimingMode::FULL;
    CfoMode    cfo_mode      = CfoMode::PER_SUBFRAME;
    PhaseMode  phase_mode    = PhaseMode::LINEAR;

    // Confidence / rejection thresholds.
    float    min_norm_corr        = 0.30f;  // reject weaker normalized DMRS corr
    float    min_peak_to_bg       = 1.30f;  // reject peaks not distinct from bg
    float    min_peak_to_2nd      = 1.05f;  // ambiguity guard
    float    max_slot_disagree    = 24.0f;  // samples; slot0/slot1 timing gap
    int      max_plausible_offset = 1024;   // |offset| beyond this is implausible

    // Timing Advance prior. When known, the coarse search is CENTERED on the TA
    // prior instead of 0, but the final offset is always the waveform estimate.
    bool     ta_known             = false;
    double   network_ta_seconds   = 0.0;

    // Nominal CFO prior (Hz) removed before per-grant residual CFO estimation.
    double   nominal_cfo_hz       = 0.0;

    // Per-UE filtered-state EMA gain (bounded update); 0 disables filtering.
    float    ue_state_alpha       = 0.25f;
};

/* ---- Rich per-grant result (mirrors the spec's UplinkSyncResult) ---- */

enum class TimingSource  { NONE = 0, NOMINAL, WAVEFORM, UE_STATE, TA_PRIOR };
enum class TimingClass   { INVALID = 0, NOISE_PEAK, PLAUSIBLE, VALIDATED };

struct UplinkSyncResult {
    bool        valid = false;
    std::string invalid_reason;

    int         integer_offset_samples      = 0;
    double      fractional_offset_samples   = 0.0;
    double      residual_cfo_hz             = 0.0;
    double      dmrs_phase_drift_rad        = 0.0;

    double      normalized_correlation      = 0.0;
    double      peak_to_second_peak         = 0.0;
    double      peak_to_background          = 0.0;
    double      slot0_correlation           = 0.0;
    double      slot1_correlation           = 0.0;
    double      slot_timing_difference_samples = 0.0;

    double      confidence                  = 0.0;   // 0..1
    TimingClass timing_class                = TimingClass::INVALID;
    TimingSource timing_source              = TimingSource::NONE;
    bool        corrected_iq_available      = false;

    // Diagnostics carried through for the report / batch harness.
    double      chest_snr_db                = 0.0;   // srsRAN chest SNR at the chosen window
    double      nominal_chest_snr_db        = 0.0;   // srsRAN chest SNR at the nominal window
    double      ta_prior_samples            = 0.0;   // network TA expressed in monitor samples
};

/* ---- Bounded per-UE uplink timing state (spec Part 8) ---- */
struct UeUplinkTimingState {
    uint16_t rnti                  = 0;
    bool     initialized           = false;
    double   filtered_integer_offset    = 0.0;
    double   filtered_fractional_offset = 0.0;
    double   filtered_cfo_hz            = 0.0;
    double   timing_variance            = 0.0;
    double   cfo_variance               = 0.0;
    uint32_t last_tti                   = 0;
    unsigned confident_observations     = 0;
};

class UplinkSyncAdapter {
public:
    UplinkSyncAdapter() = default;
    ~UplinkSyncAdapter();

    /* One-time init. Borrows an enb_ul that is already set_cell'd for this cell;
       builds a private refsignal_ul for the exact DMRS and allocates scratch.
       dmrs_cfg is the cell DMRS common config (as used by the live path). */
    bool configure(srsran_enb_ul_t* enb_ul, const srsran_cell_t& cell,
                   const srsran_refsignal_dmrs_pusch_cfg_t& dmrs_cfg,
                   const UplinkSyncConfig& cfg);

    void set_config(const UplinkSyncConfig& cfg) { cfg_ = cfg; }
    const UplinkSyncConfig& config() const { return cfg_; }

    /* Run the staged adapter on a pristine pre-FFT snapshot for ONE grant.
       `pristine` holds >= 2*sf_len samples with the target subframe starting at
       index 0 (same convention as refft_at_offset / the replay snapshot).
       ul_sf/ul_cfg describe the exact grant (rnti, grant, dmrs, hopping, uci).
       On return, if result.corrected_iq_available, enb_ul->sf_symbols holds the
       corrected frequency-domain symbols ready for srsran_pusch_decode. */
    UplinkSyncResult run(const cf_t* pristine, uint32_t nof_samples,
                         uint32_t sf_len,
                         srsran_ul_sf_cfg_t& ul_sf, srsran_ul_cfg_t& ul_cfg);

    /* Place the corrected symbols for a specific integer+fractional+CFO estimate
       into enb_ul->sf_symbols (used by run() and directly by test harnesses). */
    bool synthesize_corrected_symbols(const cf_t* pristine, uint32_t nof_samples,
                                      uint32_t sf_len,
                                      int integer_off, double frac_off, double cfo_hz);

    UeUplinkTimingState* ue_state(uint16_t rnti);

private:
    /* One "probe" at a given integer window offset: shift + FFT into
       enb_ul->sf_symbols, then compute both the srsRAN chest SNR and the
       DMRS-LS metrics (per-slot normalized correlation, residual CFO, fractional
       timing from the DMRS phase slope). */
    struct Probe {
        bool   ok = false;
        int    off = 0;
        float  chest_snr_db = NAN;
        float  chest_ta_us  = NAN;
        double norm_corr = 0, slot0_corr = 0, slot1_corr = 0;
        double frac_off = 0;         // fractional sample offset from DMRS phase slope
        double cfo_hz = 0;           // residual CFO from slot0->slot1 DMRS phase
        double phase_drift_rad = 0;
        double energy = 0;
    };
    Probe probe_at(const cf_t* pristine, uint32_t nof_samples, uint32_t sf_len,
                   srsran_ul_sf_cfg_t& ul_sf, srsran_ul_cfg_t& ul_cfg,
                   int off, double cfo_hz, double frac_off, bool want_chest);

    // DMRS-LS estimator on the current enb_ul->sf_symbols. Fills the per-slot
    // channel estimate vectors h0/h1 (length Msc = L_prb*12) and the reference.
    bool dmrs_ls(srsran_ul_sf_cfg_t& ul_sf, srsran_ul_cfg_t& ul_cfg,
                 std::vector<std::complex<float>>& h0,
                 std::vector<std::complex<float>>& h1);

    void shift_copy(const cf_t* pristine, uint32_t nof_samples, uint32_t sf_len,
                    int off, double cfo_hz, double frac_off, cf_t* working, uint32_t copy_len);

    srsran_enb_ul_t*  enb_ul_ = nullptr;
    srsran_cell_t     cell_{};
    srsran_refsignal_ul_t refs_{};
    srsran_refsignal_dmrs_pusch_cfg_t dmrs_cfg_{};
    UplinkSyncConfig  cfg_{};
    bool              configured_ = false;
    uint32_t          fft_size_ = 0;
    double            fs_hz_ = 0;

    std::vector<cf_t> working_;                 // shifted/corrected time-domain scratch
    std::vector<cf_t> ref_dmrs_;                // 2*Msc reference DMRS
    std::vector<cf_t> rx_dmrs_;                 // 2*Msc received DMRS
    std::unordered_map<uint16_t, UeUplinkTimingState> ue_states_;
};

const char* timing_class_str(TimingClass c);
const char* timing_source_str(TimingSource s);

#endif // UPLINK_SYNC_ADAPTER_H
