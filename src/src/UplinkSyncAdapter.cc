/* UplinkSyncAdapter implementation — see UplinkSyncAdapter.h for the contract. */
#include "include/UplinkSyncAdapter.h"

#include <cmath>
#include <cstring>
#include <algorithm>
#include <numeric>

using cf = std::complex<float>;

const char* timing_class_str(TimingClass c)
{
    switch (c) {
        case TimingClass::VALIDATED:  return "validated";
        case TimingClass::PLAUSIBLE:  return "plausible";
        case TimingClass::NOISE_PEAK: return "noise_peak";
        default:                      return "invalid";
    }
}
const char* timing_source_str(TimingSource s)
{
    switch (s) {
        case TimingSource::NOMINAL:  return "nominal";
        case TimingSource::WAVEFORM: return "waveform";
        case TimingSource::UE_STATE: return "ue_state";
        case TimingSource::TA_PRIOR: return "ta_prior";
        default:                     return "none";
    }
}

UplinkSyncAdapter::~UplinkSyncAdapter()
{
    // srsran_refsignal_ul_t holds only precomputed tables (filled by set_cell);
    // there is no heap to release.
}

bool UplinkSyncAdapter::configure(srsran_enb_ul_t* enb_ul, const srsran_cell_t& cell,
                                  const srsran_refsignal_dmrs_pusch_cfg_t& dmrs_cfg,
                                  const UplinkSyncConfig& cfg)
{
    enb_ul_   = enb_ul;
    cell_     = cell;
    dmrs_cfg_ = dmrs_cfg;
    cfg_      = cfg;
    if (srsran_refsignal_ul_set_cell(&refs_, cell) != SRSRAN_SUCCESS) return false;
    fft_size_ = srsran_symbol_sz(cell.nof_prb);
    fs_hz_    = (double)fft_size_ * 15000.0;   // LTE SC spacing 15 kHz
    working_.assign(3 * SRSRAN_SF_LEN_PRB(100), cf_t{});
    ref_dmrs_.assign(2 * SRSRAN_NRE * cell.nof_prb, cf_t{});
    rx_dmrs_.assign(2 * SRSRAN_NRE * cell.nof_prb, cf_t{});
    configured_ = true;
    return true;
}

UeUplinkTimingState* UplinkSyncAdapter::ue_state(uint16_t rnti)
{
    auto it = ue_states_.find(rnti);
    if (it == ue_states_.end()) {
        UeUplinkTimingState s; s.rnti = rnti;
        it = ue_states_.emplace(rnti, s).first;
    }
    return &it->second;
}

/* Build the time-domain working window: integer shift from the pristine snapshot,
   optional fractional-delay FIR, optional CFO de-rotation. copy_len = 2*sf_len. */
void UplinkSyncAdapter::shift_copy(const cf_t* pristine, uint32_t nof_samples, uint32_t sf_len,
                                   int off, double cfo_hz, double frac_off,
                                   cf_t* working, uint32_t copy_len)
{
    static thread_local std::vector<cf> tmp;
    tmp.assign(copy_len, cf{});

    // Integer window [off, off+copy_len) with a leading zero-guard for negatives.
    if (off >= 0) {
        uint32_t avail = (off < (int)nof_samples) ? (nof_samples - off) : 0;
        uint32_t n = std::min(copy_len, avail);
        for (uint32_t i = 0; i < n; i++) tmp[i] = reinterpret_cast<const cf*>(pristine)[off + i];
    } else {
        uint32_t sh = (uint32_t)(-off);
        if (sh < copy_len) {
            uint32_t n = std::min(copy_len - sh, nof_samples);
            for (uint32_t i = 0; i < n; i++) tmp[sh + i] = reinterpret_cast<const cf*>(pristine)[i];
        }
    }

    // Fractional-delay via a short windowed-sinc FIR (delay of frac_off samples).
    std::vector<cf>* src = &tmp;
    static thread_local std::vector<cf> fracbuf;
    if (std::fabs(frac_off) > 1e-4) {
        const int L = 21, C = L / 2;          // 21-tap, centered
        float h[21]; float hs = 0;
        for (int n = 0; n < L; n++) {
            double x = (double)(n - C) - frac_off;
            double s = (std::fabs(x) < 1e-8) ? 1.0 : std::sin(M_PI * x) / (M_PI * x);
            double w = 0.5 - 0.5 * std::cos(2.0 * M_PI * n / (L - 1)); // Hann
            h[n] = (float)(s * w); hs += h[n];
        }
        for (int n = 0; n < L; n++) h[n] /= hs;   // unity DC gain
        fracbuf.assign(copy_len, cf{});
        for (uint32_t i = 0; i < copy_len; i++) {
            cf acc(0, 0);
            for (int n = 0; n < L; n++) {
                int idx = (int)i + (n - C);
                if (idx >= 0 && idx < (int)copy_len) acc += h[n] * tmp[idx];
            }
            fracbuf[i] = acc;
        }
        src = &fracbuf;
    }

    // CFO de-rotation: y[n] *= exp(-j 2π f n / fs).
    cf* w = reinterpret_cast<cf*>(working);
    if (std::fabs(cfo_hz) > 1e-6) {
        const double dphi = -2.0 * M_PI * cfo_hz / fs_hz_;
        for (uint32_t i = 0; i < copy_len; i++)
            w[i] = (*src)[i] * cf((float)std::cos(dphi * i), (float)std::sin(dphi * i));
    } else {
        std::memcpy(working, src->data(), copy_len * sizeof(cf_t));
    }
}

/* DMRS least-squares channel estimate on the CURRENT enb_ul->sf_symbols.
   h0/h1 are the per-slot LS estimates over the Msc = L_prb*12 allocated REs. */
bool UplinkSyncAdapter::dmrs_ls(srsran_ul_sf_cfg_t& ul_sf, srsran_ul_cfg_t& ul_cfg,
                                std::vector<cf>& h0, std::vector<cf>& h1)
{
    const uint32_t L_prb = ul_cfg.pusch.grant.L_prb;
    if (L_prb == 0 || L_prb > cell_.nof_prb) return false;
    const uint32_t Msc = L_prb * SRSRAN_NRE;
    const uint32_t sf_idx = ul_sf.tti % SRSRAN_NOF_SF_X_FRAME;

    if (ref_dmrs_.size() < 2 * Msc) ref_dmrs_.resize(2 * Msc);
    if (rx_dmrs_.size()  < 2 * Msc) rx_dmrs_.resize(2 * Msc);

    // Exact reference DMRS for this grant (cyclic shift = grant.n_dmrs), both slots.
    if (srsran_refsignal_dmrs_pusch_gen(&refs_, &dmrs_cfg_, L_prb, sf_idx,
                                        ul_cfg.pusch.grant.n_dmrs, ref_dmrs_.data()) != SRSRAN_SUCCESS)
        return false;
    // Received DMRS extracted from the (post-FFT) symbols.
    srsran_refsignal_dmrs_pusch_get(&refs_, &ul_cfg.pusch, enb_ul_->sf_symbols, rx_dmrs_.data());

    h0.resize(Msc); h1.resize(Msc);
    const cf* R = reinterpret_cast<const cf*>(ref_dmrs_.data());
    const cf* Y = reinterpret_cast<const cf*>(rx_dmrs_.data());
    for (uint32_t k = 0; k < Msc; k++) {
        h0[k] = Y[k]       * std::conj(R[k]);         // slot 0
        h1[k] = Y[Msc + k] * std::conj(R[Msc + k]);   // slot 1
    }
    return true;
}

UplinkSyncAdapter::Probe UplinkSyncAdapter::probe_at(const cf_t* pristine, uint32_t nof_samples, uint32_t sf_len,
                                                     srsran_ul_sf_cfg_t& ul_sf, srsran_ul_cfg_t& ul_cfg,
                                                     int off, double cfo_hz, double frac_off, bool want_chest)
{
    Probe p; p.off = off;
    const uint32_t copy_len = 2 * sf_len;
    const uint32_t headroom = 3 * SRSRAN_SF_LEN_PRB(100);
    if (off >= 0) { if ((uint32_t)off + copy_len > headroom) return p; }
    else          { if ((uint32_t)(-off) > copy_len) return p; }

    shift_copy(pristine, nof_samples, sf_len, off, cfo_hz, frac_off, working_.data(), copy_len);
    // Use the guru enb_ul FFT (not srsran_ofdm_rx_sf_ng): only the guru path
    // applies the rx_window_offset frequency-domain phase compensation, without
    // which a clean burst loses ~ (window_offset_n) samples of phase slope and
    // the channel estimate collapses (measured: 115 dB -> 4.8 dB at high SNR).
    // The guru plan reads the OFDM's bound input buffer, so copy one subframe in.
    memcpy(enb_ul_->in_buffer, working_.data(), sf_len * sizeof(cf_t));
    srsran_enb_ul_fft(enb_ul_);

    if (want_chest) {
        if (srsran_chest_ul_estimate_pusch(&enb_ul_->chest, &ul_sf, &ul_cfg.pusch,
                                           enb_ul_->sf_symbols, &enb_ul_->chest_res) == SRSRAN_SUCCESS) {
            p.chest_snr_db = enb_ul_->chest_res.snr_db;
            p.chest_ta_us  = enb_ul_->chest_res.ta_us;
        }
    }

    std::vector<cf> h0, h1;
    if (!dmrs_ls(ul_sf, ul_cfg, h0, h1)) return p;
    const uint32_t Msc = (uint32_t)h0.size();

    // Per-slot normalized coherent DMRS correlation: |Σ H| / (||Y|| sqrt(Msc)).
    // With unit-modulus reference, ||Y|| == ||H||, so this is in [0,1].
    auto slot_corr = [&](const std::vector<cf>& h) -> double {
        cf sum(0, 0); double e = 0;
        for (uint32_t k = 0; k < Msc; k++) { sum += h[k]; e += std::norm(h[k]); }
        if (e <= 0) return 0;
        return std::abs(sum) / (std::sqrt(e) * std::sqrt((double)Msc));
    };
    p.slot0_corr = slot_corr(h0);
    p.slot1_corr = slot_corr(h1);
    { cf sum(0, 0); double e = 0;
      for (uint32_t k = 0; k < Msc; k++) { sum += h0[k] + h1[k]; e += std::norm(h0[k]) + std::norm(h1[k]); }
      p.norm_corr = (e > 0) ? std::abs(sum) / (std::sqrt(e) * std::sqrt((double)2 * Msc)) : 0;
      p.energy = e; }

    // Fractional timing from the DMRS phase slope (weighted per-subcarrier
    // increment, avoids unwrapping). δ = -slope·Nfft/2π. Averaged over slots.
    auto phase_slope = [&](const std::vector<cf>& h) -> double {
        cf acc(0, 0);
        for (uint32_t k = 1; k < Msc; k++) {
            float w = std::abs(h[k]) * std::abs(h[k - 1]);
            acc += w * (h[k] * std::conj(h[k - 1]));
        }
        return (std::abs(acc) > 0) ? std::arg(acc) : 0.0;   // rad per subcarrier
    };
    double slope = 0.5 * (phase_slope(h0) + phase_slope(h1));
    // Reported as the estimated sub-sample ARRIVAL delay (positive = late). The
    // correction applied downstream is the negation of this (see run()).
    p.frac_off = slope * (double)fft_size_ / (2.0 * M_PI);

    // Residual CFO from slot0->slot1 DMRS phase (Δt = 0.5 ms = one slot).
    { cf acc(0, 0);
      for (uint32_t k = 0; k < Msc; k++) acc += h1[k] * std::conj(h0[k]);
      p.phase_drift_rad = (std::abs(acc) > 0) ? std::arg(acc) : 0.0;
      p.cfo_hz = p.phase_drift_rad / (2.0 * M_PI * 0.5e-3); }

    p.ok = true;
    return p;
}

UplinkSyncResult UplinkSyncAdapter::run(const cf_t* pristine, uint32_t nof_samples, uint32_t sf_len,
                                        srsran_ul_sf_cfg_t& ul_sf, srsran_ul_cfg_t& ul_cfg)
{
    UplinkSyncResult r;
    if (!configured_) { r.invalid_reason = "not configured"; return r; }

    // TA prior expressed in monitor samples (prior only; never the final offset).
    double ta_prior_s = 0.0;
    if (cfg_.ta_known) { ta_prior_s = cfg_.network_ta_seconds * fs_hz_; r.ta_prior_samples = ta_prior_s; }
    const int center = cfg_.ta_known ? (int)llround(ta_prior_s) : 0;

    // ---- Nominal reference probe (window offset 0) ----
    Probe nom = probe_at(pristine, nof_samples, sf_len, ul_sf, ul_cfg, 0, 0, 0, true);
    r.nominal_chest_snr_db = nom.chest_snr_db;

    if (cfg_.timing_mode == TimingMode::NOMINAL) {
        // Regression / A-B baseline: leave nominal symbols in place, no correction.
        r.integer_offset_samples = 0;
        r.normalized_correlation  = nom.norm_corr;
        r.slot0_correlation = nom.slot0_corr; r.slot1_correlation = nom.slot1_corr;
        r.chest_snr_db = nom.chest_snr_db;
        r.timing_source = TimingSource::NOMINAL;
        r.timing_class  = TimingClass::PLAUSIBLE;
        r.valid = true; r.confidence = 0.5; r.corrected_iq_available = true;
        return r;
    }

    // ---- Stage 1: coarse acquisition over ±range around the center ----
    // Timing metric = srsRAN chest SNR (dB). Unlike a raw coherent DMRS
    // correlation, the chest internally estimates and removes the timing phase
    // slope, so it stays high for arrivals BETWEEN grid points — a coherent
    // correlation decorrelates within a few samples and misses them.
    std::vector<std::pair<double,int>> snr_by_off;    // (snr_db, off)
    snr_by_off.reserve(2 * cfg_.search_range / cfg_.coarse_step + 2);
    for (int off = center - cfg_.search_range; off <= center + cfg_.search_range; off += cfg_.coarse_step) {
        Probe p = probe_at(pristine, nof_samples, sf_len, ul_sf, ul_cfg, off, 0, 0, true);
        if (p.ok && std::isfinite(p.chest_snr_db)) snr_by_off.emplace_back(p.chest_snr_db, off);
    }
    if (snr_by_off.empty()) { r.invalid_reason = "no DMRS candidate"; return r; }

    // Background = median coarse SNR (dB); peak ratios expressed as linear power.
    std::vector<double> snrs; snrs.reserve(snr_by_off.size());
    for (auto& c : snr_by_off) snrs.push_back(c.first);
    std::vector<double> sorted = snrs;
    std::nth_element(sorted.begin(), sorted.begin() + sorted.size() / 2, sorted.end());
    double bg_db = sorted[sorted.size() / 2];

    std::sort(snr_by_off.begin(), snr_by_off.end(),
              [](const std::pair<double,int>& a, const std::pair<double,int>& b){ return a.first > b.first; });
    double peak_db  = snr_by_off[0].first;
    int    peak_off = snr_by_off[0].second;
    double second_db = -1e9;
    for (auto& c : snr_by_off) {
        if (std::abs(c.second - peak_off) > 2 * cfg_.coarse_step) { second_db = c.first; break; }
    }
    r.peak_to_background  = std::pow(10.0, (peak_db - bg_db) / 10.0);
    r.peak_to_second_peak = (second_db > -1e8) ? std::pow(10.0, (peak_db - second_db) / 10.0) : 99.0;

    int ncand = std::min((int)snr_by_off.size(), cfg_.max_candidates);

    // ---- Stage 2: fine integer refinement (±fine_range @ 1 sample) around candidates ----
    Probe best; best.chest_snr_db = -1e9; bool best_set = false;
    for (int i = 0; i < ncand; i++) {
        int c = snr_by_off[i].second;
        for (int off = c - cfg_.fine_range; off <= c + cfg_.fine_range; off++) {
            Probe p = probe_at(pristine, nof_samples, sf_len, ul_sf, ul_cfg, off, 0, 0, true);
            if (p.ok && std::isfinite(p.chest_snr_db) && p.chest_snr_db > best.chest_snr_db) { best = p; best_set = true; }
        }
    }
    if (!best_set) { r.invalid_reason = "no DMRS candidate"; return r; }

    // Re-probe the winner for stable final metrics (norm_corr, slot corr, frac, cfo).
    best = probe_at(pristine, nof_samples, sf_len, ul_sf, ul_cfg, best.off, 0, 0, true);

    r.integer_offset_samples = best.off;
    r.normalized_correlation = best.norm_corr;
    r.slot0_correlation = best.slot0_corr;
    r.slot1_correlation = best.slot1_corr;
    r.chest_snr_db      = best.chest_snr_db;

    // Slot timing difference: the per-slot fractional-delay estimates should
    // agree (both slots see the same arrival; a large gap => noise / ambiguity).
    r.slot_timing_difference_samples = 0.0;
    {
        std::vector<cf> h0, h1;
        // best probe already left symbols in enb_ul->sf_symbols; recompute LS.
        if (dmrs_ls(ul_sf, ul_cfg, h0, h1)) {
            auto slope1 = [&](const std::vector<cf>& h){ cf acc(0,0);
                for (size_t k=1;k<h.size();k++){ float w=std::abs(h[k])*std::abs(h[k-1]); acc += w*(h[k]*std::conj(h[k-1])); }
                return (std::abs(acc)>0)? std::arg(acc):0.0; };
            double d0 = -slope1(h0) * (double)fft_size_ / (2.0*M_PI);
            double d1 = -slope1(h1) * (double)fft_size_ / (2.0*M_PI);
            r.slot_timing_difference_samples = std::fabs(d0 - d1);
        }
    }

    // ---- Stage 3/4: fractional timing + residual CFO ----
    double frac = 0, cfo = 0;
    if (cfg_.timing_mode == TimingMode::INTEGER_FRAC || cfg_.timing_mode == TimingMode::FULL)
        frac = best.frac_off;
    if (cfg_.timing_mode == TimingMode::FULL && cfg_.cfo_mode == CfoMode::PER_SUBFRAME)
        cfo = best.cfo_hz - cfg_.nominal_cfo_hz;
    r.fractional_offset_samples = frac;
    r.residual_cfo_hz           = cfo;
    r.dmrs_phase_drift_rad      = best.phase_drift_rad;

    // ---- Stage 9: confidence + classification ----
    // Confidence blends normalized correlation, peak distinctness and slot
    // agreement into 0..1. Deliberately conservative at low correlation.
    double c_corr = std::min(1.0, best.norm_corr / 0.6);
    double c_bg   = std::min(1.0, (r.peak_to_background - 1.0) / 1.0);
    double c_2nd  = std::min(1.0, (r.peak_to_second_peak - 1.0) / 0.5);
    double c_slot = (r.slot_timing_difference_samples < cfg_.max_slot_disagree) ? 1.0 : 0.0;
    r.confidence = std::max(0.0, 0.4 * c_corr + 0.25 * c_bg + 0.2 * c_2nd + 0.15 * c_slot);

    // Rejection ladder (spec Part 9): produce an explicit reason.
    r.timing_source = TimingSource::WAVEFORM;
    if (!std::isfinite(best.norm_corr))                        { r.invalid_reason = "non-finite metric"; r.timing_class = TimingClass::INVALID; }
    else if (std::abs(best.off - center) > cfg_.max_plausible_offset) { r.invalid_reason = "implausible offset"; r.timing_class = TimingClass::INVALID; }
    else if (best.norm_corr < cfg_.min_norm_corr)             { r.invalid_reason = "weak normalized correlation"; r.timing_class = TimingClass::NOISE_PEAK; }
    else if (r.peak_to_background < cfg_.min_peak_to_bg)      { r.invalid_reason = "unvalidated noise peak"; r.timing_class = TimingClass::NOISE_PEAK; }
    else if (r.peak_to_second_peak < cfg_.min_peak_to_2nd)   { r.invalid_reason = "ambiguous peaks"; r.timing_class = TimingClass::NOISE_PEAK; }
    else if (r.slot_timing_difference_samples > cfg_.max_slot_disagree) { r.invalid_reason = "slot disagreement"; r.timing_class = TimingClass::PLAUSIBLE; }
    else                                                      { r.timing_class = TimingClass::PLAUSIBLE; }

    // ---- Per-UE state: update ONLY from confident observations ----
    if (r.timing_class == TimingClass::PLAUSIBLE && r.confidence >= 0.5f) {
        UeUplinkTimingState* st = ue_state(ul_cfg.pusch.rnti);
        double a = cfg_.ue_state_alpha;
        if (!st->initialized) {
            st->filtered_integer_offset    = best.off;
            st->filtered_fractional_offset = frac;
            st->filtered_cfo_hz            = cfo;
            st->initialized = true;
        } else {
            st->filtered_integer_offset    = (1-a)*st->filtered_integer_offset    + a*best.off;
            st->filtered_fractional_offset = (1-a)*st->filtered_fractional_offset + a*frac;
            st->filtered_cfo_hz            = (1-a)*st->filtered_cfo_hz            + a*cfo;
        }
        st->last_tti = ul_sf.tti;
        st->confident_observations++;
    }

    // ---- Emit corrected symbols for the chosen estimate ----
    if (r.timing_class == TimingClass::PLAUSIBLE || r.timing_class == TimingClass::VALIDATED) {
        // Corrections: integer window = absolute best.off; fractional = advance by
        // the estimated arrival delay (-frac); CFO = de-rotate the arrival CFO.
        synthesize_corrected_symbols(pristine, nof_samples, sf_len, best.off, -frac, cfo);
        r.corrected_iq_available = true;
        r.valid = true;
    } else {
        // Rejected: restore nominal symbols so the caller's decode is unchanged.
        probe_at(pristine, nof_samples, sf_len, ul_sf, ul_cfg, 0, 0, 0, false);
        r.corrected_iq_available = false;
        r.valid = false;
    }
    return r;
}

bool UplinkSyncAdapter::synthesize_corrected_symbols(const cf_t* pristine, uint32_t nof_samples, uint32_t sf_len,
                                                     int integer_off, double frac_off, double cfo_hz)
{
    const uint32_t copy_len = 2 * sf_len;
    const uint32_t headroom = 3 * SRSRAN_SF_LEN_PRB(100);
    if (integer_off >= 0) { if ((uint32_t)integer_off + copy_len > headroom) return false; }
    else                  { if ((uint32_t)(-integer_off) > copy_len) return false; }
    shift_copy(pristine, nof_samples, sf_len, integer_off, cfo_hz, frac_off, working_.data(), copy_len);
    memcpy(enb_ul_->in_buffer, working_.data(), sf_len * sizeof(cf_t));  // guru FFT input (see probe_at)
    srsran_enb_ul_fft(enb_ul_);
    return true;
}
