/* UlDenseDecoder — calibrated-window uplink PUSCH decode. See UlDenseDecoder.h
 * and docs/UlDenseDecoder.md. From-scratch path; does not touch PUSCH_Decoder.
 */
#include "include/UlDenseDecoder.h"

#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <numeric>
#include <mutex>
#include <vector>

// ---- global per-UE UL accounting (shared across worker threads) ------------
// grants = UL DCI-0 assignments the eNB scheduled for this C-RNTI that we tried;
// decoded = how many we actually recovered a valid MAC PDU from. Dumped
// periodically as [DENSE2-UESTATS]/[DENSE2-UE] so we can measure decode yield
// per UE and see which UEs we can't decode (and, via maxE/mcs, why).
namespace {
struct UeUlStat { uint32_t grants = 0, decoded = 0; float max_e = -99.0f; int mcs = -1; };
std::mutex g_ue_mtx;
std::unordered_map<uint16_t, UeUlStat> g_ue_stats;

void dump_ue_stats() {
    std::lock_guard<std::mutex> lk(g_ue_mtx);
    uint64_t tg = 0, td = 0; int dec_ues = 0;
    std::vector<std::pair<uint16_t, UeUlStat>> decoded, undec;
    for (auto& kv : g_ue_stats) {
        tg += kv.second.grants; td += kv.second.decoded;
        if (kv.second.decoded > 0) { dec_ues++; decoded.push_back(kv); }
        else undec.push_back(kv);
    }
    printf("[DENSE2-UESTATS] UEs=%zu decoded_UEs=%d undecoded_UEs=%zu | grants=%llu decoded_frames=%llu rate=%.2f%%\n",
           g_ue_stats.size(), dec_ues, undec.size(),
           (unsigned long long)tg, (unsigned long long)td, tg ? 100.0 * td / tg : 0.0);
    std::sort(decoded.begin(), decoded.end(),
              [](const std::pair<uint16_t, UeUlStat>& a, const std::pair<uint16_t, UeUlStat>& b)
              { return a.second.decoded > b.second.decoded; });
    for (auto& kv : decoded)
        printf("[DENSE2-UE] rnti=0x%04x grants=%u decoded=%u (%.0f%%) maxE=%.1fdB mcs=%d\n",
               kv.first, kv.second.grants, kv.second.decoded,
               100.0 * kv.second.decoded / kv.second.grants, kv.second.max_e, kv.second.mcs);
    // undecoded UEs: summarize why (energy distribution)
    int weak = 0, midE = 0, strong = 0;
    for (auto& kv : undec) {
        if (kv.second.max_e < 4) weak++; else if (kv.second.max_e < 8) midE++; else strong++;
    }
    printf("[DENSE2-UESTATS] undecoded-UE energy: <4dB(weak)=%d 4-8dB=%d >=8dB=%d\n", weak, midE, strong);
}
} // namespace

#ifdef __cplusplus
extern "C" {
#endif
#include "srsran/phy/utils/vector.h"
#include "srsran/phy/dft/ofdm.h"
#include "srsran/phy/ch_estimation/chest_ul.h"
#include "srsran/phy/phch/pusch.h"
#ifdef __cplusplus
}
#undef I
#endif

// ---- small env helpers -----------------------------------------------------
static int   env_int  (const char* k, int   d) { const char* e = getenv(k); return e ? atoi(e) : d; }
static float env_float(const char* k, float d) { const char* e = getenv(k); return e ? (float)atof(e) : d; }

bool UlDenseDecoder::enabled()
{
    static const bool on = (getenv("UL_DENSE2") != nullptr);
    return on;
}

UlDenseDecoder::UlDenseDecoder(srsran_enb_ul_t   &enb_ul,
                               srsran_ul_sf_cfg_t &ul_sf,
                               srsran_ul_cfg_t    &ul_cfg,
                               ULSchedule         *ulsche,
                               cf_t              **original_buffer,
                               cf_t              **scratch_buffer,
                               LTESniffer_pcap_writer *pcapwriter,
                               MCSTracking        *mcstracking)
    : enb_ul_(enb_ul), ul_sf_(ul_sf), ul_cfg_(ul_cfg), ulsche_(ulsche),
      original_buffer_(original_buffer), scratch_buffer_(scratch_buffer),
      pcapwriter_(pcapwriter), mcstracking_(mcstracking)
{
    pusch_res_.data = srsran_vec_u8_malloc(2000 * 8);
    own_sb_ = new srsran_softbuffer_rx_t;
    srsran_softbuffer_rx_init(own_sb_, SRSRAN_MAX_PRB);
    nominal_sym_len_ = SRSRAN_SF_LEN_RE(110, SRSRAN_CP_NORM);
    nominal_sym_ = srsran_vec_cf_malloc(nominal_sym_len_);
    sf_sym_ant1_ = srsran_vec_cf_malloc(nominal_sym_len_);
    ce0_         = srsran_vec_cf_malloc(nominal_sym_len_);
    mrc_dry_data_ = srsran_vec_u8_malloc(2000 * 8);
    mrc_dry_sb_   = new srsran_softbuffer_rx_t;
    srsran_softbuffer_rx_init(mrc_dry_sb_, SRSRAN_MAX_PRB);
    mrc_on_      = (getenv("UL_DENSE2_MRC") != nullptr);
    read_env_once();
}

UlDenseDecoder::~UlDenseDecoder()
{
    if (pusch_res_.data) free(pusch_res_.data);
    if (nominal_sym_) free(nominal_sym_);
    if (sf_sym_ant1_) free(sf_sym_ant1_);
    if (ce0_) free(ce0_);
    if (mrc_dry_data_) free(mrc_dry_data_);
    if (mrc_dry_sb_) { srsran_softbuffer_rx_free(mrc_dry_sb_); delete mrc_dry_sb_; }
    if (own_sb_) { srsran_softbuffer_rx_free(own_sb_); delete own_sb_; }
    for (auto& kv : harq_buffers_) { srsran_softbuffer_rx_free(kv.second); delete kv.second; }
}

// Persistent rx softbuffer for this UE's HARQ process; reset only on a new TX.
srsran_softbuffer_rx_t* UlDenseDecoder::harq_get(uint16_t rnti, uint32_t pid, bool is_new_tx)
{
    uint64_t key = ((uint64_t)rnti << 8) | (pid & 0xff);
    auto it = harq_buffers_.find(key);
    srsran_softbuffer_rx_t* sb;
    if (it == harq_buffers_.end()) {
        if (harq_buffers_.size() > 512) {   // bound memory: evict an arbitrary entry
            auto v = harq_buffers_.begin();
            srsran_softbuffer_rx_free(v->second); delete v->second; harq_buffers_.erase(v);
        }
        sb = new srsran_softbuffer_rx_t;
        srsran_softbuffer_rx_init(sb, SRSRAN_MAX_PRB);
        harq_buffers_[key] = sb;
    } else {
        sb = it->second;
    }
    if (is_new_tx) srsran_softbuffer_rx_reset(sb);
    return sb;
}

void UlDenseDecoder::read_env_once()
{
    if (cfg_read_) return;
    cfg_read_ = true;
    min_energy_db_ = env_float("UL_DENSE2_MINDB",    3.0f);
    boot_gate_db_  = env_float("UL_DENSE2_BOOTDB",   8.0f);
    pos_guard_     = env_int  ("UL_DENSE2_POSGUARD", 120);
    boot_range_    = env_int  ("UL_DENSE2_BOOT",     900);
    fine_range_    = env_int  ("UL_DENSE2_FINE",     150);
    fine_step_     = std::max(1, env_int("UL_DENSE2_FINE_STEP", 6));
    lock_snr_db_   = env_float("UL_DENSE2_LOCKDB",   6.0f);
    if (const char* e = getenv("UL_DENSE2_HARQ")) harq_on_ = (atoi(e) != 0);
    if (const char* e = getenv("UL_DENSE2_CAL")) { forced_c_ = atoi(e); c_seeded_ = true; c_fixed_ = forced_c_; }
    printf("[DENSE2] enabled: min_energy=%.1fdB boot=+-%d fine=+-%d/%d lockdb=%.1f cal=%s\n",
           min_energy_db_, boot_range_, fine_range_, fine_step_, lock_snr_db_,
           forced_c_ == INT32_MIN ? "auto" : std::to_string(forced_c_).c_str());
}

void UlDenseDecoder::init(std::vector<DCI_UL> dci_ul,
                          std::vector<DCI_UL> rar_dci_ul,
                          srsran_ul_sf_cfg_t &ul_sf,
                          SubframePower *sf_power)
{
    dci_ul_     = std::move(dci_ul);
    rar_dci_ul_ = std::move(rar_dci_ul);
    ul_sf_      = ul_sf;
    sf_power_   = sf_power;
}

// ---- window mechanics ------------------------------------------------------
void UlDenseDecoder::snapshot_raw()
{
    // Clean pre-FFT copy of the UL samples; every offset re-FFTs from this.
    // The primary UL decoder is fed sf_buffer_b[0] (radio B, antenna 0 = UL) —
    // enb_ul was srsran_enb_ul_init'd on sf_buffer_b[0] — so the raw UL samples
    // live in original_buffer_[0], NOT [1] (which is radio B's 2nd antenna, only
    // present in 2-RX UL_DIVERSITY mode).
    const uint32_t snap_len = 3 * SRSRAN_SF_LEN_PRB(100);
    memcpy(scratch_buffer_[0], original_buffer_[0], sizeof(cf_t) * snap_len);
}

bool UlDenseDecoder::fft_at_offset(int sample_offset)
{
    const uint32_t sf_len   = SRSRAN_SF_LEN_PRB(enb_ul_.cell.nof_prb);
    const uint32_t copy_len = 2 * sf_len;
    const uint32_t headroom = 3 * SRSRAN_SF_LEN_PRB(100);
    if (sample_offset >= 0) {
        if ((uint32_t)sample_offset + copy_len > headroom) return false;
    } else {
        if ((uint32_t)(-sample_offset) > copy_len) return false;
    }
    cf_t* snap    = scratch_buffer_[0];
    cf_t* working = scratch_buffer_[1];
    srsran_vec_cf_zero(working, copy_len);
    if (sample_offset >= 0) {
        memcpy(working, snap + sample_offset, sizeof(cf_t) * copy_len);
    } else {
        uint32_t shift = (uint32_t)(-sample_offset);
        memcpy(working + shift, snap, sizeof(cf_t) * (copy_len - shift));
    }
    srsran_ofdm_rx_sf_ng(&enb_ul_.fft, working, enb_ul_.sf_symbols);
    return true;
}

float UlDenseDecoder::chest_snr_at(int sample_offset, srsran_pusch_cfg_t &pusch)
{
    if (!fft_at_offset(sample_offset)) return -1e9f;
    if (srsran_chest_ul_estimate_pusch(&enb_ul_.chest, &ul_sf_, &pusch,
                                       enb_ul_.sf_symbols, &enb_ul_.chest_res) != SRSRAN_SUCCESS)
        return -1e9f;
    float s = enb_ul_.chest_res.snr_db;
    return std::isfinite(s) ? s : -1e9f;
}

// ---- grant -> config (standard MCS table only, v1) -------------------------
bool UlDenseDecoder::build_pusch_cfg(DCI_UL &g, srsran_pusch_cfg_t &pusch)
{
    if (g.rnti == 0 || g.ran_ul_grant == nullptr) return false;
    if (g.ran_ul_grant->tb.tbs <= 0) return false;
    uint32_t L = g.ran_ul_grant->L_prb;
    if (L == 0 || L > 100) return false;
    if (g.ran_ul_grant->tb.mcs_idx > 20) return false;   // v1: leave 64/256QAM to legacy

    pusch.rnti          = g.rnti;
    pusch.enable_64qam  = false;
    pusch.meas_ta_en    = true;
    pusch.grant         = *g.ran_ul_grant;
    pusch.uci_cfg.ack[0].nof_acks = g.nof_ack;
    // No aperiodic CSI handling in v1 — data-only PUSCH.
    pusch.uci_cfg.cqi.data_enable = false;
    pusch.uci_cfg.cqi.ri_len      = 0;
    if (pusch.uci_offset.I_offset_cqi < 2 || pusch.uci_offset.I_offset_cqi > 15)
        pusch.uci_offset.I_offset_cqi = 8;
    pusch.softbuffers.rx = own_sb_;
    return true;
}

// ---- chest-free allocated-RB energy over the noise floor (dB) ---------------
float UlDenseDecoder::grant_energy_db(DCI_UL &g)
{
    if (!sf_power_ || g.ran_ul_grant == nullptr) return -100.0f;
    const auto& rbpow = sf_power_->getRBPowerUL();
    uint32_t np = g.ran_ul_grant->n_prb[0], L = g.ran_ul_grant->L_prb;
    if (L == 0 || rbpow.size() < (size_t)np + L) return -100.0f;
    float p_alloc = 0.0f;
    for (uint32_t k = 0; k < L; k++) p_alloc += rbpow[np + k];
    p_alloc /= (float)L;
    std::vector<float> tmp(rbpow.begin(), rbpow.end());
    size_t p10 = tmp.size() / 10;
    std::nth_element(tmp.begin(), tmp.begin() + p10, tmp.end());
    return p_alloc - tmp[p10];
}

// ---- PUSCH turbo decode of whatever is in sf_symbols + chest_res.ce, plus the
//      false-positive guards and pcap write. Chest must already be done. --------
bool UlDenseDecoder::decode_tb(DCI_UL &g, srsran_pusch_cfg_t &pusch)
{
    pusch_res_.crc = false;
    if (srsran_pusch_decode(&enb_ul_.pusch, &ul_sf_, &pusch, &enb_ul_.chest_res,
                            enb_ul_.sf_symbols, &pusch_res_) != SRSRAN_SUCCESS)
        return false;

    // Reject all-zero transport blocks (turbo-on-noise false positives): CRC-24
    // of all-zeros passes, but a real MAC PDU is never all-zero. Same guard the
    // legacy path uses.
    if (pusch_res_.crc && pusch.grant.tb.tbs > 0) {
        const int nbytes = pusch.grant.tb.tbs / 8;
        bool all_zero = true;
        for (int b = 0; b < nbytes; b++) { if (pusch_res_.data[b] != 0) { all_zero = false; break; } }
        if (all_zero) pusch_res_.crc = false;
    }

    // Reject structurally-invalid MAC PDUs — the non-zero turbo-on-noise false
    // positives the all-zero guard misses (e.g. the "malformed CCCH 26307 bytes,
    // reserved bit not zero" garbage). A real UL-SCH subheader has both reserved
    // bits = 0 and a valid LCID: 0 (CCCH), 1-10 (DCCH/DTCH), 24-31 (control/pad);
    // 11-23 are reserved. Real frames (DCCH data, BSR, CCCH) all pass this.
    if (pusch_res_.crc && pusch.grant.tb.tbs >= 8) {
        uint8_t b0 = pusch_res_.data[0];
        int lcid = b0 & 0x1F;
        if ((b0 & 0xC0) != 0 || (lcid >= 11 && lcid <= 23))
            pusch_res_.crc = false;
    }

    if (pusch_res_.crc && pusch.grant.tb.tbs > 0) {
        int length = pusch.grant.tb.tbs / 8;
        pcapwriter_->write_ul_crnti(pusch_res_.data, length, pusch.rnti, ul_sf_.tti);
        return true;
    }
    return false;
}

// ---- single-antenna decode of whatever is in sf_symbols --------------------
bool UlDenseDecoder::decode_current(DCI_UL &g, srsran_pusch_cfg_t &pusch)
{
    // On a HARQ retransmission we must NOT reset — prior soft bits must remain so
    // this decode accumulates onto them. harq_no_reset_ is set by the caller.
    if (!harq_no_reset_)
        srsran_softbuffer_rx_reset_tbs(pusch.softbuffers.rx, pusch.grant.tb.tbs);
    if (srsran_chest_ul_estimate_pusch(&enb_ul_.chest, &ul_sf_, &pusch,
                                       enb_ul_.sf_symbols, &enb_ul_.chest_res) != SRSRAN_SUCCESS)
        return false;
    return decode_tb(g, pusch);
}

// ---- 2-RX maximal-ratio combine at the nominal window, then decode ---------
// Estimates the channel on each antenna (ant0 = nominal_sym_, ant1 = sf_sym_ant1_),
// then builds the "equivalent single antenna": ce_eff = sqrt(|h0|^2+|h1|^2),
// y_eff = (conj(h0)*y0 + conj(h1)*y1)/ce_eff. Feeding (y_eff, ce_eff) to the
// single-antenna equalizer inside srsran_pusch_decode yields the exact MRC output
// x = (conj(h0)y0+conj(h1)y1)/(|h0|^2+|h1|^2+noise). Falls back to ant0-only if
// ant1's estimate is unusable, so it can never do worse than single-antenna.
bool UlDenseDecoder::mrc_decode(DCI_UL &g, srsran_pusch_cfg_t &pusch)
{
    if (!harq_no_reset_)
        srsran_softbuffer_rx_reset_tbs(pusch.softbuffers.rx, pusch.grant.tb.tbs);

    const uint32_t N = nominal_sym_len_;
    // ant0 channel estimate
    memcpy(enb_ul_.sf_symbols, nominal_sym_, sizeof(cf_t) * N);
    if (srsran_chest_ul_estimate_pusch(&enb_ul_.chest, &ul_sf_, &pusch,
                                       enb_ul_.sf_symbols, &enb_ul_.chest_res) != SRSRAN_SUCCESS)
        return false;
    memcpy(ce0_, enb_ul_.chest_res.ce, sizeof(cf_t) * N);
    float noise0  = enb_ul_.chest_res.noise_estimate;
    float snr0_db = enb_ul_.chest_res.snr_db;

    // A/B (env UL_DENSE2_MRC_DIAG): does ant0 ALONE decode this grant? Dry decode
    // on the current (ant0) symbols + chest with a scratch softbuffer — no HARQ
    // touch, no pcap. Counts grants MRC recovers that ant0 alone cannot = the real,
    // decode-level MRC benefit (traffic-independent, immune to interference-corr.).
    static const bool mrc_diag = (getenv("UL_DENSE2_MRC_DIAG") != nullptr);
    bool crc0_ab = false;
    if (mrc_diag) {
        srsran_softbuffer_rx_reset_tbs(mrc_dry_sb_, pusch.grant.tb.tbs);
        srsran_softbuffer_rx_t* sv = pusch.softbuffers.rx;
        pusch.softbuffers.rx = mrc_dry_sb_;
        srsran_pusch_res_t dr; memset(&dr, 0, sizeof(dr)); dr.data = mrc_dry_data_;
        if (srsran_pusch_decode(&enb_ul_.pusch, &ul_sf_, &pusch, &enb_ul_.chest_res,
                                enb_ul_.sf_symbols, &dr) == SRSRAN_SUCCESS && dr.crc &&
            pusch.grant.tb.tbs >= 8) {
            int nb = pusch.grant.tb.tbs / 8; bool az = true;
            for (int b = 0; b < nb; b++) if (dr.data[b]) { az = false; break; }
            uint8_t b0 = dr.data[0]; int lc = b0 & 0x1F;
            crc0_ab = !az && (b0 & 0xC0) == 0 && !(lc >= 11 && lc <= 23);
        }
        pusch.softbuffers.rx = sv;
    }

    // ant1 channel estimate (leaves ce in chest_res.ce)
    memcpy(enb_ul_.sf_symbols, sf_sym_ant1_, sizeof(cf_t) * N);
    if (srsran_chest_ul_estimate_pusch(&enb_ul_.chest, &ul_sf_, &pusch,
                                       enb_ul_.sf_symbols, &enb_ul_.chest_res) != SRSRAN_SUCCESS) {
        // ant1 bad -> plain ant0 decode
        memcpy(enb_ul_.sf_symbols, nominal_sym_, sizeof(cf_t) * N);
        memcpy(enb_ul_.chest_res.ce, ce0_, sizeof(cf_t) * N);
        enb_ul_.chest_res.noise_estimate = noise0;
        return decode_tb(g, pusch);
    }

    float snr1_db = enb_ul_.chest_res.snr_db;
    // MRC gain diagnostic: theoretical MRC SNR ~ 10log10(lin(snr0)+lin(snr1)).
    if (mrc_diag && std::isfinite(snr0_db) && std::isfinite(snr1_db) && snr0_db > -20 && snr0_db < 40) {
        float mrc_snr = 10.0f * log10f(powf(10.f, snr0_db/10) + powf(10.f, snr1_db/10));
        float gain = mrc_snr - snr0_db;
        static std::atomic<uint64_t> mn{0};
        static std::atomic<long long> gsum{0}, s0s{0}, s1s{0};
        uint64_t k = mn.fetch_add(1) + 1;
        gsum.fetch_add((long long)lroundf(gain*1000));
        s0s.fetch_add((long long)lroundf(snr0_db*1000));
        s1s.fetch_add((long long)lroundf(snr1_db*1000));
        if (k <= 40 || k % 50 == 0)
            printf("[DENSE2-MRC] ant0=%.1f ant1=%.1f mrc=%.1f gain=%+.1f dB | mean: ant0=%.2f ant1=%.2f gain=%+.2f (n=%llu)\n",
                   snr0_db, snr1_db, mrc_snr, gain, s0s.load()/1000.0/k, s1s.load()/1000.0/k,
                   gsum.load()/1000.0/k, (unsigned long long)k);
    }

    cf_t* ce1 = enb_ul_.chest_res.ce;   // ant1 channel (== chest_res.ce; combined in place below)
    cf_t* out = enb_ul_.sf_symbols;     // write y_eff here
    for (uint32_t k = 0; k < N; k++) {
        float h0r = __real__ (ce0_[k]), h0i = __imag__ (ce0_[k]);
        float h1r = __real__ (ce1[k]),  h1i = __imag__ (ce1[k]);
        float m   = h0r*h0r + h0i*h0i + h1r*h1r + h1i*h1i;   // |h0|^2 + |h1|^2
        if (m > 1e-12f) {
            float mag = sqrtf(m);
            float y0r = __real__ (nominal_sym_[k]), y0i = __imag__ (nominal_sym_[k]);
            float y1r = __real__ (sf_sym_ant1_[k]), y1i = __imag__ (sf_sym_ant1_[k]);
            // conj(h)*y = (hr - j hi)(yr + j yi) = (hr yr + hi yi) + j(hr yi - hi yr)
            float nr = (h0r*y0r + h0i*y0i) + (h1r*y1r + h1i*y1i);
            float ni = (h0r*y0i - h0i*y0r) + (h1r*y1i - h1i*y1r);
            cf_t ye; __real__ ye = nr / mag; __imag__ ye = ni / mag;
            out[k] = ye;
            cf_t ceff; __real__ ceff = mag; __imag__ ceff = 0.0f;
            ce1[k] = ceff;   // ce_eff (real) into chest_res.ce
        } else {
            cf_t z; __real__ z = 0.0f; __imag__ z = 0.0f;
            out[k] = z; ce1[k] = z;
        }
    }
    enb_ul_.chest_res.noise_estimate = noise0;   // MRC preserves per-antenna noise variance
    bool crc = decode_tb(g, pusch);
    if (mrc_diag) {
        static std::atomic<uint64_t> rec{0}, lost{0}, both{0};
        if (crc && !crc0_ab) {
            uint64_t r = rec.fetch_add(1) + 1;
            printf("[DENSE2-MRC-AB] MRC recovered a grant ant0 could NOT (rnti=0x%04x mcs=%d) "
                   "| mrc_only=%llu ant0_only=%llu both=%llu\n",
                   g.rnti, g.ran_ul_grant->tb.mcs_idx, (unsigned long long)r,
                   (unsigned long long)lost.load(), (unsigned long long)both.load());
        } else if (!crc && crc0_ab) lost.fetch_add(1);   // regression — should stay ~0
        else if (crc && crc0_ab)    both.fetch_add(1);
    }
    return crc;
}

// ---- calibration state -----------------------------------------------------
int UlDenseDecoder::window_origin(uint16_t rnti)
{
    int c = (forced_c_ != INT32_MIN) ? forced_c_ : (c_seeded_ ? c_fixed_ : 0);
    auto it = delta_ue_.find(rnti);
    if (it != delta_ue_.end()) c += (int)lroundf(it->second);
    return c;
}

void UlDenseDecoder::observe_lock(uint16_t rnti, int off, float snr, bool distinct)
{
    if (snr < lock_snr_db_ || !distinct) return;
    if (forced_c_ == INT32_MIN) {
        c_samples_.push_back(off);
        if (c_samples_.size() > 64) c_samples_.pop_front();
        std::vector<int> v(c_samples_.begin(), c_samples_.end());
        std::nth_element(v.begin(), v.begin() + v.size() / 2, v.end());
        c_fixed_ = v[v.size() / 2];                 // robust running median
        if (c_samples_.size() >= 8) c_seeded_ = true;
    }
    // Per-UE geometric residual = lock offset minus the shared fixed term.
    float resid = (float)(off - c_fixed_);
    resid = std::max((float)-fine_range_, std::min((float)fine_range_, resid));
    float& d = delta_ue_[rnti];
    d = delta_ue_.count(rnti) && d != 0.0f ? 0.7f * d + 0.3f * resid : resid;
}

// ---- per-subframe decode ---------------------------------------------------
void UlDenseDecoder::decode()
{
    snapshot_raw();

    // Populate per-RB UL power for the energy gate. The legacy path gets this from
    // sf_power->computePower() right after its nominal FFT; in dense mode we run
    // the FFT ourselves, so compute it here from the nominal-window symbols.
    // GURU nominal FFT — MUST match the legacy path. srsran_ofdm_rx_sf_ng (used by
    // fft_at_offset for the shifted windows) omits the rx_window_offset phase
    // compensation and loses several dB of chest SNR vs srsran_enb_ul_fft; at our
    // marginal SNR that is the difference between decode and no-decode (an
    // ofdm_rx_sf_ng-only decoder got 0 frames where the guru legacy path got 16).
    // enb_ul_fft consumes in_buffer (== original_buffer_[0]) in place, but
    // snapshot_raw() above already saved the pristine samples for the search.
    enb_ul_.in_buffer = original_buffer_[0];
    srsran_enb_ul_fft(&enb_ul_);
    if (sf_power_) sf_power_->computePower(enb_ul_.sf_symbols);
    memcpy(nominal_sym_, enb_ul_.sf_symbols, sizeof(cf_t) * nominal_sym_len_);
    // 2-RX MRC: FFT the 2nd UL antenna at the nominal window too (needs rf_b opened
    // with 2 channels). ant1 samples in original_buffer_[1]; enb_ul_fft consumes it
    // in place but it is not used elsewhere. The window search stays single-antenna.
    if (mrc_on_) {
        enb_ul_.in_buffer = original_buffer_[1];
        srsran_enb_ul_fft(&enb_ul_);
        memcpy(sf_sym_ant1_, enb_ul_.sf_symbols, sizeof(cf_t) * nominal_sym_len_);
        enb_ul_.in_buffer = original_buffer_[0];
    }

    std::vector<DCI_UL> grants = dci_ul_;
    grants.insert(grants.end(), rar_dci_ul_.begin(), rar_dci_ul_.end());

    static std::atomic<uint64_t> g_calls{0}, g_raw{0}, g_seen{0}, g_gated{0}, g_crc{0};
    g_calls.fetch_add(1, std::memory_order_relaxed);
    g_raw.fetch_add(grants.size(), std::memory_order_relaxed);
    // Periodic heartbeat so grant-flow is visible even when nothing clears the gate.
    if (g_calls.load() % 1000 == 0)
        printf("[DENSE2] SUMMARY calls=%llu raw_grants=%llu built=%llu gated>=%.0fdB=%llu crc=%llu | Cfix=%+d seeded=%d locks=%zu\n",
               (unsigned long long)g_calls.load(), (unsigned long long)g_raw.load(),
               (unsigned long long)g_seen.load(), min_energy_db_, (unsigned long long)g_gated.load(),
               (unsigned long long)g_crc.load(), c_fixed_, (int)c_seeded_, c_samples_.size());
    if (g_calls.load() % 20000 == 0) dump_ue_stats();   // per-UE decode-yield table

    if (grants.empty()) return;

    for (auto g : grants) {
        srsran_pusch_cfg_t &pusch = ul_cfg_.pusch;
        if (!build_pusch_cfg(g, pusch)) continue;
        g_seen.fetch_add(1, std::memory_order_relaxed);

        float e_db = grant_energy_db(g);
        bool is_target = (g.rnti == target_rnti_);
        // Energy gate governs only the EXPENSIVE per-UE window search. Every grant
        // is still decoded at nominal + small-retry below (that is where real UL
        // decodes; gating that away is what made an energy-gated-only decoder miss
        // real frames the legacy path caught).
        bool do_search = (e_db >= min_energy_db_ || is_target);

        int best_off = 0; float best = -1e9f, bg = 0.0f; bool distinct = false; int n = 0;
        if (do_search) {
            g_gated.fetch_add(1, std::memory_order_relaxed);
            int center;
            if (c_seeded_) center = window_origin(g.rnti);
            else if (e_db >= boot_gate_db_) {
                int bo = 0; float bs = -1e9f;
                for (int off = -boot_range_; off <= boot_range_; off += 16) {
                    float s = chest_snr_at(off, pusch);
                    if (s > bs) { bs = s; bo = off; }
                }
                center = bo;                            // bootstrap wide-scan peak
            } else center = 0;
            double sum = 0.0;
            for (int off = center - fine_range_; off <= center + fine_range_; off += fine_step_) {
                float s = chest_snr_at(off, pusch);
                if (s <= -1e8f) continue;
                sum += s; n++;
                if (s > best) { best = s; best_off = off; }
            }
            if (n > 0) { bg = (float)(sum / n); distinct = (best - bg) > 2.0f; }
        }

        // Paired A/B (UL_DENSE2_AB): same grant, nominal window vs calibrated best.
        // Traffic-independent proof that re-centering lifts chest SNR on real grants.
        static const bool ab_on = (getenv("UL_DENSE2_AB") != nullptr);
        static std::atomic<uint64_t> ab_n{0};
        static std::atomic<long long> ab_s0{0}, ab_sc{0};   // millidB fixed-point sums
        if (ab_on && do_search && n > 0) {
            float s0 = chest_snr_at(0, pusch);       // chest at nominal window
            if (std::isfinite(s0) && s0 > -1e8f) {
                ab_n.fetch_add(1);
                ab_s0.fetch_add((long long)lroundf(s0   * 1000.0f));
                ab_sc.fetch_add((long long)lroundf(best * 1000.0f));
                uint64_t k = ab_n.load();
                if (k <= 60 || k % 50 == 0)
                    printf("[DENSE2-AB] rnti=0x%04x e=%.1fdB  snr@0=%.1f  snr@%+d=%.1f  gain=%+.1f  | mean0=%.2f meanCal=%.2f (n=%llu)\n",
                           g.rnti, e_db, s0, best_off, best, best - s0,
                           ab_s0.load()/1000.0/k, ab_sc.load()/1000.0/k, (unsigned long long)k);
            }
        }

        // Candidate windows, first CRC wins. ALWAYS decode at nominal + the legacy
        // small-retry set — real UL decodes NEAR nominal, and that is exactly what
        // the legacy path catches. Add the calibrated origin (if seeded) and the
        // energy-search peak for strong grants. HARQ accumulates at nominal (0),
        // the stable reference. The nominal window reuses the one saved FFT.
        static const int base_off[] = {0, 16, -16, 32, -32, 64, -64};
        int cands[16]; int nc = 0;
        for (int b : base_off) cands[nc++] = b;
        if (c_seeded_)          cands[nc++] = window_origin(g.rnti);
        if (do_search && n > 0) cands[nc++] = best_off;

        bool crc = false; int crc_off = 0;
        for (int i = 0; i < nc && !crc; i++) {
            int off = cands[i];
            // Geometric guard: reject far-POSITIVE windows (real UL arrives near/
            // before the DL reference; a large +offset decode is a noise false
            // positive). Small +retry and negative windows are allowed.
            if (off > pos_guard_ || off < -1200) continue;
            bool dup = false; for (int j = 0; j < i; j++) if (cands[j] == off) { dup = true; break; }
            if (dup) continue;
            // HARQ soft-combine at the nominal window; private scratch elsewhere.
            if (harq_on_ && off == 0) {
                uint32_t pid = ul_sf_.tti % 8;
                int ndi = g.ran_ul_dci ? g.ran_ul_dci->tb.ndi : 0;
                uint64_t key = ((uint64_t)g.rnti << 8) | (pid & 0xff);
                auto it = harq_last_ndi_.find(key);
                bool new_tx = (it == harq_last_ndi_.end()) || (it->second != ndi);
                harq_last_ndi_[key] = ndi;
                pusch.softbuffers.rx = harq_get(g.rnti, pid, new_tx);
                harq_no_reset_ = !new_tx;
            } else {
                pusch.softbuffers.rx = own_sb_;
                harq_no_reset_ = false;
            }
            if (off == 0) {
                if (mrc_on_) {
                    crc = mrc_decode(g, pusch);    // 2-RX MRC at the nominal window
                } else {
                    memcpy(enb_ul_.sf_symbols, nominal_sym_, sizeof(cf_t) * nominal_sym_len_);
                    crc = decode_current(g, pusch);
                }
            } else {
                if (!fft_at_offset(off)) continue;
                crc = decode_current(g, pusch);
            }
            if (crc) crc_off = off;
        }
        pusch.softbuffers.rx = own_sb_;
        harq_no_reset_ = false;
        if (crc) g_crc.fetch_add(1, std::memory_order_relaxed);

        // Per-UE UL accounting: grants attempted vs frames decoded, per C-RNTI.
        {
            std::lock_guard<std::mutex> lk(g_ue_mtx);
            auto& u = g_ue_stats[g.rnti];
            u.grants++; if (crc) u.decoded++;
            if (e_db > u.max_e) u.max_e = e_db;
            u.mcs = g.ran_ul_grant->tb.mcs_idx;
        }

        if (do_search && n > 0) observe_lock(g.rnti, best_off, best, distinct);

        static std::atomic<uint64_t> logn{0};
        uint64_t ln = logn.fetch_add(1);
        if (ln < 40 || ln % 200 == 0 || crc)
            printf("[DENSE2] rnti=0x%04x mcs=%d L=%d e=%.1fdB off=%+d snr=%.1f(bg%.1f) crc=%d@%+d "
                   "| Cfix=%+d seeded=%d seen=%llu gated=%llu crc=%llu\n",
                   g.rnti, g.ran_ul_grant->tb.mcs_idx, g.ran_ul_grant->L_prb, e_db,
                   best_off, best, bg, (int)crc, crc_off, c_fixed_, (int)c_seeded_,
                   (unsigned long long)g_seen.load(), (unsigned long long)g_gated.load(),
                   (unsigned long long)g_crc.load());
    }
}
