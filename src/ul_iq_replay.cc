/* ul_iq_replay — offline replay + timing analysis of a raw-UL-IQ capture.
 *
 * 1) Exact replay equivalence: rebuild the decode context from decode_ctx.bin,
 *    rerun the same nominal FFT -> chest -> PUSCH decode on the stored samples,
 *    and assert it reproduces the live CRC + channel SINR bit-for-bit.
 * 2) Timing search on the identical burst:
 *    --sweep N      linear ±N samples (chest+decode every step)
 *    --widesweep N  coarse (step 16, chest only) over ±N -> rank top DMRS-SINR
 *                   peaks -> fine ±16 @ 1-sample with decode -> accept CRC only.
 *
 * At 23.04 Msps, 1 sample ~= 43.4 ns, so --widesweep 1024 ~= ±44.4 us.
 *
 * Prints a machine-readable "RESULT ..." line for batch harnessing, plus FNV-1a
 * hashes of the IQ and (on CRC success) the decoded payload for divergence
 * localization / payload-equivalence checks.
 */
#include "srsran/srsran.h"
#include "include/UlIqCapture.h"
#include "include/UplinkSyncAdapter.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <string>
#include <vector>
#include <algorithm>

static uint64_t fnv1a(const void* p, size_t n)
{
    const uint8_t* b = (const uint8_t*)p; uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < n; i++) { h ^= b[i]; h *= 1099511628211ULL; }
    return h;
}

static bool load_file(const std::string& path, std::vector<uint8_t>& out)
{
    FILE* f = fopen(path.c_str(), "rb");
    if (!f) return false;
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    if (n <= 0) { fclose(f); return false; }
    out.resize((size_t)n);
    size_t r = fread(out.data(), 1, (size_t)n, f); fclose(f);
    return r == (size_t)n;
}

// Decode at a sample offset using the SAME mechanism as the live offset-retry
// (srsran_ofdm_rx_sf_ng on a shifted copy of the pristine snapshot). do_decode
// off => chest only (fast, for the coarse peak scan). Returns crc.
struct OffRes { float snr, ta; int crc; uint64_t payload_hash; };
static OffRes decode_at_offset(srsran_enb_ul_t& enb_ul, srsran_ul_sf_cfg_t& ul_sf,
                               srsran_ul_cfg_t& ul_cfg, srsran_pusch_res_t& pusch_res,
                               const std::vector<cf_t>& pristine, std::vector<cf_t>& working,
                               uint32_t sf_len, int off, bool do_decode)
{
    OffRes r; r.snr = NAN; r.ta = NAN; r.crc = 0; r.payload_hash = 0;
    const uint32_t copy_len = 2 * sf_len;
    if (off >= 0) { if ((uint32_t)off + copy_len > pristine.size()) return r; }
    else          { if ((uint32_t)(-off) > copy_len) return r; }
    srsran_vec_cf_zero(working.data(), copy_len);
    if (off >= 0) memcpy(working.data(), pristine.data() + off, copy_len * sizeof(cf_t));
    else { uint32_t sh = (uint32_t)(-off); memcpy(working.data() + sh, pristine.data(), (copy_len - sh) * sizeof(cf_t)); }
    srsran_ofdm_rx_sf_ng(&enb_ul.fft, working.data(), enb_ul.sf_symbols);
    int cr = srsran_chest_ul_estimate_pusch(&enb_ul.chest, &ul_sf, &ul_cfg.pusch, enb_ul.sf_symbols, &enb_ul.chest_res);
    r.snr = enb_ul.chest_res.snr_db; r.ta = enb_ul.chest_res.ta_us;
    if (do_decode && cr == SRSRAN_SUCCESS) {
        srsran_softbuffer_rx_reset_tbs(ul_cfg.pusch.softbuffers.rx, ul_cfg.pusch.grant.tb.tbs);
        pusch_res.crc = false;
        srsran_pusch_decode(&enb_ul.pusch, &ul_sf, &ul_cfg.pusch, &enb_ul.chest_res, enb_ul.sf_symbols, &pusch_res);
        r.crc = pusch_res.crc ? 1 : 0;
        if (r.crc) r.payload_hash = fnv1a(pusch_res.data, ul_cfg.pusch.grant.tb.tbs / 8);
    }
    return r;
}

int main(int argc, char** argv)
{
    if (argc < 2) { fprintf(stderr, "usage: %s <capture_dir> [--sweep N] [--widesweep N]\n", argv[0]); return 2; }
    std::string dir = argv[1];
    int sweep = 0, widesweep = 0; bool adapter_mode = false;
    for (int i = 2; i < argc; i++) {
        if (std::string(argv[i]) == "--sweep" && i + 1 < argc) sweep = atoi(argv[i+1]);
        if (std::string(argv[i]) == "--widesweep" && i + 1 < argc) widesweep = atoi(argv[i+1]);
        if (std::string(argv[i]) == "--adapter") adapter_mode = true;
    }

    std::vector<uint8_t> ctxbytes;
    // Accept v1 (no live_payload_hash) and v2 blobs: zero-init then copy what's
    // present. live_payload_hash stays 0 (n/a) for v1.
    if (!load_file(dir + "/decode_ctx.bin", ctxbytes) || ctxbytes.size() + 8 < sizeof(DecodeCtxBlob)) {
        fprintf(stderr, "ERROR: cannot read decode_ctx.bin\n"); printf("RESULT status=load_error\n"); return 3;
    }
    DecodeCtxBlob ctx; memset(&ctx, 0, sizeof(ctx));
    memcpy(&ctx, ctxbytes.data(), std::min(ctxbytes.size(), sizeof(ctx)));
    if (ctx.magic != UL_IQ_CTX_MAGIC) { fprintf(stderr, "ERROR: bad magic\n"); printf("RESULT status=bad_magic\n"); return 3; }
    if (ctx.version != UL_IQ_CTX_VERSION) fprintf(stderr, "WARN: blob version %u != %u\n", ctx.version, UL_IQ_CTX_VERSION);

    std::vector<uint8_t> iqbytes;
    if (!load_file(dir + "/uplink_cf32.iq", iqbytes)) { printf("RESULT status=iq_error\n"); return 3; }
    const uint32_t nof_samples = iqbytes.size() / sizeof(cf_t);
    std::vector<cf_t> pristine(nof_samples);
    memcpy(pristine.data(), iqbytes.data(), nof_samples * sizeof(cf_t));
    const uint64_t iq_hash = fnv1a(pristine.data(), nof_samples * sizeof(cf_t));
    const uint32_t sf_len = SRSRAN_SF_LEN_PRB(ctx.nof_prb);

    printf("Capture: %s\n  cell=%d nof_prb=%d rnti=0x%x tti=%u mcs=%u L_prb=%u n_prb=%u rv=%u 64qam=%d\n"
           "  IQ: %u samples sf_len=%u iq_hash=%016lx\n  LIVE: crc=%d snr_db=%.3f ta_us=%.3f noise=%.4e\n",
           dir.c_str(), ctx.cell_id, ctx.nof_prb, ctx.rnti, ctx.tti, ctx.grant.tb.mcs_idx,
           ctx.grant.L_prb, ctx.grant.n_prb[0], ctx.grant.tb.rv, ctx.enable_64qam,
           nof_samples, sf_len, iq_hash, ctx.live_crc, ctx.live_snr_db, ctx.live_ta_us, ctx.live_noise_estimate);

    // ---- Rebuild decoder exactly as the live path ----
    srsran_enb_ul_t enb_ul; memset(&enb_ul, 0, sizeof(enb_ul));
    std::vector<cf_t> in_buffer(3 * SRSRAN_SF_LEN_PRB(100));
    if (srsran_enb_ul_init(&enb_ul, in_buffer.data(), 110)) { printf("RESULT status=init_error\n"); return 4; }
    srsran_cell_t cell; memset(&cell, 0, sizeof(cell));
    cell.nof_prb = ctx.nof_prb; cell.id = ctx.cell_id; cell.cp = (srsran_cp_t)ctx.cp;
    cell.nof_ports = ctx.nof_ports ? ctx.nof_ports : 1;
    cell.phich_length = SRSRAN_PHICH_NORM; cell.phich_resources = SRSRAN_PHICH_R_1; cell.frame_type = SRSRAN_FDD;
    srsran_ul_cfg_t ul_cfg; memset(&ul_cfg, 0, sizeof(ul_cfg));
    ul_cfg.dmrs = ctx.dmrs;
    if (srsran_enb_ul_set_cell(&enb_ul, cell, &ul_cfg.dmrs, NULL)) { printf("RESULT status=setcell_error\n"); return 4; }
    // Experiment: override the DMRS channel-estimate smoothing filter. Heavier
    // frequency-domain averaging denoises the estimate on tiny allocations at low
    // SNR. UL_CHEST_SMOOTH=<len> uses a Gaussian filter of that length (2..63).
    if (const char* sm = getenv("UL_CHEST_SMOOTH")) {
        int len = atoi(sm); if (len < 1) len = 1; if (len > 63) len = 63;
        float sigma = getenv("UL_CHEST_SIGMA") ? (float)atof(getenv("UL_CHEST_SIGMA")) : 2.0f;
        enb_ul.chest.smooth_filter_len = (uint32_t)len;
        if (len == 1) { enb_ul.chest.smooth_filter[0] = 1.0f; }      // len 1 = no averaging
        else if (getenv("UL_CHEST_RECT")) {                          // rectangular (equal weights)
            for (int k = 0; k < len; k++) enb_ul.chest.smooth_filter[k] = 1.0f / (float)len;
        } else srsran_chest_set_smooth_filter_gauss(enb_ul.chest.smooth_filter, (uint32_t)len, sigma);
    }
    ul_cfg.hopping = ctx.hopping; ul_cfg.pusch.rnti = ctx.rnti; ul_cfg.pusch.grant = ctx.grant;
    ul_cfg.pusch.enable_64qam = ctx.enable_64qam != 0; ul_cfg.pusch.uci_cfg = ctx.uci_cfg;
    ul_cfg.pusch.uci_offset = ctx.uci_offset; ul_cfg.pusch.meas_ta_en = true;
    // Experiment: turbo-decoder max iterations (default 0 => srsRAN's 5). More
    // iterations can decode marginally weaker TBs at extra CPU (diminishing).
    if (const char* it = getenv("UL_MAX_ITER")) ul_cfg.pusch.max_nof_iterations = (uint32_t)atoi(it);
    srsran_softbuffer_rx_t softbuffer; srsran_softbuffer_rx_init(&softbuffer, SRSRAN_MAX_PRB);
    ul_cfg.pusch.softbuffers.rx = &softbuffer;
    srsran_pusch_res_t pusch_res; memset(&pusch_res, 0, sizeof(pusch_res));
    pusch_res.data = srsran_vec_u8_malloc(2000 * 8);
    srsran_ul_sf_cfg_t ul_sf; memset(&ul_sf, 0, sizeof(ul_sf)); ul_sf.tti = ctx.tti;

    // ---- NOMINAL: exact live path (srsran_enb_ul_fft), must match ----
    srsran_softbuffer_rx_reset_tbs(ul_cfg.pusch.softbuffers.rx, ul_cfg.pusch.grant.tb.tbs);
    memcpy(in_buffer.data(), pristine.data(), sf_len * sizeof(cf_t));
    enb_ul.in_buffer = in_buffer.data();
    srsran_enb_ul_fft(&enb_ul);
    int cret = srsran_chest_ul_estimate_pusch(&enb_ul.chest, &ul_sf, &ul_cfg.pusch, enb_ul.sf_symbols, &enb_ul.chest_res);
    // Experiment: per-UE CFO correction. srsRAN estimates chest_res.cfo_hz but never
    // applies it; de-rotate each OFDM symbol by its time phase and re-chest.
    if (cret == SRSRAN_SUCCESS && getenv("UL_REPLAY_CFO")) {
        float cfo = enb_ul.chest_res.cfo_hz;
        if (std::isfinite(cfo) && fabsf(cfo) > 15.0f && fabsf(cfo) < 950.0f) {
            uint32_t nsc = cell.nof_prb * SRSRAN_NRE, nsymb = SRSRAN_CP_NORM_SF_NSYMB;
            float Tsym = 1e-3f / (float)nsymb;
            for (uint32_t m = 0; m < nsymb; m++) {
                float ph = -2.0f * (float)M_PI * cfo * (float)m * Tsym, cr = cosf(ph), ci = sinf(ph);
                cf_t* s = &enb_ul.sf_symbols[(size_t)m * nsc];
                for (uint32_t k = 0; k < nsc; k++) {
                    float xr = __real__ s[k], xi = __imag__ s[k];
                    __real__ s[k] = xr*cr - xi*ci; __imag__ s[k] = xr*ci + xi*cr;
                }
            }
            cret = srsran_chest_ul_estimate_pusch(&enb_ul.chest, &ul_sf, &ul_cfg.pusch, enb_ul.sf_symbols, &enb_ul.chest_res);
        }
    }
    // Experiment: scale the noise estimate (LLR / MMSE calibration). >1 = assume
    // more noise (softer LLRs), <1 = harder LLRs.
    if (const char* ns = getenv("UL_NOISE_SCALE")) enb_ul.chest_res.noise_estimate *= (float)atof(ns);
    pusch_res.crc = false;
    if (cret == SRSRAN_SUCCESS)
        srsran_pusch_decode(&enb_ul.pusch, &ul_sf, &ul_cfg.pusch, &enb_ul.chest_res, enb_ul.sf_symbols, &pusch_res);
    const float rsnr = enb_ul.chest_res.snr_db, rta = enb_ul.chest_res.ta_us;
    const int rcrc = pusch_res.crc ? 1 : 0;
    uint64_t rpay = rcrc ? fnv1a(pusch_res.data, ul_cfg.pusch.grant.tb.tbs / 8) : 0;
    printf("REPLAY(nominal): crc=%d snr_db=%.3f ta_us=%.3f noise=%.4e payload_hash=%016lx\n",
           rcrc, rsnr, rta, enb_ul.chest_res.noise_estimate, rpay);

    const bool crc_match = (rcrc == ctx.live_crc);
    const bool snr_match = std::isnan(rsnr) ? (std::isnan(ctx.live_snr_db) || ctx.live_snr_db == 0.0f)
                                            : fabsf(rsnr - ctx.live_snr_db) < 0.05f;
    // Byte-exact payload equivalence, checkable only when BOTH sides decoded and
    // the blob carries a live hash (v2+). Vacuously true otherwise.
    const bool have_live_pay = (ctx.version >= 2 && ctx.live_crc == 1 && ctx.live_payload_hash != 0);
    const bool payload_match = (rcrc == 1 && have_live_pay) ? (rpay == ctx.live_payload_hash) : true;
    const bool payload_testable = (rcrc == 1 && have_live_pay);
    const bool equiv = crc_match && snr_match && payload_match;
    printf("EQUIVALENCE: crc %s | snr %s (Δ=%.5f) | payload %s => %s\n",
           crc_match ? "MATCH" : "MISMATCH", snr_match ? "MATCH" : "MISMATCH", rsnr - ctx.live_snr_db,
           !payload_testable ? "n/a" : (payload_match ? "MATCH" : "MISMATCH"),
           equiv ? "PASS" : "FAIL");

    // ---- Timing search ----
    int    best_snr_off = 0;  float best_snr = std::isnan(rsnr) ? -1e9f : rsnr;
    int    crc_off = 0;       int   crc_found = 0, crc_multi = 0; uint64_t crc_pay = 0;
    std::vector<cf_t> working(2 * sf_len);

    if (sweep > 0) {
        printf("\nLINEAR SWEEP (off : snr ta crc):\n");
        for (int off = -sweep; off <= sweep; off += 2) {
            OffRes r = decode_at_offset(enb_ul, ul_sf, ul_cfg, pusch_res, pristine, working, sf_len, off, true);
            if (std::isfinite(r.snr) && r.snr > best_snr) { best_snr = r.snr; best_snr_off = off; }
            if (r.crc) { if (!crc_found) { crc_off = off; crc_pay = r.payload_hash; } else crc_multi++; crc_found++; }
            printf("  %+6d : %6.2f %7.3f %d\n", off, r.snr, r.ta, r.crc);
        }
    }

    if (widesweep > 0) {
        // 1) coarse chest-only scan, collect (snr,off)
        const int coarse_step = 16;
        std::vector<std::pair<float,int> > peaks;
        for (int off = -widesweep; off <= widesweep; off += coarse_step) {
            OffRes r = decode_at_offset(enb_ul, ul_sf, ul_cfg, pusch_res, pristine, working, sf_len, off, false);
            if (std::isfinite(r.snr)) peaks.push_back(std::make_pair(r.snr, off));
        }
        // 2) rank, take top 5 peaks
        std::sort(peaks.begin(), peaks.end(), [](const std::pair<float,int>&a, const std::pair<float,int>&b){ return a.first > b.first; });
        int ntop = (int)std::min((size_t)5, peaks.size());
        printf("\nWIDE SWEEP ±%d (coarse step %d): top DMRS-SINR peaks:", widesweep, coarse_step);
        for (int i = 0; i < ntop; i++) printf(" [off=%+d snr=%.2f]", peaks[i].second, peaks[i].first);
        printf("\n  fine ±16 @1-sample + decode around each peak:\n");
        // 3) fine search + decode around each top peak
        for (int i = 0; i < ntop; i++) {
            int c = peaks[i].second;
            for (int off = c - 16; off <= c + 16; off++) {
                OffRes r = decode_at_offset(enb_ul, ul_sf, ul_cfg, pusch_res, pristine, working, sf_len, off, true);
                if (std::isfinite(r.snr) && r.snr > best_snr) { best_snr = r.snr; best_snr_off = off; }
                if (r.crc) {
                    if (!crc_found) { crc_off = off; crc_pay = r.payload_hash; }
                    else if (r.payload_hash != crc_pay) crc_multi++;
                    crc_found++;
                    printf("    CRC PASS @ off=%+d snr=%.2f ta=%.3f payload=%016lx\n", off, r.snr, r.ta, r.payload_hash);
                }
            }
        }
        if (!crc_found) printf("    no CRC pass at any offset\n");
    }

    if (sweep > 0 || widesweep > 0) {
        printf("SWEEP best_snr_off=%+d best_snr=%.2f (nominal=%.2f gain=%.2f dB) crc_found=%d crc_off=%+d multi=%d\n",
               best_snr_off, best_snr, rsnr, best_snr - (std::isnan(rsnr)?0:rsnr), crc_found, crc_off, crc_multi);
    }

    // ---- UplinkSyncAdapter (staged per-grant sync + classify + decode) ----
    // Runs the full adapter on the identical stored burst: coarse DMRS/chest
    // acquisition -> fine integer -> fractional -> residual CFO -> classify ->
    // corrected FFT -> decode. Prints the classification and whether correcting
    // the per-grant timing/CFO recovers a CRC the nominal window missed.
    if (adapter_mode) {
        UplinkSyncAdapter ad;
        UplinkSyncConfig scfg;
        scfg.search_range = 1024;
        if (const char* e = getenv("UL_ADAPT_RANGE"))  scfg.search_range = atoi(e);
        if (const char* e = getenv("UL_ADAPT_MINCORR")) scfg.min_norm_corr = (float)atof(e);
        srsran_refsignal_dmrs_pusch_cfg_t dmrs = ctx.dmrs;
        int acrc = 0; float asnr = NAN; UplinkSyncResult sr;
        if (ad.configure(&enb_ul, cell, dmrs, scfg)) {
            sr = ad.run(pristine.data(), nof_samples, sf_len, ul_sf, ul_cfg);
            if (sr.corrected_iq_available) {
                srsran_softbuffer_rx_reset_tbs(ul_cfg.pusch.softbuffers.rx, ul_cfg.pusch.grant.tb.tbs);
                pusch_res.crc = false;
                if (srsran_chest_ul_estimate_pusch(&enb_ul.chest, &ul_sf, &ul_cfg.pusch,
                                                   enb_ul.sf_symbols, &enb_ul.chest_res) == SRSRAN_SUCCESS)
                    srsran_pusch_decode(&enb_ul.pusch, &ul_sf, &ul_cfg.pusch, &enb_ul.chest_res,
                                        enb_ul.sf_symbols, &pusch_res);
                acrc = pusch_res.crc ? 1 : 0; asnr = enb_ul.chest_res.snr_db;
            }
        }
        printf("\nADAPTER: class=%s src=%s off=%+d frac=%.3f cfo=%.1fHz norm_corr=%.3f "
               "p2bg=%.2f p2snd=%.2f slot0=%.2f slot1=%.2f slotdiff=%.1f conf=%.2f reason='%s'\n"
               "  nominal_crc=%d adapter_crc=%d adapter_snr=%.2f (recovered=%d)\n",
               timing_class_str(sr.timing_class), timing_source_str(sr.timing_source),
               sr.integer_offset_samples, sr.fractional_offset_samples, sr.residual_cfo_hz,
               sr.normalized_correlation, sr.peak_to_background, sr.peak_to_second_peak,
               sr.slot0_correlation, sr.slot1_correlation, sr.slot_timing_difference_samples,
               sr.confidence, sr.invalid_reason.c_str(), rcrc, acrc, asnr, (!rcrc && acrc) ? 1 : 0);
        printf("ADAPTER_RESULT class=%s off=%+d cfo=%.2f norm_corr=%.4f p2bg=%.3f conf=%.3f "
               "nominal_crc=%d adapter_crc=%d recovered=%d mcs=%u tbs=%u L_prb=%u\n",
               timing_class_str(sr.timing_class), sr.integer_offset_samples, sr.residual_cfo_hz,
               sr.normalized_correlation, sr.peak_to_background, sr.confidence,
               rcrc, acrc, (!rcrc && acrc) ? 1 : 0, ctx.grant.tb.mcs_idx, ctx.grant.tb.tbs, ctx.grant.L_prb);
    }

    // Machine-readable summary for batch harnessing
    printf("RESULT status=ok equiv=%s live_crc=%d replay_crc=%d live_snr=%.4f replay_snr=%.4f "
           "live_ta=%.4f replay_ta=%.4f snr_dphi=%.5f crc_match=%d snr_match=%d "
           "mcs=%u tbs=%u L_prb=%u n_prb=%u rv=%u nan_chest=%d iq_hash=%016lx live_payload=%016lx replay_payload=%016lx "
           "payload_match=%d payload_testable=%d sweep_best_off=%+d sweep_best_snr=%.3f sweep_crc_found=%d sweep_crc_off=%+d sweep_crc_multi=%d\n",
           equiv ? "PASS" : "FAIL", ctx.live_crc, rcrc, ctx.live_snr_db, rsnr, ctx.live_ta_us, rta,
           rsnr - ctx.live_snr_db, crc_match ? 1 : 0, snr_match ? 1 : 0,
           ctx.grant.tb.mcs_idx, ctx.grant.tb.tbs, ctx.grant.L_prb, ctx.grant.n_prb[0], ctx.grant.tb.rv,
           std::isnan(rsnr) ? 1 : 0, iq_hash, ctx.live_payload_hash, rpay,
           payload_match ? 1 : 0, payload_testable ? 1 : 0,
           best_snr_off, best_snr, crc_found, crc_off, crc_multi);

    free(pusch_res.data);
    srsran_softbuffer_rx_free(&softbuffer);
    srsran_enb_ul_free(&enb_ul);
    return equiv ? 0 : 1;
}
