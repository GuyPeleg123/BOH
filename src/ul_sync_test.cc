/* ul_sync_test — ground-truth validation of the UplinkSyncAdapter (spec Test 2).
 *
 * Generates a KNOWN PUSCH burst with srsran_ue_ul (real DMRS, real turbo-coded
 * TB), injects KNOWN impairments (integer + fractional timing, residual CFO,
 * AWGN to a target SNR), then runs the adapter and the existing srsRAN decoder
 * on the impaired samples. Because the truth is known, this measures:
 *   - integer / fractional / CFO estimation accuracy (does the adapter recover
 *     what we injected, within tolerance?)
 *   - CRC recovery: does correcting the injected timing/CFO restore the CRC that
 *     the nominal (uncorrected) window loses?
 *
 * This is the only offline test that can PROVE the estimators independently of
 * whether real OTA captures carry enough energy to decode.
 *
 * Modes:
 *   --inject <int> <frac> <cfo>     single impairment, verbose
 *   --sweep-timing                  integer + fractional grid (spec Test 2)
 *   --sweep-cfo                     CFO grid (spec Test 2)
 *   --bler <snr_lo> <snr_hi> <step> BLER vs SNR, adapter off vs on (Test 3/4)
 * Common opts: -n <nof_prb> -L <L_prb> -m <mcs> -s <snr_db> -N <trials> --seed s
 */
#include "include/UplinkSyncAdapter.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <string>
#include <vector>
#include <complex>
#include <random>
#include <algorithm>

using cf = std::complex<float>;

struct Args {
    int   nof_prb = 25, L_prb = 4, mcs = 4;
    float snr_db  = 20.0f;
    int   trials  = 1;
    unsigned seed = 12345;
    std::string mode = "inject";
    int   inj_int = 0; double inj_frac = 0, inj_cfo = 0;
    float bler_lo = -2, bler_hi = 10, bler_step = 2;
};

// ---- A reusable TX/RX rig around one cell/grant ----
struct Rig {
    srsran_cell_t cell{};
    srsran_ue_ul_t  ue_ul{};
    srsran_enb_ul_t enb_ul{};
    srsran_ul_sf_cfg_t ul_sf{};
    srsran_ue_ul_cfg_t ue_ul_cfg{};
    srsran_ul_cfg_t rx_ul_cfg{};             // enb-side config (grant, dmrs, hopping)
    srsran_pusch_grant_t grant{};
    srsran_softbuffer_tx_t sb_tx{};
    srsran_softbuffer_rx_t sb_rx{};
    srsran_pusch_res_t pusch_res{};
    std::vector<cf_t> ue_out;                // ue_ul out_buffer (1 subframe)
    std::vector<cf_t> enb_in;                // enb_ul in_buffer (3 subframes @100prb)
    std::vector<uint8_t> tx_data, rx_data;
    uint32_t sf_len = 0, tbs_bytes = 0;
    UplinkSyncAdapter adapter;

    bool init(const Args& a);
    void free_all();
};

bool Rig::init(const Args& a)
{
    cell.nof_prb = a.nof_prb; cell.nof_ports = 1; cell.id = 1;
    cell.cp = SRSRAN_CP_NORM; cell.phich_length = SRSRAN_PHICH_NORM;
    cell.phich_resources = SRSRAN_PHICH_R_1; cell.frame_type = SRSRAN_FDD;
    sf_len = SRSRAN_SF_LEN_PRB(cell.nof_prb);

    ue_out.assign(sf_len, cf_t{});
    enb_in.assign(3 * SRSRAN_SF_LEN_PRB(100), cf_t{});

    if (srsran_ue_ul_init(&ue_ul, ue_out.data(), cell.nof_prb)) { fprintf(stderr, "ue_ul_init\n"); return false; }
    if (srsran_ue_ul_set_cell(&ue_ul, cell))                     { fprintf(stderr, "ue_ul_set_cell\n"); return false; }
    if (srsran_enb_ul_init(&enb_ul, enb_in.data(), 110))         { fprintf(stderr, "enb_ul_init\n"); return false; }

    srsran_refsignal_dmrs_pusch_cfg_t dmrs{};
    dmrs.cyclic_shift = 0; dmrs.delta_ss = 0;
    dmrs.group_hopping_en = false; dmrs.sequence_hopping_en = false;

    ue_ul_cfg.ul_cfg.dmrs = dmrs;
    ue_ul_cfg.ul_cfg.hopping.n_sb = 1; ue_ul_cfg.ul_cfg.hopping.hopping_offset = 0;
    ue_ul_cfg.ul_cfg.hopping.hop_mode = decltype(ue_ul_cfg.ul_cfg.hopping.hop_mode)(1); // inter-SF
    ue_ul_cfg.normalize_mode = SRSRAN_UE_UL_NORMALIZE_MODE_AUTO;

    rx_ul_cfg.dmrs = dmrs;
    if (srsran_enb_ul_set_cell(&enb_ul, cell, &rx_ul_cfg.dmrs, NULL)) { fprintf(stderr, "enb_ul_set_cell\n"); return false; }

    // Build the PUSCH grant from a DCI0 (fixed RIV = L_prb @ prb 0).
    srsran_dci_ul_t dci{};
    dci.rnti = 0x46; dci.freq_hop_fl = (decltype(dci.freq_hop_fl))(-1); // no freq hopping
    dci.type2_alloc.riv = srsran_ra_type2_to_riv(a.L_prb, 0, cell.nof_prb);
    dci.tb.mcs_idx = a.mcs; dci.tb.ndi = 1; dci.tb.rv = 0;
    ul_sf.tti = 0;
    if (srsran_ue_ul_dci_to_pusch_grant(&ue_ul, &ul_sf, &ue_ul_cfg, &dci, &grant)) {
        fprintf(stderr, "dci_to_pusch_grant\n"); return false;
    }
    grant.n_prb_tilde[0] = grant.n_prb[0]; grant.n_prb_tilde[1] = grant.n_prb[1];
    ue_ul_cfg.ul_cfg.pusch.grant = grant;
    ue_ul_cfg.ul_cfg.pusch.rnti  = dci.rnti;
    ue_ul_cfg.grant_available    = true;   // else srsran_ue_ul_encode zeros the output
    ue_ul_cfg.cc_idx             = 0;
    rx_ul_cfg.pusch.grant = grant;
    rx_ul_cfg.pusch.rnti  = dci.rnti;
    rx_ul_cfg.pusch.meas_ta_en = true;

    tbs_bytes = grant.tb.tbs / 8;

    srsran_softbuffer_tx_init(&sb_tx, 100);
    srsran_softbuffer_rx_init(&sb_rx, 100);
    ue_ul_cfg.ul_cfg.pusch.softbuffers.tx = &sb_tx;
    rx_ul_cfg.pusch.softbuffers.rx        = &sb_rx;

    tx_data.assign(tbs_bytes ? tbs_bytes : 1, 0);
    rx_data.assign(2000 * 8, 0);
    pusch_res.data = rx_data.data();

    UplinkSyncConfig scfg;
    scfg.search_range = 2400;          // must cover the test BASE margin below
    scfg.max_plausible_offset = 2048;  // test uses a BASE=1200 leading margin
    if (!adapter.configure(&enb_ul, cell, dmrs, scfg)) { fprintf(stderr, "adapter.configure\n"); return false; }
    return true;
}

void Rig::free_all()
{
    srsran_ue_ul_free(&ue_ul);
    srsran_enb_ul_free(&enb_ul);
    srsran_softbuffer_tx_free(&sb_tx);
    srsran_softbuffer_rx_free(&sb_rx);
}

// Windowed-sinc fractional delay (same kernel as the adapter, opposite use).
static void frac_delay(const std::vector<cf>& in, std::vector<cf>& out, double mu)
{
    const int L = 21, C = L / 2; float h[21]; float hs = 0;
    for (int n = 0; n < L; n++) {
        double x = (double)(n - C) - mu;
        double s = (std::fabs(x) < 1e-8) ? 1.0 : std::sin(M_PI * x) / (M_PI * x);
        double w = 0.5 - 0.5 * std::cos(2.0 * M_PI * n / (L - 1));
        h[n] = (float)(s * w); hs += h[n];
    }
    for (int n = 0; n < L; n++) h[n] /= hs;
    out.assign(in.size(), cf{});
    for (size_t i = 0; i < in.size(); i++) {
        cf acc(0, 0);
        for (int n = 0; n < L; n++) { int idx = (int)i + (n - C); if (idx >= 0 && idx < (int)in.size()) acc += h[n] * in[idx]; }
        out[i] = acc;
    }
}

struct TrialResult {
    bool   nominal_crc = false, adapted_crc = false;
    int    est_int = 0; double est_frac = 0, est_cfo = 0, norm_corr = 0, confidence = 0;
    std::string tclass, treason;
};

// One trial: generate -> impair -> (nominal decode) + (adapter decode). BASE is
// the leading margin so both signs of injected integer offset stay readable.
static TrialResult one_trial(Rig& R, const Args& a, int inj_int, double inj_frac, double inj_cfo,
                             float snr_db, std::mt19937& rng, TimingMode tmode)
{
    TrialResult tr;
    const int BASE = 1200;
    double fs = (double)srsran_symbol_sz(R.cell.nof_prb) * 15000.0;

    // Random TB, encode to time domain.
    std::uniform_int_distribution<int> byte(0, 255);
    for (uint32_t i = 0; i < R.tbs_bytes; i++) R.tx_data[i] = (uint8_t)byte(rng);
    srsran_softbuffer_tx_reset(&R.sb_tx);
    srsran_pusch_data_t pdata{}; pdata.ptr = R.tx_data.data();
    R.ul_sf.tti = 0;
    if (srsran_ue_ul_encode(&R.ue_ul, &R.ul_sf, &R.ue_ul_cfg, &pdata) < 0) { tr.treason = "encode_fail"; return tr; }

    // Measure TX signal power for the target SNR.
    double sigp = 0; for (uint32_t i = 0; i < R.sf_len; i++) sigp += std::norm(reinterpret_cast<cf*>(R.ue_out.data())[i]);
    sigp /= R.sf_len;
    double npow = sigp / std::pow(10.0, snr_db / 10.0);
    double nstd = std::sqrt(npow / 2.0);
    std::normal_distribution<float> gn(0.0f, (float)nstd);

    // Apply fractional delay to the clean TX subframe.
    std::vector<cf> clean(R.sf_len);
    for (uint32_t i = 0; i < R.sf_len; i++) clean[i] = reinterpret_cast<cf*>(R.ue_out.data())[i];
    std::vector<cf> shaped;
    if (std::fabs(inj_frac) > 1e-6) frac_delay(clean, shaped, inj_frac); else shaped = clean;

    // Compose the pristine snapshot: noise everywhere, TB placed at BASE+inj_int,
    // CFO applied across the placed subframe (phase referenced to subframe start).
    uint32_t total = R.enb_in.size();
    std::vector<cf> pris(total);
    for (uint32_t i = 0; i < total; i++) pris[i] = cf(gn(rng), gn(rng));
    int pos = BASE + inj_int;
    for (uint32_t i = 0; i < R.sf_len; i++) {
        int idx = pos + (int)i;
        if (idx < 0 || idx >= (int)total) continue;
        cf s = shaped[i];
        if (std::fabs(inj_cfo) > 1e-9) {
            double ph = 2.0 * M_PI * inj_cfo * (double)i / fs;
            s *= cf((float)std::cos(ph), (float)std::sin(ph));
        }
        pris[idx] += s;
    }
    const cf_t* pristine = reinterpret_cast<cf_t*>(pris.data());
    uint32_t nof = total;

    // ---- NOMINAL decode: window at the true integer position WITHOUT the
    // fractional/CFO/refined-timing correction. We center the nominal window at
    // BASE+inj_int so the ONLY thing the adapter adds is fine timing/frac/CFO
    // (isolates the adapter's contribution rather than the coarse integer, which
    // any windowing would find). ----
    auto decode_here = [&](void) -> bool {
        srsran_softbuffer_rx_reset_tbs(&R.sb_rx, R.grant.tb.tbs);
        R.pusch_res.crc = false;
        if (srsran_chest_ul_estimate_pusch(&R.enb_ul.chest, &R.ul_sf, &R.rx_ul_cfg.pusch,
                                           R.enb_ul.sf_symbols, &R.enb_ul.chest_res) != SRSRAN_SUCCESS) return false;
        srsran_pusch_decode(&R.enb_ul.pusch, &R.ul_sf, &R.rx_ul_cfg.pusch, &R.enb_ul.chest_res,
                            R.enb_ul.sf_symbols, &R.pusch_res);
        return R.pusch_res.crc && (memcmp(R.rx_data.data(), R.tx_data.data(), R.tbs_bytes) == 0);
    };

    // NOMINAL = the global, downlink-derived monitor window (fixed at BASE), with
    // NO per-UE timing/frac/CFO correction. This is exactly what a receiver using
    // one global UL timing reference does; the UE actually arrives at BASE+inj_int.
    R.adapter.synthesize_corrected_symbols(pristine, nof, R.sf_len, BASE, 0.0, 0.0);
    tr.nominal_crc = decode_here();

    // ---- ADAPTER decode: full staged estimate + correction ----
    UplinkSyncConfig scfg = R.adapter.config();
    scfg.timing_mode = tmode;
    R.adapter.set_config(scfg);
    UplinkSyncResult sr = R.adapter.run(pristine, nof, R.sf_len, R.ul_sf, R.rx_ul_cfg);
    tr.est_int  = sr.integer_offset_samples - BASE;   // recover injected offset
    tr.est_frac = sr.fractional_offset_samples;
    tr.est_cfo  = sr.residual_cfo_hz;
    tr.norm_corr = sr.normalized_correlation;
    tr.confidence = sr.confidence;
    tr.tclass = timing_class_str(sr.timing_class);
    tr.treason = sr.invalid_reason;
    if (sr.corrected_iq_available) tr.adapted_crc = decode_here();
    return tr;
}

/* Ground-truth HARQ soft-combining gain (spec Part 13). Encodes the SAME TB at
   the standard RV sequence 0,2,3,1, adds independent AWGN to each transmission,
   and decodes each into a PERSISTENT rx softbuffer (no reset between RVs) so
   srsRAN accumulates the soft bits across retransmissions. Reports BLER vs SNR
   as a function of how many transmissions were combined — the left-shift is the
   combining gain. This is the effect the live path currently throws away by
   resetting the softbuffer on every grant. */
static void harq_mode(int nof_prb, int L_prb, int mcs, float lo, float hi, float step,
                      int trials, unsigned seed)
{
    srsran_cell_t cell{}; cell.nof_prb=nof_prb; cell.nof_ports=1; cell.id=1; cell.cp=SRSRAN_CP_NORM;
    cell.phich_length=SRSRAN_PHICH_NORM; cell.phich_resources=SRSRAN_PHICH_R_1; cell.frame_type=SRSRAN_FDD;

    srsran_pusch_t tx{}, rx{};
    if (srsran_pusch_init_ue(&tx,nof_prb)||srsran_pusch_set_cell(&tx,cell)||
        srsran_pusch_init_enb(&rx,nof_prb)||srsran_pusch_set_cell(&rx,cell)) { fprintf(stderr,"pusch init\n"); return; }
    srsran_chest_ul_res_t chest{}; srsran_chest_ul_res_init(&chest,nof_prb); srsran_chest_ul_res_set_identity(&chest);

    srsran_ul_sf_cfg_t ul_sf{}; ul_sf.tti=0;
    srsran_pusch_hopping_cfg_t hop{}; hop.n_sb=1; hop.hopping_offset=0;
    hop.hop_mode=(decltype(hop.hop_mode))1;
    srsran_dci_ul_t dci{}; dci.freq_hop_fl=(decltype(dci.freq_hop_fl))(-1);
    dci.type2_alloc.riv=srsran_ra_type2_to_riv(L_prb,0,nof_prb); dci.tb.mcs_idx=mcs;
    srsran_pusch_cfg_t cfg{};
    if (srsran_ra_ul_dci_to_grant(&cell,&ul_sf,&hop,&dci,&cfg.grant)) { fprintf(stderr,"grant\n"); return; }
    cfg.grant.n_prb_tilde[0]=cfg.grant.n_prb[0]; cfg.grant.n_prb_tilde[1]=cfg.grant.n_prb[1];
    cfg.rnti=0x46;

    srsran_softbuffer_tx_t sbtx{}; srsran_softbuffer_tx_init(&sbtx,100);
    srsran_softbuffer_rx_t sbrx{}; srsran_softbuffer_rx_init(&sbrx,100);
    uint32_t tbs_b=cfg.grant.tb.tbs/8;
    std::vector<uint8_t> tb(tbs_b?tbs_b:1), rxb(150000);
    uint32_t nof_re=SRSRAN_NRE*nof_prb*2*SRSRAN_CP_NSYMB(cell.cp);
    std::vector<cf> sf(nof_re);
    std::mt19937 rng(seed);
    const bool chase=getenv("UL_HARQ_CHASE"); const int RVir[4]={0,2,3,1}, RVch[4]={0,0,0,0}; const int* RV=chase?RVch:RVir; const int MAXTX=4;

    printf("# HARQ soft-combining: nof_prb=%d L_prb=%d mcs=%d tbs=%u bits, %d trials/pt\n",
           nof_prb,L_prb,mcs,cfg.grant.tb.tbs,trials);
    printf("# BLER vs SNR by number of combined transmissions (RV 0,2,3,1):\n");
    printf("# %-6s | %-8s %-8s %-8s %-8s\n","snr","1-tx","2-tx","3-tx","4-tx");
    for (float snr=lo; snr<=hi+1e-6f; snr+=step){
        int fail[4]={0,0,0,0}; int resc=0;
        for (int t=0;t<trials;t++){
            for (uint32_t i=0;i<tbs_b;i++) tb[i]=(uint8_t)(rng()&0xff);
            srsran_softbuffer_rx_reset_tbs(&sbrx,cfg.grant.tb.tbs);
            srsran_softbuffer_tx_reset(&sbtx);   // once per TB: the first encode fills the
                                                 // full circular buffer that later RVs select from
            int decoded_at=-1;
            for (int k=0;k<MAXTX;k++){
                cfg.grant.tb.rv=RV[k]; cfg.softbuffers.tx=&sbtx;
                srsran_pusch_data_t pd{}; pd.ptr=tb.data();
                std::fill(sf.begin(),sf.end(),cf{});
                if (srsran_pusch_encode(&tx,&ul_sf,&cfg,&pd,reinterpret_cast<cf_t*>(sf.data()))) break;
                double P=0; uint32_t nz=0;
                for (uint32_t i=0;i<nof_re;i++){ double m=std::norm(sf[i]); if (m>0){P+=m;nz++;} }
                P = nz? P/nz : 1.0;
                double nvar=P/std::pow(10.0,snr/10.0), nstd=std::sqrt(nvar/2.0);
                std::normal_distribution<float> gn(0.f,(float)nstd);
                for (uint32_t i=0;i<nof_re;i++) sf[i]+=cf(gn(rng),gn(rng));
                chest.noise_estimate=(float)nvar;
                srsran_pusch_res_t pr{}; pr.data=rxb.data(); cfg.softbuffers.rx=&sbrx;
                srsran_pusch_decode(&rx,&ul_sf,&cfg,&chest,reinterpret_cast<cf_t*>(sf.data()),&pr);
                if (pr.crc && memcmp(rxb.data(),tb.data(),tbs_b)==0){ decoded_at=k; break; }
            }
            for (int n=0;n<MAXTX;n++) if (decoded_at<0 || decoded_at>n) fail[n]++;
            if (decoded_at>0) resc++;
        }
        printf("  %-6.1f | %-8.3f %-8.3f %-8.3f %-8.3f   (rescued_by_combine=%d)\n", snr,
               (double)fail[0]/trials,(double)fail[1]/trials,(double)fail[2]/trials,(double)fail[3]/trials, resc);
    }
    srsran_pusch_free(&tx); srsran_pusch_free(&rx); srsran_chest_ul_res_free(&chest);
    srsran_softbuffer_tx_free(&sbtx); srsran_softbuffer_rx_free(&sbrx);
}

static void parse(int argc, char** argv, Args& a)
{
    for (int i = 1; i < argc; i++) {
        std::string s = argv[i];
        auto next = [&](void){ return (i + 1 < argc) ? argv[++i] : (char*)"0"; };
        if      (s == "-n") a.nof_prb = atoi(next());
        else if (s == "-L") a.L_prb = atoi(next());
        else if (s == "-m") a.mcs = atoi(next());
        else if (s == "-s") a.snr_db = atof(next());
        else if (s == "-N") a.trials = atoi(next());
        else if (s == "--seed") a.seed = (unsigned)strtoul(next(), NULL, 10);
        else if (s == "--inject") { a.mode = "inject"; a.inj_int = atoi(next()); a.inj_frac = atof(next()); a.inj_cfo = atof(next()); }
        else if (s == "--sweep-timing") a.mode = "sweep-timing";
        else if (s == "--sweep-cfo")    a.mode = "sweep-cfo";
        else if (s == "--bler") { a.mode = "bler"; a.bler_lo = atof(next()); a.bler_hi = atof(next()); a.bler_step = atof(next()); }
        else if (s == "--selftest") a.mode = "selftest";
        else if (s == "--harq") { a.mode = "harq"; a.bler_lo=atof(next()); a.bler_hi=atof(next()); a.bler_step=atof(next()); }
    }
}

int main(int argc, char** argv)
{
    Args a; parse(argc, argv, a);
    if (a.mode == "harq") {
        harq_mode(a.nof_prb, a.L_prb, a.mcs, a.bler_lo, a.bler_hi, a.bler_step, a.trials, a.seed);
        return 0;
    }
    Rig R;
    if (!R.init(a)) return 2;
    printf("# cell nof_prb=%d L_prb=%d mcs=%d tbs=%u bits (%u B) fs=%.0f\n",
           a.nof_prb, a.L_prb, a.mcs, R.grant.tb.tbs, R.tbs_bytes,
           (double)srsran_symbol_sz(a.nof_prb) * 15000.0);
    std::mt19937 rng(a.seed);

    if (a.mode == "selftest") {
        // Canonical clean loop: encode -> place at enb_in[0] -> enb_ul_fft ->
        // chest -> decode, no noise, no offset. Proves the TX/RX config matches.
        std::uniform_int_distribution<int> byte(0, 255);
        for (uint32_t i = 0; i < R.tbs_bytes; i++) R.tx_data[i] = (uint8_t)byte(rng);
        srsran_softbuffer_tx_reset(&R.sb_tx);
        srsran_pusch_data_t pdata{}; pdata.ptr = R.tx_data.data();
        R.ul_sf.tti = 0;
        int enc = srsran_ue_ul_encode(&R.ue_ul, &R.ul_sf, &R.ue_ul_cfg, &pdata);
        double sigp = 0; for (uint32_t i = 0; i < R.sf_len; i++) sigp += std::norm(reinterpret_cast<cf*>(R.ue_out.data())[i]);
        std::fill(R.enb_in.begin(), R.enb_in.end(), cf_t{});
        memcpy(R.enb_in.data(), R.ue_out.data(), R.sf_len * sizeof(cf_t));
        R.enb_ul.in_buffer = R.enb_in.data();
        srsran_enb_ul_fft(&R.enb_ul);
        srsran_softbuffer_rx_reset_tbs(&R.sb_rx, R.grant.tb.tbs);
        R.pusch_res.crc = false;
        int ce = srsran_chest_ul_estimate_pusch(&R.enb_ul.chest, &R.ul_sf, &R.rx_ul_cfg.pusch,
                                                R.enb_ul.sf_symbols, &R.enb_ul.chest_res);
        srsran_pusch_decode(&R.enb_ul.pusch, &R.ul_sf, &R.rx_ul_cfg.pusch, &R.enb_ul.chest_res,
                            R.enb_ul.sf_symbols, &R.pusch_res);
        bool match = R.pusch_res.crc && (memcmp(R.rx_data.data(), R.tx_data.data(), R.tbs_bytes) == 0);
        printf("SELFTEST(canonical enb_ul_fft) enc=%d sigp=%.4e chest_ret=%d snr_db=%.2f ta_us=%.3f crc=%d match=%d\n",
               enc, sigp / R.sf_len, ce, R.enb_ul.chest_res.snr_db, R.enb_ul.chest_res.ta_us,
               R.pusch_res.crc, match);

        // Same clean signal, but decoded through the adapter's synthesize path
        // (shift_copy + srsran_ofdm_rx_sf_ng) at offset 0 — isolates ofdm_rx_sf_ng.
        R.adapter.synthesize_corrected_symbols(R.enb_in.data(), R.enb_in.size(), R.sf_len, 0, 0.0, 0.0);
        srsran_softbuffer_rx_reset_tbs(&R.sb_rx, R.grant.tb.tbs);
        R.pusch_res.crc = false;
        int ce2 = srsran_chest_ul_estimate_pusch(&R.enb_ul.chest, &R.ul_sf, &R.rx_ul_cfg.pusch,
                                                 R.enb_ul.sf_symbols, &R.enb_ul.chest_res);
        srsran_pusch_decode(&R.enb_ul.pusch, &R.ul_sf, &R.rx_ul_cfg.pusch, &R.enb_ul.chest_res,
                            R.enb_ul.sf_symbols, &R.pusch_res);
        bool match2 = R.pusch_res.crc && (memcmp(R.rx_data.data(), R.tx_data.data(), R.tbs_bytes) == 0);
        printf("SELFTEST(adapter ofdm_rx_sf_ng) chest_ret=%d snr_db=%.2f crc=%d match=%d\n",
               ce2, R.enb_ul.chest_res.snr_db, R.pusch_res.crc, match2);

        // Adapter run() on the clean signal at offset 0.
        UplinkSyncConfig sc = R.adapter.config(); sc.timing_mode = TimingMode::FULL; R.adapter.set_config(sc);
        UplinkSyncResult sr = R.adapter.run(R.enb_in.data(), R.enb_in.size(), R.sf_len, R.ul_sf, R.rx_ul_cfg);
        printf("SELFTEST(adapter run) est_int=%d frac=%.3f cfo=%.1f norm_corr=%.3f p2bg=%.2f class=%s\n",
               sr.integer_offset_samples, sr.fractional_offset_samples, sr.residual_cfo_hz,
               sr.normalized_correlation, sr.peak_to_background, timing_class_str(sr.timing_class));
        R.free_all();
        return 0;
    }

    if (a.mode == "inject") {
        TrialResult tr = one_trial(R, a, a.inj_int, a.inj_frac, a.inj_cfo, a.snr_db, rng, TimingMode::FULL);
        printf("INJECT int=%d frac=%.3f cfo=%.1f snr=%.1f =>\n", a.inj_int, a.inj_frac, a.inj_cfo, a.snr_db);
        printf("  EST int=%d (err %d)  frac=%.3f (err %+.3f)  cfo=%.1f (err %+.1f)  norm_corr=%.3f conf=%.2f class=%s %s\n",
               tr.est_int, tr.est_int - a.inj_int, tr.est_frac, tr.est_frac - a.inj_frac,
               tr.est_cfo, tr.est_cfo - a.inj_cfo, tr.norm_corr, tr.confidence, tr.tclass.c_str(), tr.treason.c_str());
        printf("  CRC nominal=%d adapted=%d combined=%d\n", tr.nominal_crc, tr.adapted_crc,
               tr.nominal_crc || tr.adapted_crc);
        R.free_all();
        return 0;
    }

    if (a.mode == "sweep-timing") {
        const int    ints[]  = {0, 8, -8, 16, -16, 32, -32, 64, -64, 128, -128, 256, -256, 512, -512};
        const double fracs[] = {0.0, 0.1, -0.1, 0.25, -0.25, 0.5, -0.5};
        printf("# TIMING SWEEP (snr=%.1f, %d trials each). Receiver keeps combined=nom||adp\n", a.snr_db, a.trials);
        printf("# adapter is a fallback: it only needs to help where nominal fails.\n");
        printf("# %-7s %-7s | %-9s | %-7s %-7s %-9s %-8s\n", "inj_int", "inj_frac", "int_mae*", "nom", "comb", "recovered", "broke");
        for (int ii : ints) for (double ff : fracs) {
            double ie = 0; int nc = 0, comb = 0, rec = 0, broke = 0, ok = 0, conf_ok = 0;
            for (int t = 0; t < a.trials; t++) {
                TrialResult tr = one_trial(R, a, ii, ff, 0.0, a.snr_db, rng, TimingMode::INTEGER_FRAC);
                bool c = tr.nominal_crc || tr.adapted_crc;
                // int_mae* only over CRC-validated adapter picks (a failed CRC is
                // rejected by the receiver, so its offset error is irrelevant).
                if (tr.adapted_crc) { ie += std::abs(tr.est_int - ii); conf_ok++; }
                nc += tr.nominal_crc; comb += c;
                rec += (!tr.nominal_crc && tr.adapted_crc);
                broke += (tr.nominal_crc && !tr.adapted_crc && !c); // impossible (comb keeps nom)
                ok++;
            }
            printf("  %-7d %-7.2f | %-9.2f | %-7d %-7d %-9d %-8d\n", ii, ff,
                   conf_ok ? ie / conf_ok : 0.0, nc, comb, rec, broke);
        }
        R.free_all();
        return 0;
    }

    if (a.mode == "sweep-cfo") {
        const double cfos[] = {0, 25, -25, 50, -50, 100, -100, 250, -250, 500, -500};
        printf("# CFO SWEEP (snr=%.1f, %d trials each). Injected int=256 (well beyond CP) so nominal\n", a.snr_db, a.trials);
        printf("# fails and the adapter must estimate+correct BOTH timing and CFO to recover.\n");
        printf("# %-8s | %-12s | %-7s %-7s %-9s\n", "inj_cfo", "cfo_err(mae)", "nom", "comb", "recovered");
        for (double cc : cfos) {
            double ce = 0; int nc = 0, comb = 0, rec = 0, ok = 0, conf_ok = 0;
            for (int t = 0; t < a.trials; t++) {
                TrialResult tr = one_trial(R, a, 256, 0.0, cc, a.snr_db, rng, TimingMode::FULL);
                if (tr.adapted_crc) { ce += std::fabs(tr.est_cfo - cc); conf_ok++; }
                nc += tr.nominal_crc; comb += (tr.nominal_crc || tr.adapted_crc);
                rec += (!tr.nominal_crc && tr.adapted_crc); ok++;
            }
            printf("  %-8.0f | %-12.2f | %-7d %-7d %-9d\n", cc, conf_ok ? ce / conf_ok : 0.0, nc, comb, rec);
        }
        R.free_all();
        return 0;
    }

    if (a.mode == "bler") {
        printf("# BLER vs SNR (%d trials/pt): per-UE arrival impaired int=256 frac=0.4 cfo=200\n", a.trials);
        printf("# (256 samples >> CP, so the global window never decodes it). nominal vs combined.\n");
        printf("# %-6s | %-10s %-10s\n", "snr", "bler_nom", "bler_comb");
        for (float snr = a.bler_lo; snr <= a.bler_hi + 1e-6; snr += a.bler_step) {
            int nc = 0, comb = 0;
            for (int t = 0; t < a.trials; t++) {
                TrialResult tr = one_trial(R, a, 256, 0.4, 200.0, snr, rng, TimingMode::FULL);
                nc += tr.nominal_crc; comb += (tr.nominal_crc || tr.adapted_crc);
            }
            printf("  %-6.1f | %-10.3f %-10.3f\n", snr,
                   1.0 - (double)nc / a.trials, 1.0 - (double)comb / a.trials);
        }
        R.free_all();
        return 0;
    }

    R.free_all();
    return 0;
}
