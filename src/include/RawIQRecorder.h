/* RawIQRecorder — bounded, grant-keyed raw-uplink-IQ recorder.
 *
 * Captures the EXACT pre-FFT time-domain UL samples the live decoder used
 * (from sf_buffer_offset[0], the clean 3-subframe snapshot taken before the
 * in-place FFT), together with full per-grant metadata, so any burst — success
 * or failure — can be replayed offline and reprocessed with alternate timing /
 * channel-estimation / noise / LLR hypotheses.
 *
 * Design (see spec): bounded memory+disk, grant-triggered, records CRC failures,
 * independent of live decode outcome, thread-safe, and NON-BLOCKING to the RT
 * receive/subframe path — request_capture() only copies into a bounded queue; a
 * dedicated writer thread serializes files. Env-gated (UL_IQ_REC); zero cost off.
 *
 * On-disk (per capture):   <outdir>/capture_<runid>_<seq>/
 *                              metadata.json
 *                              uplink_cf32.iq   (interleaved little-endian f32 I,Q)
 * plus a run-level index    <outdir>/captures.csv
 * Files are written to a .tmp dir and renamed atomically on completion.
 */
#ifndef RAW_IQ_RECORDER_H
#define RAW_IQ_RECORDER_H

#include <cstdint>
#include <string>
#include <vector>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <deque>
#include "srsran/srsran.h"

struct CaptureMeta {
    std::string category;                 // crc_ok/strong_fail/moderate_fail/weak_fail/chest_nan/timing_outlier/retx
    // RF config
    double   sample_rate = 0, center_freq_ul = 0, master_clock = 0;
    int      nof_prb = 0; float ul_gain = 0;
    std::string clock_source = "external", time_source = "external";
    std::string sdr_model = "B210", sdr_serial;
    // Timing / capture-integrity
    uint32_t tti = 0, sfn = 0, sf_idx = 0, pusch_start_sample = 0;
    double   ts_a = 0, ts_b = 0, ts_ab_diff_us = 0; int secs_eq = 0;
    uint32_t requested_samples = 0, actual_samples = 0; int complete = 1;
    // Cell / DMRS
    int      cell_id = 0, cp = 0, fdd = 1;
    uint32_t dmrs_cyclic_shift = 0, delta_ss = 0; int group_hop = 0, seq_hop = 0;
    // Grant
    uint16_t rnti = 0; int mcs_idx = 0, mod = 0; uint32_t tbs = 0, rv = 0; int ndi = 0;
    uint32_t n_prb0 = 0, L_prb = 0, n_dmrs = 0; int is_retx = 0;
    // Live measurements
    float energy_snr = 0, chest_sinr = 0, p_alloc = 0, noise_floor = 0;
    float ta_us = 0, cfo_hz = 0;
    int   crc = 0;
    // Exact decode context (a DecodeCtxBlob, see UlIqCapture.h) written verbatim
    // as decode_ctx.bin so the burst can be replayed bit-for-bit. Empty => skip.
    std::vector<uint8_t> ctx_blob;
};

class RawIQRecorder {
public:
    static RawIQRecorder& instance();

    void configure();                       // read env once; start writer thread
    bool enabled() const { return enabled_; }
    bool quota_reached() const { return max_captures_ > 0 && quota_used_.load() >= max_captures_; }

    // Non-blocking: copies `nof_samples` cf_t from `iq` + `meta` into a bounded
    // queue and returns immediately. Drops (counted) if disabled, quota reached,
    // or the queue is full. NEVER writes disk on the calling thread.
    void request_capture(const cf_t* iq, uint32_t nof_samples, CaptureMeta meta);

    void shutdown();
    std::string stats() const;

private:
    RawIQRecorder() {}
    ~RawIQRecorder();
    void writer_loop();
    void write_one(const std::vector<cf_t>& iq, const CaptureMeta& m, uint64_t seq);

    bool        enabled_ = false, started_ = false;
    std::string outdir_, run_id_, csv_path_;
    size_t      max_captures_ = 0, max_queue_ = 64;

    std::atomic<uint64_t> quota_used_{0}, n_requested_{0}, n_written_{0},
                          n_dropped_queue_{0}, n_diskerr_{0};
    uint64_t    seq_ = 0;

    struct Item { std::vector<cf_t> iq; CaptureMeta meta; uint64_t seq; };
    std::deque<Item>        queue_;
    mutable std::mutex      mtx_;
    std::condition_variable cv_;
    std::atomic<bool>       stop_{false};
    std::thread             writer_;
};

#endif // RAW_IQ_RECORDER_H
