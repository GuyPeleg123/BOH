#include "include/RawIQRecorder.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <fstream>
#include <ctime>
#include <sys/stat.h>
#include <sys/types.h>

RawIQRecorder& RawIQRecorder::instance()
{
    static RawIQRecorder inst;
    return inst;
}

RawIQRecorder::~RawIQRecorder()
{
    shutdown();
}

static std::string env_or(const char* k, const std::string& def)
{
    const char* v = getenv(k);
    return (v && *v) ? std::string(v) : def;
}

void RawIQRecorder::configure()
{
    if (started_) return;                    // idempotent
    started_ = true;
    if (!getenv("UL_IQ_REC")) { enabled_ = false; return; }
    enabled_ = true;

    // run id = timestamp; outdir default under the captures tree
    char tbuf[32];
    time_t now = time(nullptr);
    strftime(tbuf, sizeof(tbuf), "%Y-%m-%d_%H-%M-%S", localtime(&now));
    run_id_  = tbuf;
    outdir_  = env_or("UL_IQ_DIR", env_or("HOME", "/tmp") + "/ltesniffer-captures/iq_" + run_id_);
    max_captures_ = (size_t)atoll(env_or("UL_IQ_MAX", "500").c_str());
    max_queue_    = (size_t)atoll(env_or("UL_IQ_QUEUE", "64").c_str());

    ::mkdir((env_or("HOME", "/tmp") + "/ltesniffer-captures").c_str(), 0775);
    if (::mkdir(outdir_.c_str(), 0775) != 0 && errno != EEXIST) {
        fprintf(stderr, "[IQREC] could not create outdir %s — disabling\n", outdir_.c_str());
        enabled_ = false; return;
    }
    csv_path_ = outdir_ + "/captures.csv";
    {
        std::ofstream csv(csv_path_.c_str());
        csv << "seq,tti,rnti,mcs,L_prb,rv,energy_snr,chest_sinr,ta_us,crc,category,samples,path\n";
    }
    writer_ = std::thread(&RawIQRecorder::writer_loop, this);
    printf("[IQREC] ENABLED -> %s  (max_captures=%zu, queue=%zu)\n",
           outdir_.c_str(), max_captures_, max_queue_);
    fflush(stdout);
}

void RawIQRecorder::request_capture(const cf_t* iq, uint32_t nof_samples, CaptureMeta meta)
{
    if (!enabled_ || iq == nullptr || nof_samples == 0) { n_dropped_queue_++; return; }
    if (quota_reached()) { n_dropped_queue_++; return; }
    n_requested_++;

    Item item;
    item.iq.assign(iq, iq + nof_samples);    // copy off the RT path
    meta.actual_samples = nof_samples;
    meta.complete = (meta.requested_samples == 0 || nof_samples >= meta.requested_samples) ? 1 : 0;
    item.meta = std::move(meta);

    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (queue_.size() >= max_queue_) { n_dropped_queue_++; return; }  // bounded; never block RT
        item.seq = seq_++;
        quota_used_++;
        queue_.push_back(std::move(item));
    }
    cv_.notify_one();
}

void RawIQRecorder::writer_loop()
{
    for (;;) {
        Item item;
        {
            std::unique_lock<std::mutex> lk(mtx_);
            cv_.wait(lk, [this] { return stop_.load() || !queue_.empty(); });
            if (queue_.empty()) { if (stop_.load()) break; else continue; }
            item = std::move(queue_.front());
            queue_.pop_front();
        }
        write_one(item.iq, item.meta, item.seq);
    }
}

static void json_kv(std::ostream& o, const char* k, double v, bool last=false)
{ o << "  \"" << k << "\": " << v << (last ? "\n" : ",\n"); }
static void json_ks(std::ostream& o, const char* k, const std::string& v, bool last=false)
{ o << "  \"" << k << "\": \"" << v << "\"" << (last ? "\n" : ",\n"); }

void RawIQRecorder::write_one(const std::vector<cf_t>& iq, const CaptureMeta& m, uint64_t seq)
{
    char name[64]; snprintf(name, sizeof(name), "capture_%s_%06llu", run_id_.c_str(), (unsigned long long)seq);
    std::string tmp = outdir_ + "/." + name + ".tmp";
    std::string fin = outdir_ + "/" + name;
    ::mkdir(tmp.c_str(), 0775);

    // 1) IQ payload — cf_t is interleaved complex float32 => write raw.
    std::string iqp = tmp + "/uplink_cf32.iq";
    FILE* f = fopen(iqp.c_str(), "wb");
    if (!f) { n_diskerr_++; return; }
    size_t wrote = fwrite(iq.data(), sizeof(cf_t), iq.size(), f);
    fflush(f); fclose(f);
    if (wrote != iq.size()) { n_diskerr_++; return; }

    // 2) metadata.json
    std::ostringstream j;
    j << "{\n";
    json_ks(j, "format_version", "1");
    json_ks(j, "category", m.category);
    json_ks(j, "run_id", run_id_);
    json_kv(j, "seq", (double)seq);
    json_ks(j, "iq_format", "cf32_interleaved_le");
    json_kv(j, "iq_samples", (double)iq.size());
    // rf
    json_kv(j, "sample_rate", m.sample_rate);
    json_kv(j, "master_clock", m.master_clock);
    json_kv(j, "center_freq_ul", m.center_freq_ul);
    json_kv(j, "nof_prb", m.nof_prb);
    json_kv(j, "ul_gain", m.ul_gain);
    json_ks(j, "clock_source", m.clock_source);
    json_ks(j, "time_source", m.time_source);
    json_ks(j, "sdr_model", m.sdr_model);
    json_ks(j, "sdr_serial", m.sdr_serial);
    // timing / integrity
    json_kv(j, "tti", m.tti); json_kv(j, "sfn", m.sfn); json_kv(j, "sf_idx", m.sf_idx);
    json_kv(j, "pusch_start_sample", m.pusch_start_sample);
    json_kv(j, "ts_a", m.ts_a); json_kv(j, "ts_b", m.ts_b);
    json_kv(j, "ts_ab_diff_us", m.ts_ab_diff_us); json_kv(j, "secs_eq", m.secs_eq);
    json_kv(j, "requested_samples", m.requested_samples);
    json_kv(j, "actual_samples", m.actual_samples); json_kv(j, "complete", m.complete);
    // cell / dmrs
    json_kv(j, "cell_id", m.cell_id); json_kv(j, "cp", m.cp); json_kv(j, "fdd", m.fdd);
    json_kv(j, "dmrs_cyclic_shift", m.dmrs_cyclic_shift); json_kv(j, "delta_ss", m.delta_ss);
    json_kv(j, "group_hop", m.group_hop); json_kv(j, "seq_hop", m.seq_hop);
    // grant
    json_kv(j, "rnti", m.rnti); json_kv(j, "mcs_idx", m.mcs_idx); json_kv(j, "mod", m.mod);
    json_kv(j, "tbs", m.tbs); json_kv(j, "rv", m.rv); json_kv(j, "ndi", m.ndi);
    json_kv(j, "n_prb0", m.n_prb0); json_kv(j, "L_prb", m.L_prb); json_kv(j, "n_dmrs", m.n_dmrs);
    json_kv(j, "is_retx", m.is_retx);
    // measurements
    json_kv(j, "energy_snr", m.energy_snr); json_kv(j, "chest_sinr", m.chest_sinr);
    json_kv(j, "p_alloc", m.p_alloc); json_kv(j, "noise_floor", m.noise_floor);
    json_kv(j, "ta_us", m.ta_us); json_kv(j, "cfo_hz", m.cfo_hz);
    json_kv(j, "crc", m.crc, true);
    j << "}\n";
    std::string mp = tmp + "/metadata.json";
    std::ofstream mf(mp.c_str()); mf << j.str(); mf.flush(); mf.close();

    // 2b) exact decode context (POD blob) for bit-for-bit replay
    if (!m.ctx_blob.empty()) {
        std::string cp = tmp + "/decode_ctx.bin";
        FILE* cf = fopen(cp.c_str(), "wb");
        if (cf) {
            size_t w = fwrite(m.ctx_blob.data(), 1, m.ctx_blob.size(), cf);
            fflush(cf); fclose(cf);
            if (w != m.ctx_blob.size()) { n_diskerr_++; return; }
        } else { n_diskerr_++; return; }
    }

    // 3) atomic publish
    if (::rename(tmp.c_str(), fin.c_str()) != 0) { n_diskerr_++; return; }
    n_written_++;

    // 4) index row (writer thread only -> no lock needed)
    std::ofstream csv(csv_path_.c_str(), std::ios::app);
    csv << seq << "," << m.tti << "," << m.rnti << "," << m.mcs_idx << "," << m.L_prb << ","
        << m.rv << "," << m.energy_snr << "," << m.chest_sinr << "," << m.ta_us << ","
        << m.crc << "," << m.category << "," << iq.size() << "," << name << "\n";
}

void RawIQRecorder::shutdown()
{
    if (!started_) return;
    stop_.store(true);
    cv_.notify_all();
    if (writer_.joinable()) writer_.join();
    if (enabled_)
        printf("[IQREC] shutdown: %s\n", stats().c_str());
}

std::string RawIQRecorder::stats() const
{
    std::ostringstream s;
    s << "requested=" << n_requested_.load() << " written=" << n_written_.load()
      << " dropped_queue=" << n_dropped_queue_.load() << " disk_err=" << n_diskerr_.load()
      << " quota_used=" << quota_used_.load() << "/" << max_captures_;
    return s.str();
}
