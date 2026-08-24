#include "include/JSONEmitter.h"
#include "include/DCICollection.h"

#include <cstring>
#include <signal.h>
#include <sstream>
#include <iomanip>
#include <cmath>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

extern "C" {
#include "srsran/phy/phch/dci.h"
}

namespace {

const char* dci_format_name(srsran_dci_format_t fmt) {
    switch (fmt) {
        case SRSRAN_DCI_FORMAT0:  return "0";
        case SRSRAN_DCI_FORMAT1:  return "1";
        case SRSRAN_DCI_FORMAT1A: return "1A";
        case SRSRAN_DCI_FORMAT1B: return "1B";
        case SRSRAN_DCI_FORMAT1C: return "1C";
        case SRSRAN_DCI_FORMAT1D: return "1D";
        case SRSRAN_DCI_FORMAT2:  return "2";
        case SRSRAN_DCI_FORMAT2A: return "2A";
        case SRSRAN_DCI_FORMAT2B: return "2B";
        default:                  return "?";
    }
}

void append_rb_map(std::ostringstream& os, const std::vector<uint16_t>& map) {
    os << '[';
    bool first = true;
    for (uint16_t v : map) {
        if (!first) os << ',';
        first = false;
        os << static_cast<unsigned>(v);
    }
    os << ']';
}

void append_pwr_map(std::ostringstream& os, const std::vector<float>& map) {
    os << '[';
    bool first = true;
    for (float v : map) {
        if (!first) os << ',';
        first = false;
        if (std::isfinite(v)) {
            os << std::fixed << std::setprecision(2) << v;
        } else {
            os << "null";
        }
    }
    os << ']';
}

} // namespace

JSONEmitter::JSONEmitter(const std::string& path)
    : start_time(std::chrono::steady_clock::now()),
      // Default-constructed = clock epoch (zero duration since reference).
      // Earlier version used time_point::min() which made `now - last_rich_sf`
      // overflow nanoseconds → the >=20ms check returned false forever, so
      // the rich `sf` event NEVER fired (we only ever got `sf_tick`).
      last_rich_sf{}
{
    if (path.empty()) {
        return;
    }

    // Prevent the sniffer from dying if the GUI backend disconnects.
    ::signal(SIGPIPE, SIG_IGN);

    // Open the FIFO write-end with O_NONBLOCK so a stalled reader can never
    // wedge the sniffer. The reader (backend) opens the FIFO with O_RDONLY
    // before launching us, so the open(2) shouldn't block here either — but
    // O_NONBLOCK guarantees it.
    fd = ::open(path.c_str(), O_WRONLY | O_NONBLOCK);
    if (fd < 0) {
        std::fprintf(stderr, "[JSONEmitter] open('%s') failed: %s\n",
                     path.c_str(), std::strerror(errno));
        return;
    }
    fp = ::fdopen(fd, "w");
    if (!fp) {
        std::fprintf(stderr, "[JSONEmitter] fdopen failed: %s\n", std::strerror(errno));
        ::close(fd);
        fd = -1;
        return;
    }
    // Line-buffered so each event is visible to the reader immediately.
    std::setvbuf(fp, nullptr, _IOLBF, 0);
}

JSONEmitter::~JSONEmitter() {
    if (fp) {
        std::fclose(fp);   // closes fd too
        fp = nullptr;
        fd = -1;
    }
}

double JSONEmitter::elapsed() const {
    using namespace std::chrono;
    return duration<double>(steady_clock::now() - start_time).count();
}

std::string JSONEmitter::escapeString(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 2);
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b";  break;
            case '\f': out += "\\f";  break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out += c;
                }
        }
    }
    return out;
}

void JSONEmitter::writeLine(const std::string& line) {
    if (!fp || fd < 0) return;
    std::lock_guard<std::mutex> lock(mtx);

    // Single write+newline so we never split an event across two write(2)s.
    // Use write(2) directly to get clean EAGAIN semantics on a non-blocking
    // FIFO — stdio's buffering would mask backpressure.
    std::string payload = line;
    payload.push_back('\n');

    const char* buf = payload.data();
    size_t left = payload.size();
    while (left > 0) {
        ssize_t w = ::write(fd, buf, left);
        if (w > 0) {
            buf  += w;
            left -= static_cast<size_t>(w);
            continue;
        }
        if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            // Reader is slow / disconnected. Drop this event rather than
            // block. Operator sees the count in the next stats event.
            ++dropped_events;
            return;
        }
        if (w < 0 && errno == EINTR) {
            continue;
        }
        // EPIPE (reader gone), EBADF, ENOSPC, etc. — disable the emitter so
        // we don't keep error-spinning. The reader can come back next run.
        std::fclose(fp);
        fp = nullptr;
        fd = -1;
        return;
    }
}

void JSONEmitter::emitHello(const Args& args) {
    if (!fp) return;
    std::ostringstream os;
    os << std::fixed;
    os << "{\"t\":\"hello\",\"ts\":" << std::setprecision(6) << elapsed()
       << ",\"version\":1,\"args\":{"
       << "\"rf_freq\":"      << std::setprecision(1) << args.rf_freq
       << ",\"ul_freq\":"     << args.ul_freq
       << ",\"sniffer_mode\":"<< args.sniffer_mode
       << ",\"nof_prb\":"     << args.nof_prb
       << ",\"nof_threads\":" << args.nof_sniffer_thread
       << ",\"rnti\":"        << args.rnti
       << ",\"target_rnti\":" << args.target_rnti
       << ",\"cell_search\":" << (args.cell_search ? "true" : "false")
       << ",\"rf_args\":\""   << escapeString(args.rf_args) << "\""
       << ",\"rf_gain\":"     << std::setprecision(1) << args.rf_gain
       << ",\"nof_rx_ant\":"  << args.rf_nof_rx_ant
       << ",\"api_mode\":"    << args.api_mode
       << "}}";
    writeLine(os.str());
}

void JSONEmitter::emitCell(const srsran_cell_t& cell, double dl_freq, double ul_freq, double sample_rate) {
    if (!fp) return;
    std::ostringstream os;
    os << std::fixed;
    os << "{\"t\":\"cell\",\"ts\":" << std::setprecision(6) << elapsed()
       << ",\"pci\":"        << cell.id
       << ",\"nof_prb\":"    << cell.nof_prb
       << ",\"nof_ports\":"  << cell.nof_ports
       << ",\"cp\":\""       << (cell.cp == SRSRAN_CP_NORM ? "normal" : "extended") << "\""
       << ",\"mode\":\""     << (cell.frame_type == SRSRAN_FDD ? "FDD" : "TDD") << "\""
       << ",\"dl_freq\":"    << std::setprecision(1) << dl_freq
       << ",\"ul_freq\":"    << ul_freq
       << ",\"sample_rate\":"<< sample_rate
       << "}";
    writeLine(os.str());
}

void JSONEmitter::emitMIB(uint32_t sfn, int sfn_offset) {
    if (!fp) return;
    std::ostringstream os;
    os << std::fixed << std::setprecision(6);
    os << "{\"t\":\"mib\",\"ts\":" << elapsed()
       << ",\"sfn\":" << sfn
       << ",\"sfn_offset\":" << sfn_offset
       << "}";
    writeLine(os.str());
}

// Rich `sf` event capped at this rate (50 Hz). At real-LTE rates the cheap
// `sf_tick` still fires every subframe (1 kHz), so the operator never loses
// throughput counts — they just don't get the per-PRB heatmap at 1000 Hz.
static constexpr int RICH_SF_INTERVAL_MS = 20;

void JSONEmitter::emitSubframe(const SubframeInfo& info) {
    if (!fp) return;
    const DCICollection& coll = info.getDCICollection();
    const auto& dl = coll.getDCI_DL();
    const auto& ul = coll.getDCI_UL();

    // Decide cheap vs. rich. Rich path runs at most RICH_SF_INTERVAL_MS apart;
    // anything more frequent gets the lightweight `sf_tick`.
    using clock = std::chrono::steady_clock;
    auto now = clock::now();
    bool emit_rich;
    {
        std::lock_guard<std::mutex> lock(mtx);
        emit_rich = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_rich_sf).count()
                    >= RICH_SF_INTERVAL_MS;
        if (emit_rich) last_rich_sf = now;
    }

    if (!emit_rich) {
        std::ostringstream os;
        os << std::fixed << std::setprecision(6);
        os << "{\"t\":\"sf_tick\",\"ts\":" << elapsed()
           << ",\"sfn\":" << coll.get_sfn()
           << ",\"sf\":"  << coll.get_sf_idx()
           << ",\"cfi\":" << coll.get_cfi()
           << ",\"dl_n\":" << dl.size()
           << ",\"ul_n\":" << ul.size()
           << "}";
        writeLine(os.str());
        return;
    }

    std::ostringstream os;
    os << std::fixed << std::setprecision(6);
    os << "{\"t\":\"sf\",\"ts\":" << elapsed()
       << ",\"sfn\":" << coll.get_sfn()
       << ",\"sf\":"  << coll.get_sf_idx()
       << ",\"cfi\":" << coll.get_cfi();

    // DL DCIs
    os << ",\"dl\":[";
    bool first = true;
    for (const auto& d : dl) {
        if (!first) os << ',';
        first = false;
        os << "{\"rnti\":" << d.rnti
           << ",\"fmt\":\""<< dci_format_name(d.format) << "\""
           << ",\"mcs\":"  << (d.dl_grant ? d.dl_grant->mcs[0].idx : 0)
           << ",\"nprb\":" << (d.dl_grant ? d.dl_grant->nof_prb : 0)
           << ",\"tbs\":"  << (d.dl_grant ? d.dl_grant->mcs[0].tbs : 0)
           << ",\"ndi\":"  << (d.dl_dci_unpacked ? d.dl_dci_unpacked->ndi : 0)
           << ",\"harq\":" << (d.dl_dci_unpacked ? d.dl_dci_unpacked->harq_process : 0)
           << ",\"ncce\":" << d.location.ncce
           << ",\"L\":"    << d.location.L
           << ",\"hist\":" << d.histval
           << ",\"hex\":\""<< escapeString(d.hex) << "\""
           << "}";
    }
    os << "]";

    // UL DCIs
    os << ",\"ul\":[";
    first = true;
    for (const auto& d : ul) {
        if (!first) os << ',';
        first = false;
        os << "{\"rnti\":" << d.rnti
           << ",\"fmt\":\"0\""
           << ",\"mcs\":"  << (d.ul_grant ? d.ul_grant->mcs.idx : 0)
           << ",\"nprb\":" << (d.ul_grant ? d.ul_grant->L_prb : 0)
           << ",\"tbs\":"  << (d.ul_grant ? d.ul_grant->mcs.tbs : 0)
           << ",\"ndi\":"  << (d.ul_dci_unpacked ? d.ul_dci_unpacked->ndi : 0)
           << ",\"ncce\":" << d.location.ncce
           << ",\"L\":"    << d.location.L
           << ",\"hist\":" << d.histval
           << ",\"hex\":\""<< escapeString(d.hex) << "\""
           << "}";
    }
    os << "]";

    // RB maps
    os << ",\"rb_dl\":";
    append_rb_map(os, coll.getRBMapDL());
    os << ",\"rb_ul\":";
    append_rb_map(os, coll.getRBMapUL());

    // Power
    const SubframePower& pw = info.getSubframePower();
    os << ",\"pwr_dl\":";
    append_pwr_map(os, pw.getRBPowerDL());
    if (std::isfinite(pw.getMin()) && std::isfinite(pw.getMax())) {
        os << ",\"pwr_min\":" << std::setprecision(2) << pw.getMin()
           << ",\"pwr_max\":" << pw.getMax();
    }

    os << "}";
    writeLine(os.str());
}

void JSONEmitter::emitLog(const char* level, const std::string& msg) {
    if (!fp) return;
    std::ostringstream os;
    os << std::fixed << std::setprecision(6);
    os << "{\"t\":\"log\",\"ts\":" << elapsed()
       << ",\"level\":\"" << (level ? level : "info") << "\""
       << ",\"msg\":\""   << escapeString(msg) << "\"}";
    writeLine(os.str());
}

void JSONEmitter::emitStats(uint32_t sfn, uint32_t sf_processed, uint32_t sf_skipped,
                            uint32_t nof_rnti, uint32_t rb_dl_total, uint32_t rb_ul_total,
                            float cfo_hz) {
    if (!fp) return;
    std::ostringstream os;
    os << std::fixed << std::setprecision(6);
    os << "{\"t\":\"stats\",\"ts\":" << elapsed()
       << ",\"sfn\":"          << sfn
       << ",\"sf_processed\":" << sf_processed
       << ",\"sf_skipped\":"   << sf_skipped
       << ",\"nof_rnti\":"     << nof_rnti
       << ",\"rb_dl_total\":"  << rb_dl_total
       << ",\"rb_ul_total\":"  << rb_ul_total
       << ",\"cfo_hz\":"       << std::setprecision(1) << cfo_hz
       << ",\"dropped_events\":" << dropped_events
       << "}";
    writeLine(os.str());
}

void JSONEmitter::emitIdentity(uint32_t sfn, const char* kind, uint16_t rnti,
                               const std::string& value, const std::string& from) {
    if (!fp) return;
    std::ostringstream os;
    os << std::fixed << std::setprecision(6);
    os << "{\"t\":\"identity\",\"ts\":" << elapsed()
       << ",\"sfn\":"  << sfn
       << ",\"kind\":\""<< (kind ? kind : "") << "\""
       << ",\"rnti\":" << rnti
       << ",\"value\":\""<< escapeString(value) << "\""
       << ",\"from\":\""<< escapeString(from) << "\""
       << "}";
    writeLine(os.str());
}

void JSONEmitter::emitBye(const std::string& reason) {
    if (!fp) return;
    std::ostringstream os;
    os << std::fixed << std::setprecision(6);
    os << "{\"t\":\"bye\",\"ts\":" << elapsed()
       << ",\"reason\":\"" << escapeString(reason) << "\"}";
    writeLine(os.str());
}
