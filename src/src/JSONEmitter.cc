#include "include/JSONEmitter.h"
#include "include/DCICollection.h"

#include <cstring>
#include <signal.h>
#include <sstream>
#include <iomanip>
#include <cmath>

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
    : start_time(std::chrono::steady_clock::now())
{
    if (path.empty()) {
        return;
    }

    // Prevent the sniffer from dying if the GUI backend disconnects.
    ::signal(SIGPIPE, SIG_IGN);

    fp = std::fopen(path.c_str(), "w");
    if (!fp) {
        std::fprintf(stderr, "[JSONEmitter] Failed to open '%s'; JSON output disabled.\n",
                     path.c_str());
        return;
    }
    // Line-buffered so each event is visible to the reader immediately.
    std::setvbuf(fp, nullptr, _IOLBF, 0);
}

JSONEmitter::~JSONEmitter() {
    if (fp) {
        std::fclose(fp);
        fp = nullptr;
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
    if (!fp) return;
    std::lock_guard<std::mutex> lock(mtx);
    if (std::fputs(line.c_str(), fp) == EOF) {
        std::fclose(fp);
        fp = nullptr;
        return;
    }
    std::fputc('\n', fp);
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

void JSONEmitter::emitSubframe(const SubframeInfo& info) {
    if (!fp) return;
    const DCICollection& coll = info.getDCICollection();
    const auto& dl = coll.getDCI_DL();
    const auto& ul = coll.getDCI_UL();

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
