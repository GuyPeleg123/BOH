#pragma once

#include "ArgManager.h"
#include "SubframeInfoConsumer.h"
#include "SubframeInfo.h"

#include <chrono>
#include <cstdio>
#include <mutex>
#include <string>

#include "srsran/srsran.h"

/**
 * JSONEmitter — single-writer, thread-safe newline-delimited JSON emitter
 * used by the GUI backend. Writes to a file path (typically a FIFO) provided
 * via the -J CLI flag.
 *
 * Disabled by default; isOpen() returns false unless a path was supplied,
 * in which case all emit* calls become no-ops.
 *
 * Schema documented in gui/PROTOCOL.md.
 */
class JSONEmitter {
public:
    explicit JSONEmitter(const std::string& path);
    ~JSONEmitter();

    JSONEmitter(const JSONEmitter&)            = delete;
    JSONEmitter& operator=(const JSONEmitter&) = delete;

    bool isOpen() const { return fp != nullptr; }

    // Lines dropped because the FIFO writer would have blocked (EAGAIN).
    // Surfaced in the next stats event so the operator knows the rate at
    // which events are being lost on backpressure.
    uint64_t droppedEvents() const { return dropped_events; }
    void     resetDroppedEvents()  { dropped_events = 0; }

    void emitHello(const Args& args);
    void emitCell(const srsran_cell_t& cell, double dl_freq, double ul_freq, double sample_rate);
    void emitMIB(uint32_t sfn, int sfn_offset);

    // Emit *one* of:
    //   - sf_tick (cheap: ts, sfn, sf, cfi, dl_n, ul_n) — every subframe
    //   - sf       (rich: + dl[], ul[], rb_dl[], rb_ul[], pwr_dl[]) — at most
    //              every RICH_SF_INTERVAL_MS, so the frontend can render rate
    //              from the cheap event and detail from the rich one.
    // Both share the same DCIToJSON entry point; throttling is internal here.
    void emitSubframe(const SubframeInfo& info);

    void emitLog(const char* level, const std::string& msg);
    void emitStats(uint32_t sfn, uint32_t sf_processed, uint32_t sf_skipped,
                   uint32_t nof_rnti, uint32_t rb_dl_total, uint32_t rb_ul_total,
                   float cfo_hz);
    void emitIdentity(uint32_t sfn, const char* kind, uint16_t rnti,
                      const std::string& value, const std::string& from);
    void emitBye(const std::string& reason);

private:
    void writeLine(const std::string& line);
    double elapsed() const;
    static std::string escapeString(const std::string& s);

    std::mutex mtx;
    FILE*      fp = nullptr;
    int        fd = -1;          // raw fd; kept so we can fcntl O_NONBLOCK and write(2) without stdio backpressure
    uint64_t   dropped_events = 0;
    std::chrono::steady_clock::time_point start_time;
    std::chrono::steady_clock::time_point last_rich_sf;  // last time a rich sf event was emitted
};

/**
 * DCIToJSON adapts the JSONEmitter to the SubframeInfoConsumer interface,
 * so it can be registered alongside the existing DCIToFile / DCIDrawASCII.
 */
class DCIToJSON : public SubframeInfoConsumer {
public:
    explicit DCIToJSON(JSONEmitter& emitter_) : emitter(emitter_) {}
    void consumeDCICollection(const SubframeInfo& info) override {
        emitter.emitSubframe(info);
    }

private:
    JSONEmitter& emitter;
};
