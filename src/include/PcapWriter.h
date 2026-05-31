/*
 * LTE DL_Snifer version 1.0
 * 
 */
#pragma once

#include "srsran/common/mac_pcap.h"
#include "srsran/common/pcap.h"
using namespace srsran;

class PcapWriter //not using now
{
public:
    PcapWriter(/* args */);
    ~PcapWriter();
    void pcap_set_up_file(std::string file_name);
    void pcap_close_file();
    void pcap_write_sib(uint8_t* pdu, uint32_t pdu_len_bytes, bool crc_ok, uint32_t tti, uint8_t cc_idx);
    void pcap_write_paging(uint8_t* pdu, uint32_t pdu_len_bytes, bool crc_ok, uint32_t tti, uint8_t cc_idx);
    void pcap_write_rar(uint8_t* pdu, uint32_t pdu_len_bytes, uint16_t ranti, bool crc_ok, uint32_t tti, uint8_t cc_idx);
    void pcap_write_crnti(uint8_t* pdu, uint32_t pdu_len_bytes, uint16_t crnti, bool crc_ok, uint32_t tti, uint8_t cc_idx);
private:
    std::string filename = "testpcap.pcap"; //random pcap file
    mac_pcap pcapwriter;
    std::mutex pcapmutex;
};

// Define a new class for not creating a new thread of pcap
class LTESniffer_pcap_writer
{
public:
    LTESniffer_pcap_writer() {enable_write=false; ue_id=0; pcap_file = NULL; };
    void enable(bool en);
    void open(const std::string filename, const std::string api_filename, uint32_t ue_id = 0);
    void close();

    // Rotation knobs (opt-in via env vars LTESNIFFER_PCAP_ROTATE_MB /
    // LTESNIFFER_PCAP_ROTATE_MIN at open() time). Long captures otherwise
    // produce one multi-GB file that's a pain to ship around.
    void configure_rotation(size_t bytes, int minutes);

    // Live PCAP-over-FIFO for Wireshark (F12). Opt-in via env var
    // LTESNIFFER_PCAP_STREAM=/path/to/named-pipe. User runs
    //   mkfifo /tmp/lte.pcap && wireshark -k -i /tmp/lte.pcap
    // and frames stream live (libpcap global header on connect, then per-PDU
    // records — identical wire format to the on-disk pcap, just on a FIFO).

    void set_ue_id(uint16_t ue_id);

    void write_dl_crnti(uint8_t *pdu, uint32_t pdu_len_bytes, uint16_t crnti, bool crc_ok, uint32_t tti, bool retx); //C RNTI
    void write_dl_ranti(uint8_t *pdu, uint32_t pdu_len_bytes, uint16_t ranti, bool crc_ok, uint32_t tti);
    
    // SI and BCH only for DL 
    void write_dl_sirnti(uint8_t *pdu, uint32_t pdu_len_bytes, bool crc_ok, uint32_t tti); //SI
    void write_dl_bch(uint8_t *pdu, uint32_t pdu_len_bytes, bool crc_ok, uint32_t tti); // mib
    void write_dl_pch(uint8_t *pdu, uint32_t pdu_len_bytes, bool crc_ok, uint32_t tti); //paging
    void write_ul_crnti(uint8_t* pdu, uint32_t pdu_len_bytes, uint16_t crnti, uint32_t tti);
    
    /*Function for api*/
    void write_ul_crnti_api(uint8_t* pdu, uint32_t pdu_len_bytes, uint16_t crnti, uint32_t tti);
    void write_dl_crnti_api(uint8_t *pdu, uint32_t pdu_len_bytes, uint16_t crnti, bool crc_ok, uint32_t tti, bool retx); //C RNTI
    void write_dl_paging_api(uint8_t* pdu, uint32_t pdu_len_bytes, uint16_t rnti, bool crc_ok, uint32_t tti, bool retx);
private:
    std::mutex pcap_mutex;
    bool enable_write;
    FILE *pcap_file;
    FILE *pcap_file_api;
    uint32_t ue_id;

    // Rotation state. base_filename_ is the original `-F` value; we rewrite
    // it with an ISO8601 timestamp + sequence number on each rotation.
    std::string base_filename_;
    std::string api_filename_;
    size_t      rotate_bytes_ = 0;   // 0 = disabled
    int         rotate_minutes_ = 0; // 0 = disabled
    size_t      bytes_written_ = 0;
    int         rotation_seq_ = 0;
    long long   file_opened_ms_ = 0; // monotonic ms since epoch
    // Periodic-flush counters (in writes, not bytes). Previously the flush
    // condition was `(bytes_written_ & 63) == 0`, which actually fires only
    // when bytes_written_ happens to be a multiple of 64 — for irregular PDU
    // sizes that's stochastic (~1/64 chance per write) and can be zero for an
    // entire low-volume capture. Real counters make it deterministic.
    uint32_t    writes_since_flush_      = 0;
    uint32_t    writes_since_flush_api_  = 0;
    static constexpr uint32_t FLUSH_EVERY_N_WRITES = 64;
    void rotate_if_needed_locked();
    std::string make_rotated_name(const std::string& base);

    // Live-stream FIFO for Wireshark. pcap_stream_file_ is the open write end
    // (null until a reader attaches); pcap_stream_path_ remembers the target so
    // the write path can lazily (re)open it if Wireshark is launched after the
    // capture starts. stream_last_attempt_ms_ throttles those retry opens.
    FILE*       pcap_stream_file_       = nullptr;
    std::string pcap_stream_path_;            // LTESNIFFER_PCAP_STREAM; empty = disabled
    long long   stream_last_attempt_ms_ = 0;  // monotonic ms of last (re)open attempt
    bool        stream_open_warned_     = false; // log non-ENXIO open errors once
    // Try to open pcap_stream_path_ O_WRONLY|O_NONBLOCK and write the libpcap
    // global header on success. No-op if already open or streaming disabled.
    // ENXIO (no reader yet) is silent so the periodic retry can pick it up.
    void try_open_stream_locked();

    void pack_and_write(uint8_t* pdu, uint32_t pdu_len_bytes, uint32_t reTX, bool crc_ok, uint32_t tti,
                                uint16_t crnti_, uint8_t direction, uint8_t rnti_type);

    void pack_and_write_api(uint8_t* pdu, uint32_t pdu_len_bytes, uint32_t reTX, bool crc_ok, uint32_t tti,
                                uint16_t crnti_, uint8_t direction, uint8_t rnti_type);
};