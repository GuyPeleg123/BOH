#include "include/PcapWriter.h"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <cstring>
#include <cerrno>

PcapWriter::PcapWriter(/* args */)
{

}

PcapWriter::~PcapWriter()
{
}

void PcapWriter::pcap_set_up_file(std::string file_name)
{
    filename = file_name;
    pcapwriter.open(filename);
}

void PcapWriter::pcap_close_file()
{
    pcapwriter.close();
}

void PcapWriter::pcap_write_sib(uint8_t* pdu, 
                               uint32_t pdu_len_bytes, 
                               bool crc_ok, 
                               uint32_t tti, 
                               uint8_t cc_idx)
{
    std::unique_lock<std::mutex> lock(pcapmutex);
    pcapwriter.write_dl_sirnti(pdu, pdu_len_bytes, crc_ok, tti, cc_idx);
    lock.unlock();
}

void PcapWriter::pcap_write_paging(uint8_t* pdu, 
                                  uint32_t pdu_len_bytes, 
                                  bool crc_ok, 
                                  uint32_t tti, 
                                  uint8_t cc_idx)
{
    std::unique_lock<std::mutex> lock(pcapmutex);
    pcapwriter.write_dl_pch(pdu, pdu_len_bytes, crc_ok, tti, cc_idx);
    lock.unlock();
}

void PcapWriter::pcap_write_rar(uint8_t* pdu, 
                               uint32_t pdu_len_bytes, 
                               uint16_t ranti, 
                               bool crc_ok, 
                               uint32_t tti, 
                               uint8_t cc_idx)
{
    std::unique_lock<std::mutex> lock(pcapmutex);
    pcapwriter.write_dl_ranti(pdu, pdu_len_bytes, ranti, crc_ok, tti, cc_idx);
    lock.unlock();
}

void PcapWriter::pcap_write_crnti(uint8_t* pdu, 
                                  uint32_t pdu_len_bytes, 
                                  uint16_t crnti, 
                                  bool crc_ok, 
                                  uint32_t tti, 
                                  uint8_t cc_idx)
{
    std::unique_lock<std::mutex> lock(pcapmutex);
    pcapwriter.write_dl_crnti(pdu, pdu_len_bytes, crnti, crc_ok, tti, cc_idx);
    lock.unlock();
}


//New class:
void LTESniffer_pcap_writer::enable(bool en)
{
  enable_write = en;   // was hardcoded true -> could never be disabled
}
void LTESniffer_pcap_writer::open(const std::string filename, const std::string api_filename, uint32_t ue_id)
{
  // Pick up rotation knobs from env so the GUI / operator can enable without
  // a CLI flag rebuild. Default disabled → identical behaviour to before.
  if (const char* mb = std::getenv("LTESNIFFER_PCAP_ROTATE_MB")) {
    long v = std::strtol(mb, nullptr, 10);
    if (v > 0) rotate_bytes_ = static_cast<size_t>(v) * 1024 * 1024;
  }
  if (const char* mn = std::getenv("LTESNIFFER_PCAP_ROTATE_MIN")) {
    long v = std::strtol(mn, nullptr, 10);
    if (v > 0) rotate_minutes_ = static_cast<int>(v);
  }
  base_filename_  = filename;
  api_filename_   = api_filename;

  std::string first_name = (rotate_bytes_ || rotate_minutes_)
                             ? make_rotated_name(filename)
                             : filename;

  pcap_file       = DLT_PCAP_Open(MAC_LTE_DLT, first_name.c_str());
  pcap_file_api   = DLT_PCAP_Open(MAC_LTE_DLT, api_filename.c_str());
  // Flush the global PCAP headers immediately so the files are non-zero on
  // disk from the very first moment — without this, stdio buffering keeps
  // the 24-byte header in userspace memory until the buffer fills (8 KB) or
  // fclose() is called, making the files appear empty while sniffing.
  if (pcap_file)     std::fflush(pcap_file);
  if (pcap_file_api) std::fflush(pcap_file_api);
  this->ue_id              = ue_id;
  enable_write             = true;
  bytes_written_           = 0;
  writes_since_flush_      = 0;
  writes_since_flush_api_  = 0;
  file_opened_ms_ = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::steady_clock::now().time_since_epoch()).count();
  if (rotate_bytes_ || rotate_minutes_) {
    fprintf(stderr, "[PcapWriter] rotation: %zu MB / %d min, first file: %s\n",
            rotate_bytes_ / (1024*1024), rotate_minutes_, first_name.c_str());
  }

  // Live-stream FIFO for Wireshark (opt-in via env). Open non-blocking so a
  // missing/unread FIFO doesn't wedge the capture; ignore SIGPIPE in case
  // Wireshark goes away mid-capture.
  if (const char* stream_path = std::getenv("LTESNIFFER_PCAP_STREAM")) {
    ::signal(SIGPIPE, SIG_IGN);
    int sfd = ::open(stream_path, O_WRONLY | O_NONBLOCK);
    if (sfd >= 0) {
      pcap_stream_file_ = ::fdopen(sfd, "wb");
      if (pcap_stream_file_) {
        // libpcap global header for MAC-LTE DLT (147).
        struct {
          uint32_t magic; uint16_t v_major, v_minor;
          int32_t  thiszone; uint32_t sigfigs;
          uint32_t snaplen; uint32_t linktype;
        } hdr = { 0xa1b2c3d4, 2, 4, 0, 0, 65535, 147 };
        std::fwrite(&hdr, sizeof(hdr), 1, pcap_stream_file_);
        std::fflush(pcap_stream_file_);
        fprintf(stderr, "[PcapWriter] live stream → %s (open in Wireshark with -k -i %s)\n",
                stream_path, stream_path);
      } else {
        ::close(sfd);
      }
    } else {
      fprintf(stderr, "[PcapWriter] stream FIFO open '%s' failed: %s "
                       "(create it first with: mkfifo %s)\n",
              stream_path, std::strerror(errno), stream_path);
    }
  }
}

void LTESniffer_pcap_writer::configure_rotation(size_t bytes, int minutes)
{
  rotate_bytes_   = bytes;
  rotate_minutes_ = minutes;
}

std::string LTESniffer_pcap_writer::make_rotated_name(const std::string& base)
{
  // Insert "_<iso8601>_<seq>" before the extension.
  rotation_seq_++;
  std::time_t now = std::time(nullptr);
  char buf[32];
  std::strftime(buf, sizeof(buf), "%Y%m%dT%H%M%S", std::gmtime(&now));
  std::string out = base;
  auto dot = out.find_last_of('.');
  std::string stem = (dot == std::string::npos) ? out : out.substr(0, dot);
  std::string ext  = (dot == std::string::npos) ? ".pcap" : out.substr(dot);
  char seq[8]; std::snprintf(seq, sizeof(seq), "%03d", rotation_seq_);
  return stem + "_" + buf + "_" + seq + ext;
}

void LTESniffer_pcap_writer::rotate_if_needed_locked()
{
  if (!(rotate_bytes_ || rotate_minutes_)) return;
  bool by_bytes = rotate_bytes_ && bytes_written_ >= rotate_bytes_;
  bool by_time  = false;
  long long now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::steady_clock::now().time_since_epoch()).count();
  if (rotate_minutes_) {
    long long limit_ms = static_cast<long long>(rotate_minutes_) * 60 * 1000;
    by_time = (now_ms - file_opened_ms_) >= limit_ms;
  }
  if (!by_bytes && !by_time) return;

  DLT_PCAP_Close(pcap_file);
  std::string next = make_rotated_name(base_filename_);
  pcap_file = DLT_PCAP_Open(MAC_LTE_DLT, next.c_str());
  bytes_written_      = 0;
  writes_since_flush_ = 0;
  file_opened_ms_     = now_ms;
  fprintf(stderr, "[PcapWriter] rotated -> %s (reason=%s)\n",
          next.c_str(), by_bytes ? "size" : "time");
}

void LTESniffer_pcap_writer::close()
{
  fprintf(stdout, "Saving MAC PCAP file\n");
  DLT_PCAP_Close(pcap_file);
  // api_collector.pcap was never closed — its stdio buffer was silently
  // discarded on process exit.  Close it explicitly here.
  DLT_PCAP_Close(pcap_file_api);
  pcap_file     = nullptr;
  pcap_file_api = nullptr;
  if (pcap_stream_file_) {
    std::fclose(pcap_stream_file_);
    pcap_stream_file_ = nullptr;
  }
}

void LTESniffer_pcap_writer::set_ue_id(uint16_t ue_id) {
  this->ue_id = ue_id;
}

void LTESniffer_pcap_writer::pack_and_write(uint8_t* pdu, uint32_t pdu_len_bytes, uint32_t reTX, bool crc_ok, uint32_t tti, 
                              uint16_t crnti, uint8_t direction, uint8_t rnti_type)
{

  std::unique_lock<std::mutex> lock(pcap_mutex);
  if (enable_write) {
    MAC_Context_Info_t        context;
    context.direction       = direction;
    context.rntiType        = rnti_type;
    context.sysFrameNumber  = (uint16_t)(tti/10);
    context.subFrameNumber  = (uint16_t)(tti%10);
    context.rnti            = crnti;
    context.ueid            = (uint16_t)ue_id;
    context.isRetx          = (uint8_t)reTX;
    context.crcStatusOK     = crc_ok;
    context.radioType       = FDD_RADIO;
    context.isRetx          = reTX;
    context.nbiotMode       = 0;
    context.cc_idx          = 0;

    if (pdu && pcap_file) {   // null-check: a failed DLT_PCAP_Open must not crash on write
      rotate_if_needed_locked();
      LTE_PCAP_MAC_WritePDU(pcap_file, &context, pdu, pdu_len_bytes);
      bytes_written_ += pdu_len_bytes + 64;  // ~header overhead estimate (used by rotation)
      // Flush every FLUSH_EVERY_N_WRITES PDUs so data reaches disk during an
      // active capture even if the process is later killed before fclose()
      // runs. This used to be `(bytes_written_ & 63) == 0`, which only fires
      // when bytes_written_ is a multiple of 64 — a stochastic ~1/64 event,
      // and effectively never for low-volume writers like UL PUSCH.
      if (pcap_file && ++writes_since_flush_ >= FLUSH_EVERY_N_WRITES) {
        std::fflush(pcap_file);
        writes_since_flush_ = 0;
      }
      // Mirror to live-stream FIFO if open. Same writer, different FILE*.
      // If the reader's gone away we'll get EPIPE/EBADF — close + null out
      // so subsequent writes are no-ops.
      if (pcap_stream_file_) {
        if (LTE_PCAP_MAC_WritePDU(pcap_stream_file_, &context, pdu, pdu_len_bytes) < 0) {
          std::fclose(pcap_stream_file_);
          pcap_stream_file_ = nullptr;
        }
      }
    }
  }
  lock.unlock();
}

void LTESniffer_pcap_writer::pack_and_write_api(uint8_t* pdu, uint32_t pdu_len_bytes, uint32_t reTX, bool crc_ok, uint32_t tti,
                              uint16_t crnti, uint8_t direction, uint8_t rnti_type)
{

  std::unique_lock<std::mutex> lock(pcap_mutex);
  if (enable_write) {
    MAC_Context_Info_t        context;
    context.direction       = direction;
    context.rntiType        = rnti_type;
    context.sysFrameNumber  = (uint16_t)(tti/10);
    context.subFrameNumber  = (uint16_t)(tti%10);
    context.rnti            = crnti;
    context.ueid            = (uint16_t)ue_id;
    context.isRetx          = (uint8_t)reTX;
    context.crcStatusOK     = crc_ok;
    context.radioType       = FDD_RADIO;
    context.isRetx          = reTX;
    context.nbiotMode       = 0;
    context.cc_idx          = 0;

    if (pdu && pcap_file_api) {
      LTE_PCAP_MAC_WritePDU(pcap_file_api, &context, pdu, pdu_len_bytes);
      // Same periodic flush as the main pcap — without it, api_collector.pcap
      // could silently lose every packet on SIGKILL.
      if (pcap_file_api && ++writes_since_flush_api_ >= FLUSH_EVERY_N_WRITES) {
        std::fflush(pcap_file_api);
        writes_since_flush_api_ = 0;
      }
    }
  }
  lock.unlock();
}

void LTESniffer_pcap_writer::write_dl_crnti(uint8_t* pdu, uint32_t pdu_len_bytes, uint16_t rnti, bool crc_ok, uint32_t tti, bool retx)
{
  pack_and_write(pdu, pdu_len_bytes, retx, crc_ok, tti, rnti, DIRECTION_DOWNLINK, C_RNTI);
}

void LTESniffer_pcap_writer::write_dl_ranti(uint8_t* pdu, uint32_t pdu_len_bytes, uint16_t rnti, bool crc_ok, uint32_t tti)
{
  pack_and_write(pdu, pdu_len_bytes, 0, crc_ok, tti, rnti, DIRECTION_DOWNLINK, RA_RNTI);
}

void LTESniffer_pcap_writer::write_dl_bch(uint8_t* pdu, uint32_t pdu_len_bytes, bool crc_ok, uint32_t tti)
{
  pack_and_write(pdu, pdu_len_bytes, 0, crc_ok, tti, 0, DIRECTION_DOWNLINK, NO_RNTI);
}

void LTESniffer_pcap_writer::write_dl_pch(uint8_t* pdu, uint32_t pdu_len_bytes, bool crc_ok, uint32_t tti)
{
  pack_and_write(pdu, pdu_len_bytes, 0, crc_ok, tti, SRSRAN_PRNTI, DIRECTION_DOWNLINK, P_RNTI);
}

void LTESniffer_pcap_writer::write_dl_sirnti(uint8_t* pdu, uint32_t pdu_len_bytes, bool crc_ok, uint32_t tti)
{
  pack_and_write(pdu, pdu_len_bytes, 0, crc_ok, tti, SRSRAN_SIRNTI, DIRECTION_DOWNLINK, SI_RNTI);
}

void LTESniffer_pcap_writer::write_ul_crnti(uint8_t* pdu, uint32_t pdu_len_bytes, uint16_t crnti, uint32_t tti)
{
  pack_and_write(pdu, pdu_len_bytes, 0, true, tti, crnti, DIRECTION_UPLINK, C_RNTI);
}

void LTESniffer_pcap_writer::write_ul_crnti_api(uint8_t* pdu, uint32_t pdu_len_bytes, uint16_t crnti, uint32_t tti)
{
  pack_and_write_api(pdu, pdu_len_bytes, 0, true, tti, crnti, DIRECTION_UPLINK, C_RNTI);
}

void LTESniffer_pcap_writer::write_dl_crnti_api(uint8_t* pdu, uint32_t pdu_len_bytes, uint16_t rnti, bool crc_ok, uint32_t tti, bool retx)
{
  pack_and_write_api(pdu, pdu_len_bytes, retx, crc_ok, tti, rnti, DIRECTION_DOWNLINK, C_RNTI);
}

void LTESniffer_pcap_writer::write_dl_paging_api(uint8_t* pdu, uint32_t pdu_len_bytes, uint16_t rnti, bool crc_ok, uint32_t tti, bool retx)
{
  pack_and_write_api(pdu, pdu_len_bytes, retx, crc_ok, tti, SRSRAN_PRNTI, DIRECTION_DOWNLINK, P_RNTI);
}
