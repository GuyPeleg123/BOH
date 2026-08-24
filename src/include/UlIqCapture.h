/* UlIqCapture — on-disk format shared by the live recorder (UL_Sniffer_PUSCH)
 * and the offline replay tool (ul_iq_replay).
 *
 * A capture directory contains:
 *   uplink_cf32.iq   raw pre-FFT UL samples, interleaved little-endian f32 I,Q
 *   metadata.json    human-readable metadata (RawIQRecorder)
 *   decode_ctx.bin   the EXACT srsran decode context the live decoder used
 *
 * decode_ctx.bin is a single POD DecodeCtxBlob written verbatim. It captures the
 * precise grant / DMRS / hopping / UCI configuration so the replay tool can
 * reconstruct the decode bit-for-bit — this is what makes replay equivalence a
 * true identity rather than an approximation. All members are POD (no pointers):
 * softbuffers are NOT stored; the replay tool allocates fresh ones.
 */
#ifndef UL_IQ_CAPTURE_H
#define UL_IQ_CAPTURE_H

#include <cstdint>
#include "srsran/srsran.h"

#define UL_IQ_CTX_MAGIC   0x554C4951u   /* "ULIQ" */
#define UL_IQ_CTX_VERSION 2u            /* v2 adds live_payload_hash (FNV-1a) */

/* FNV-1a 64-bit — shared by recorder and replay so the live payload hash and the
 * replay payload hash are directly comparable (byte-exact payload equivalence). */
static inline uint64_t ul_iq_fnv1a(const void* p, unsigned long n)
{
    const unsigned char* b = (const unsigned char*)p;
    uint64_t h = 1469598103934665603ULL;
    for (unsigned long i = 0; i < n; i++) { h ^= b[i]; h *= 1099511628211ULL; }
    return h;
}

#pragma pack(push, 8)
typedef struct {
    uint32_t magic;
    uint32_t version;

    // Cell (enough to init srsran_enb_ul_t exactly as the live path did)
    int32_t  cell_id;
    int32_t  nof_prb;
    int32_t  cp;          // srsran_cp_t
    int32_t  nof_ports;

    // Subframe + PUSCH identity
    uint32_t tti;
    uint16_t rnti;
    uint16_t _pad0;
    int32_t  enable_64qam;

    // Exact decode configuration (all POD)
    srsran_pusch_grant_t              grant;
    srsran_refsignal_dmrs_pusch_cfg_t dmrs;
    srsran_pusch_hopping_cfg_t        hopping;
    srsran_uci_cfg_t                  uci_cfg;
    srsran_uci_offset_cfg_t           uci_offset;

    // Live outcome, for the replay equivalence assertion
    int32_t  live_crc;
    float    live_snr_db;
    float    live_ta_us;
    float    live_noise_estimate;
    uint64_t live_payload_hash;   // v2+: FNV-1a of the decoded TB (tbs/8 bytes), 0 if CRC failed
} DecodeCtxBlob;
#pragma pack(pop)

#endif // UL_IQ_CAPTURE_H
