#pragma once

#include <cstdint>
#include <map>
#include <mutex>
#include <string>

#include "srsran/common/security.h"

using namespace srsran;

// Per-bearer PDCP sliding-window state (one per SRB/DRB per UE)
struct PdcpBearerState {
    uint32_t hfn        = 0;
    uint32_t last_sn    = UINT32_MAX;   // sentinel: "no packet seen yet"
    uint8_t  sn_bits    = 0;            // 5 for SRB, 12 for DRB
};

// All security material for one UE (keyed by RNTI)
struct UESecurityState {
    uint8_t  k_enb[32]     = {};
    uint8_t  kasme[32]     = {};
    uint8_t  k_rrc_enc[32] = {};
    uint8_t  k_rrc_int[32] = {};
    uint8_t  k_up_enc[32]  = {};

    CIPHERING_ALGORITHM_ID_ENUM cipher_algo = CIPHERING_ALGORITHM_ID_EEA0;
    INTEGRITY_ALGORITHM_ID_ENUM integ_algo  = INTEGRITY_ALGORITHM_ID_EIA0;

    bool has_kenb        = false;
    bool keys_derived    = false;  // sub-keys ready (algo known)
    bool security_active = false;  // ciphering is on

    uint32_t hfn_hint    = 0;      // starting HFN guess for mid-session join

    // Bearer states: SRBs indexed by LCID (1,2), DRBs indexed by LCID (3+)
    std::map<uint8_t, PdcpBearerState> srb;
    std::map<uint8_t, PdcpBearerState> drb;
};

/*
 * KeyStore – loads a JSON key file, drives per-RNTI security state, and
 * performs PDCP decryption.  Thread-safe (all public methods hold mtx_).
 *
 * JSON format (array of objects):
 *   [
 *     {
 *       "rnti"     : "0x1234",        // C-RNTI in hex
 *       "kenb"     : "<64 hex chars>", // 256-bit K_eNB
 *       "kasme"    : "<64 hex chars>", // 256-bit KASME (stored for future use)
 *       "hfn_hint" : 0                // optional starting HFN (default 0)
 *     }
 *   ]
 */
class KeyStore {
public:
    // Load and parse the JSON key file.  Returns false on error.
    bool load(const std::string& json_path);

    // Returns true if we have key material for this RNTI.
    bool has_ue(uint16_t rnti);

    // Called when SecurityModeCommand is decoded from an unencrypted RRC message.
    // Derives KRRCenc, KRRCint, KUPenc from K_eNB + the negotiated algorithms.
    void set_security_algo(uint16_t rnti,
                           CIPHERING_ALGORITHM_ID_ENUM cipher,
                           INTEGRITY_ALGORITHM_ID_ENUM integ);

    // Called when SecurityModeCommand is seen — ciphering starts on next DL SDU.
    void activate_security(uint16_t rnti);

    // True after activate_security() has been called for this RNTI.
    bool is_security_active(uint16_t rnti);

    // Open output pcap files derived from base_path:
    //   base_path + "_decrypted_ip.pcap"   — raw IPv4/IPv6 from DRBs
    // Returns false if the file cannot be opened.
    bool open_output(const std::string& base_path);
    void close_output();

    // Process one decoded MAC PDU.  Parses the MAC sub-headers, identifies
    // SRBs (LCID 1,2) and DRBs (LCID 3+), and attempts PDCP decryption for
    // each when security is active.
    void process_dl_mac_pdu(uint16_t rnti, uint8_t* mac_pdu,
                             uint32_t mac_pdu_len, uint32_t tti);

private:
    std::map<uint16_t, UESecurityState> states_;
    std::mutex mtx_;
    FILE* ip_pcap_fd_ = nullptr;

    // Write pcap global header to fd (DLT=101 raw IP).
    static void write_pcap_global_hdr(FILE* fd);
    // Write one raw-IP packet record.
    void write_ip_pkt(const uint8_t* pkt, uint32_t len, uint32_t tti);

    // Decrypt SRB PDU (LCID 1 or 2).  sdu/sdu_len is the full MAC SDU
    // (= RLC AM PDU, 2-byte header + PDCP).
    // Fills out[] with plaintext RRC bytes; returns length or 0 on failure.
    uint32_t decrypt_srb(UESecurityState& ue, uint8_t lcid,
                         const uint8_t* sdu, uint32_t sdu_len,
                         uint8_t* out);

    // Decrypt DRB PDU (LCID 3+).  sdu/sdu_len is the full MAC SDU.
    // Writes decrypted IP packet to output pcap on success.
    void decrypt_drb(UESecurityState& ue, uint8_t lcid,
                     const uint8_t* sdu, uint32_t sdu_len,
                     uint32_t tti);

    // Inner decrypt helper: updates bearer HFN, handles mid-session sync.
    // For SRBs verifies integrity; for DRBs checks IP header.
    bool do_decrypt(uint8_t* key16, uint8_t* int_key16,
                    CIPHERING_ALGORITHM_ID_ENUM cipher,
                    INTEGRITY_ALGORITHM_ID_ENUM integ,
                    uint8_t bearer_param, uint8_t direction,
                    PdcpBearerState& bs,
                    const uint8_t* ct, uint32_t ct_len,
                    const uint8_t* mac_i,   // non-null → SRB (verify integrity)
                    uint8_t* plain_out,
                    uint32_t hfn_hint);

    // Cipher one block using the negotiated algorithm.
    bool cipher_block(uint8_t* key16, CIPHERING_ALGORITHM_ID_ENUM algo,
                      uint32_t count, uint8_t bearer, uint8_t direction,
                      const uint8_t* in, uint32_t len, uint8_t* out);

    // Compute integrity MAC-I.
    bool integrity_mac(uint8_t* key16, INTEGRITY_ALGORITHM_ID_ENUM algo,
                       uint32_t count, uint8_t bearer, uint8_t direction,
                       const uint8_t* msg, uint32_t msg_len,
                       uint8_t mac_out[4]);

    static bool parse_hex(const std::string& hex, uint8_t* out, size_t n);
    static bool is_valid_ip(const uint8_t* pkt, uint32_t len);
};
