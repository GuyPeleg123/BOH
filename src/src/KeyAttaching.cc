/*
 * KeyAttaching.cc — PDCP key-attach feature for LTESniffer.
 *
 * Loads per-RNTI K_eNB from a JSON key file, detects the negotiated security
 * algorithm from RRC SecurityModeCommand, derives K_RRCenc / K_UPenc, and
 * decrypts PDCP PDUs on all DL SRBs and DRBs.
 *
 * Decrypted user-plane IP packets are written to a raw-IP (DLT=101) pcap
 * alongside the main encrypted capture.
 */

#include "include/KeyAttaching.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iostream>
#include <sstream>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#include "srsran/mac/pdu.h"
#include "srsran/srslog/srslog.h"

// ──────────────────────────────────────────────────────────────────────────────
// Minimal JSON parser (avoids external library dependency)
// Handles a flat array of objects with string-valued keys.
// ──────────────────────────────────────────────────────────────────────────────

static std::string trim(const std::string& s) {
    size_t b = s.find_first_not_of(" \t\r\n\"");
    size_t e = s.find_last_not_of(" \t\r\n\"");
    if (b == std::string::npos) return "";
    return s.substr(b, e - b + 1);
}

// Parse a JSON file that is an array of flat key-value objects.
// Returns a vector of maps (key→value, both trimmed of quotes/whitespace).
static std::vector<std::map<std::string,std::string>> parse_json_array(const std::string& path)
{
    std::vector<std::map<std::string,std::string>> result;
    std::ifstream f(path);
    if (!f.is_open()) return result;

    std::string content((std::istreambuf_iterator<char>(f)),
                         std::istreambuf_iterator<char>());

    std::map<std::string,std::string> obj;
    bool in_obj = false;

    size_t i = 0;
    while (i < content.size()) {
        if (content[i] == '{') {
            obj.clear();
            in_obj = true;
            i++;
            continue;
        }
        if (content[i] == '}' && in_obj) {
            result.push_back(obj);
            in_obj = false;
            i++;
            continue;
        }
        if (in_obj && content[i] == '"') {
            // read key
            size_t k_start = i + 1;
            size_t k_end   = content.find('"', k_start);
            if (k_end == std::string::npos) break;
            std::string key = content.substr(k_start, k_end - k_start);

            // skip to ':'
            size_t colon = content.find(':', k_end);
            if (colon == std::string::npos) break;

            // read value (string or number)
            size_t v_start = colon + 1;
            while (v_start < content.size() &&
                   (content[v_start] == ' ' || content[v_start] == '\t')) v_start++;

            std::string val;
            if (v_start < content.size() && content[v_start] == '"') {
                // string value
                size_t ve = content.find('"', v_start + 1);
                if (ve == std::string::npos) break;
                val = content.substr(v_start + 1, ve - v_start - 1);
                i = ve + 1;
            } else {
                // numeric value
                size_t ve = v_start;
                while (ve < content.size() && content[ve] != ',' &&
                       content[ve] != '}' && content[ve] != '\n') ve++;
                val = trim(content.substr(v_start, ve - v_start));
                i = ve;
            }
            obj[key] = val;
            continue;
        }
        i++;
    }
    return result;
}

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

bool KeyStore::parse_cipher_algo(const std::string& s, CIPHERING_ALGORITHM_ID_ENUM& out)
{
    if (s == "EEA0") { out = CIPHERING_ALGORITHM_ID_EEA0;     return true; }
    if (s == "EEA1") { out = CIPHERING_ALGORITHM_ID_128_EEA1; return true; }
    if (s == "EEA2") { out = CIPHERING_ALGORITHM_ID_128_EEA2; return true; }
    if (s == "EEA3") { out = CIPHERING_ALGORITHM_ID_128_EEA3; return true; }
    return false;
}

bool KeyStore::parse_integ_algo(const std::string& s, INTEGRITY_ALGORITHM_ID_ENUM& out)
{
    if (s == "EIA0") { out = INTEGRITY_ALGORITHM_ID_EIA0;     return true; }
    if (s == "EIA1") { out = INTEGRITY_ALGORITHM_ID_128_EIA1; return true; }
    if (s == "EIA2") { out = INTEGRITY_ALGORITHM_ID_128_EIA2; return true; }
    if (s == "EIA3") { out = INTEGRITY_ALGORITHM_ID_128_EIA3; return true; }
    return false;
}

bool KeyStore::parse_hex(const std::string& hex, uint8_t* out, size_t n)
{
    std::string h = hex;
    // strip leading 0x
    if (h.size() >= 2 && h[0] == '0' && (h[1] == 'x' || h[1] == 'X'))
        h = h.substr(2);
    if (h.size() != n * 2) return false;
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        if (sscanf(h.c_str() + 2*i, "%02x", &v) != 1) return false;
        out[i] = static_cast<uint8_t>(v);
    }
    return true;
}

bool KeyStore::is_valid_ip(const uint8_t* p, uint32_t len)
{
    // DRB accept oracle. This is a HEURISTIC (no MAC-I on the user plane), so
    // the goal is to make a wrong-key keystream that happens to start with a
    // 0x4./0x6. nibble much less likely to be mistaken for a real packet —
    // WITHOUT ever rejecting a well-formed IPv4/IPv6 SDU. Every constraint
    // below is mandated by RFC 791 / RFC 8200 for a valid header, so a genuine
    // packet always passes; only random keystream is filtered harder.
    if (len < 20) return false;
    uint8_t ver = p[0] >> 4;
    if (ver == 4) {
        // IHL (RFC 791): header length in 32-bit words, always in [5,15].
        uint8_t  ihl  = p[0] & 0x0F;
        if (ihl < 5 || ihl > 15) return false;
        uint32_t hdr  = (uint32_t)ihl * 4;          // header length in bytes (>=20 since ihl>=5)
        if (len < hdr) return false;                 // SDU must contain the header
        // total_length >= header length and within the captured SDU.
        // (<= len, not ==, because RLC/MAC padding can leave trailing bytes.)
        uint16_t total = (uint16_t(p[2]) << 8) | p[3];
        return total >= hdr && total <= len;
    }
    if (ver == 6) {
        // payload_length (RFC 8200): bytes after the fixed 40-byte header.
        // 40 + payload must fit within the captured SDU (allow trailing bytes).
        uint16_t payload = (uint16_t(p[4]) << 8) | p[5];
        return (uint32_t)(40 + payload) <= len;
    }
    return false;
}

// ──────────────────────────────────────────────────────────────────────────────
// Load
// ──────────────────────────────────────────────────────────────────────────────

bool KeyStore::load(const std::string& json_path)
{
    auto entries = parse_json_array(json_path);
    if (entries.empty()) {
        fprintf(stderr, "[KeyAttach] Failed to parse key file: %s\n", json_path.c_str());
        return false;
    }

    std::lock_guard<std::mutex> lk(mtx_);
    for (auto& e : entries) {
        // RNTI
        auto it_rnti = e.find("rnti");
        if (it_rnti == e.end()) { fprintf(stderr, "[KeyAttach] Entry missing 'rnti'\n"); continue; }
        unsigned rnti_v = 0;
        if (sscanf(it_rnti->second.c_str(), "%i", &rnti_v) != 1) {
            fprintf(stderr, "[KeyAttach] Bad RNTI: %s\n", it_rnti->second.c_str());
            continue;
        }
        uint16_t rnti = static_cast<uint16_t>(rnti_v);

        UESecurityState ue = {};

        // K_eNB — two accepted input paths:
        //   Path A: "kenb" (32-byte hex)   — direct, use as-is.
        //   Path B: "kasme" + "nas_count"  — derive K_eNB via
        //           3GPP TS 33.401 Annex A.2 (HMAC-SHA256).
        // Path A takes priority when both are present.
        auto it_kenb  = e.find("kenb");
        auto it_kasme = e.find("kasme");
        auto it_nasct = e.find("nas_count");

        if (it_kenb != e.end()) {
            // Path A — K_eNB supplied directly
            if (!parse_hex(it_kenb->second, ue.k_enb, 32)) {
                fprintf(stderr, "[KeyAttach] RNTI 0x%04x: bad kenb (need 64 hex chars)\n", rnti);
                continue;
            }
            // Also store KASME if provided alongside (for informational purposes)
            if (it_kasme != e.end())
                parse_hex(it_kasme->second, ue.kasme, 32);
            ue.has_kenb = true;
        } else if (it_kasme != e.end() && it_nasct != e.end()) {
            // Path B — derive K_eNB from KASME + NAS uplink count
            if (!parse_hex(it_kasme->second, ue.kasme, 32)) {
                fprintf(stderr, "[KeyAttach] RNTI 0x%04x: bad kasme (need 64 hex chars)\n", rnti);
                continue;
            }
            uint32_t nas_count = (uint32_t)strtoul(it_nasct->second.c_str(), nullptr, 0);
            if (security_generate_k_enb(ue.kasme, nas_count, ue.k_enb) != SRSRAN_SUCCESS) {
                fprintf(stderr, "[KeyAttach] RNTI 0x%04x: K_eNB derivation from KASME failed\n", rnti);
                continue;
            }
            ue.has_kenb = true;
            printf("[KeyAttach] RNTI 0x%04x: K_eNB derived from KASME (nas_count=%u)\n",
                   rnti, nas_count);
        } else {
            fprintf(stderr, "[KeyAttach] RNTI 0x%04x: need 'kenb'  OR  'kasme'+'nas_count'\n", rnti);
            continue;
        }

        // hfn_hint (optional)
        auto it_hfn = e.find("hfn_hint");
        if (it_hfn != e.end())
            ue.hfn_hint = (uint32_t)strtoul(it_hfn->second.c_str(), nullptr, 0);

        // cipher_algo + integ_algo (optional).
        // When both are present the keys are derived immediately and security
        // is activated at load time, enabling mid-session decryption without
        // waiting to observe a live SecurityModeCommand on DL SRB1.
        auto it_cipher = e.find("cipher_algo");
        auto it_integ  = e.find("integ_algo");
        if (it_cipher != e.end() && it_integ != e.end()) {
            CIPHERING_ALGORITHM_ID_ENUM cipher;
            INTEGRITY_ALGORITHM_ID_ENUM integ;
            bool cipher_ok = parse_cipher_algo(it_cipher->second, cipher);
            bool integ_ok  = parse_integ_algo(it_integ->second, integ);
            if (!cipher_ok) {
                fprintf(stderr, "[KeyAttach] RNTI 0x%04x: unknown cipher_algo '%s' "
                        "(valid: EEA0 EEA1 EEA2 EEA3)\n", rnti, it_cipher->second.c_str());
            } else if (!integ_ok) {
                fprintf(stderr, "[KeyAttach] RNTI 0x%04x: unknown integ_algo '%s' "
                        "(valid: EIA0 EIA1 EIA2 EIA3)\n", rnti, it_integ->second.c_str());
            } else {
                ue.cipher_algo = cipher;
                ue.integ_algo  = integ;
                security_generate_k_rrc(ue.k_enb, cipher, integ, ue.k_rrc_enc, ue.k_rrc_int);
                uint8_t k_up_int_tmp[32];
                security_generate_k_up(ue.k_enb, cipher, integ, ue.k_up_enc, k_up_int_tmp);
                ue.keys_derived    = true;
                ue.security_active = true;
                printf("[KeyAttach] RNTI 0x%04x: pre-set algo cipher=%s integ=%s "
                       "(security active, mid-session join enabled)\n",
                       rnti, it_cipher->second.c_str(), it_integ->second.c_str());
            }
        }

        states_[rnti] = ue;
        printf("[KeyAttach] Loaded keys for RNTI 0x%04x (hfn_hint=%u)\n", rnti, ue.hfn_hint);
    }
    return !states_.empty();
}

// ──────────────────────────────────────────────────────────────────────────────
// Security state management
// ──────────────────────────────────────────────────────────────────────────────

bool KeyStore::has_ue(uint16_t rnti)
{
    std::lock_guard<std::mutex> lk(mtx_);
    return states_.count(rnti) > 0;
}

void KeyStore::set_security_algo(uint16_t rnti,
                                  CIPHERING_ALGORITHM_ID_ENUM cipher,
                                  INTEGRITY_ALGORITHM_ID_ENUM integ)
{
    std::lock_guard<std::mutex> lk(mtx_);
    auto it = states_.find(rnti);
    if (it == states_.end()) return;

    UESecurityState& ue = it->second;
    ue.cipher_algo = cipher;
    ue.integ_algo  = integ;

    if (!ue.has_kenb) return;

    // Derive K_RRC_enc, K_RRC_int, K_UP_enc from K_eNB + algorithms
    security_generate_k_rrc(ue.k_enb, cipher, integ, ue.k_rrc_enc, ue.k_rrc_int);
    uint8_t k_up_int_tmp[32];
    security_generate_k_up(ue.k_enb, cipher, integ, ue.k_up_enc, k_up_int_tmp);

    ue.keys_derived = true;
    printf("[KeyAttach] RNTI 0x%04x: keys derived (cipher=%d, integ=%d)\n",
           rnti, (int)cipher, (int)integ);
}

void KeyStore::activate_security(uint16_t rnti)
{
    std::lock_guard<std::mutex> lk(mtx_);
    auto it = states_.find(rnti);
    if (it == states_.end()) return;
    it->second.security_active = true;
    printf("[KeyAttach] RNTI 0x%04x: security activated\n", rnti);
}

bool KeyStore::is_security_active(uint16_t rnti)
{
    std::lock_guard<std::mutex> lk(mtx_);
    auto it = states_.find(rnti);
    if (it == states_.end()) return false;
    return it->second.security_active;
}

// ──────────────────────────────────────────────────────────────────────────────
// PCAP output (raw IP, DLT=101)
// ──────────────────────────────────────────────────────────────────────────────

static void write_u32_le(FILE* f, uint32_t v) {
    uint8_t b[4] = { uint8_t(v), uint8_t(v>>8), uint8_t(v>>16), uint8_t(v>>24) };
    fwrite(b, 1, 4, f);
}

void KeyStore::write_pcap_global_hdr(FILE* fd)
{
    write_u32_le(fd, 0xa1b2c3d4u); // magic
    uint8_t ver[] = {0x02,0x00, 0x04,0x00};
    fwrite(ver, 1, 4, fd);
    write_u32_le(fd, 0);           // thiszone
    write_u32_le(fd, 0);           // sigfigs
    write_u32_le(fd, 65535);       // snaplen
    write_u32_le(fd, 101);         // DLT_RAW (raw IP)
}

bool KeyStore::open_output(const std::string& base_path)
{
    std::string ip_path = base_path + "_decrypted_ip.pcap";
    // 0600 from creation: this file holds DECRYPTED subscriber IP traffic and
    // the sniffer runs as root, so a plain fopen() would honour umask and leave
    // it world-readable (0644). Create restricted, then fchmod to be sure.
    int fd = open(ip_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd >= 0) {
        fchmod(fd, 0600);
        ip_pcap_fd_ = fdopen(fd, "wb");
        if (!ip_pcap_fd_) close(fd);
    } else {
        ip_pcap_fd_ = nullptr;
    }
    if (!ip_pcap_fd_) {
        fprintf(stderr, "[KeyAttach] Cannot open %s: %s\n", ip_path.c_str(), strerror(errno));
        return false;
    }
    write_pcap_global_hdr(ip_pcap_fd_);
    printf("[KeyAttach] Decrypted IP pcap: %s\n", ip_path.c_str());
    return true;
}

void KeyStore::close_output()
{
    if (ip_pcap_fd_) { fflush(ip_pcap_fd_); fclose(ip_pcap_fd_); ip_pcap_fd_ = nullptr; }
}

void KeyStore::write_ip_pkt(const uint8_t* pkt, uint32_t len, uint32_t tti)
{
    if (!ip_pcap_fd_) return;
    uint32_t sec  = tti / 1000;
    uint32_t usec = (tti % 1000) * 1000;
    write_u32_le(ip_pcap_fd_, sec);
    write_u32_le(ip_pcap_fd_, usec);
    write_u32_le(ip_pcap_fd_, len);
    write_u32_le(ip_pcap_fd_, len);
    fwrite(pkt, 1, len, ip_pcap_fd_);
}

// ──────────────────────────────────────────────────────────────────────────────
// Cipher / Integrity helpers
// ──────────────────────────────────────────────────────────────────────────────

bool KeyStore::cipher_block(uint8_t* key16, CIPHERING_ALGORITHM_ID_ENUM algo,
                             uint32_t count, uint8_t bearer, uint8_t direction,
                             const uint8_t* in, uint32_t len, uint8_t* out)
{
    switch (algo) {
    case CIPHERING_ALGORITHM_ID_EEA0:
        memcpy(out, in, len);
        return true;
    case CIPHERING_ALGORITHM_ID_128_EEA1:
        return security_128_eea1(key16, count, bearer, direction,
                                 const_cast<uint8_t*>(in), len, out) == 0;
    case CIPHERING_ALGORITHM_ID_128_EEA2:
        return security_128_eea2(key16, count, bearer, direction,
                                 const_cast<uint8_t*>(in), len, out) == 0;
    case CIPHERING_ALGORITHM_ID_128_EEA3:
        return security_128_eea3(key16, count, bearer, direction,
                                 const_cast<uint8_t*>(in), len, out) == 0;
    default:
        return false;
    }
}

bool KeyStore::integrity_mac(uint8_t* key16, INTEGRITY_ALGORITHM_ID_ENUM algo,
                              uint32_t count, uint8_t bearer, uint8_t direction,
                              const uint8_t* msg, uint32_t msg_len,
                              uint8_t mac_out[4])
{
    uint8_t mac[4] = {};
    int r = 1;
    switch (algo) {
    case INTEGRITY_ALGORITHM_ID_EIA0:
        memset(mac_out, 0, 4);
        return true;
    case INTEGRITY_ALGORITHM_ID_128_EIA1:
        r = security_128_eia1(key16, count, bearer, direction,
                              const_cast<uint8_t*>(msg), msg_len, mac);
        break;
    case INTEGRITY_ALGORITHM_ID_128_EIA2:
        r = security_128_eia2(key16, count, bearer, direction,
                              const_cast<uint8_t*>(msg), msg_len, mac);
        break;
    case INTEGRITY_ALGORITHM_ID_128_EIA3:
        r = security_128_eia3(key16, count, bearer, direction,
                              const_cast<uint8_t*>(msg), msg_len, mac);
        break;
    default:
        return false;
    }
    if (r != 0) return false;
    memcpy(mac_out, mac, 4);
    return true;
}

// ──────────────────────────────────────────────────────────────────────────────
// Core decryption with HFN tracking + mid-session synchronisation
// ──────────────────────────────────────────────────────────────────────────────

bool KeyStore::do_decrypt(uint8_t* key16, uint8_t* int_key16,
                           CIPHERING_ALGORITHM_ID_ENUM cipher,
                           INTEGRITY_ALGORITHM_ID_ENUM integ,
                           uint8_t bearer_param, uint8_t direction,
                           PdcpBearerState& bs,
                           const uint8_t* ct, uint32_t ct_len,
                           const uint8_t* mac_i,
                           uint8_t* plain_out,
                           uint32_t hfn_hint)
{
    if (ct_len == 0 || ct_len > 8192) return false;

    // Extract SN from the ciphertext context (caller already parsed it)
    // — but we need it to compute COUNT.  It was embedded by callers in
    //   the PdcpBearerState before calling us; we reconstruct it from the
    //   state's last_sn field (set by caller).
    uint32_t sn       = bs.last_sn;
    uint32_t sn_mask  = (1u << bs.sn_bits) - 1u;

    // Determine HFN search base: if first packet, start at hfn_hint.
    uint32_t hfn = bs.hfn;
    if (bs.hfn == 0 && bs.last_sn == UINT32_MAX) {
        hfn = hfn_hint;
    }

    // HFN is only ever committed below on a VERIFIED decrypt (SRB: MAC-I match;
    // DRB: is_valid_ip). The callers must NOT speculatively advance bs.hfn on a
    // bare backward-SN jump — a dropped/reordered packet (routine for a passive
    // sniffer) would otherwise permanently poison the bearer's HFN. A genuine
    // SN wrap is still handled here by the forward search (try_hfn = hfn+1).
    //
    // Search window:
    //   DRB (mac_i == nullptr): forward only [hfn .. hfn+N]. The DRB oracle is
    //     heuristic, so widening backward would raise garbage-accept risk —
    //     keep it conservative (unchanged from before).
    //   SRB (mac_i != nullptr) with a REAL integrity algo (EIA1/2/3): allow one
    //     HFN step backward [hfn-1 .. hfn+N]. Every candidate is MAC-I gated, so
    //     a wrong HFN is rejected cryptographically (no false-accept risk). This
    //     lets a late/reordered SRB PDU belonging to the previous HFN still
    //     decrypt instead of being lost. (Bounded to hfn-1, only when hfn > 0.)
    //     EIA0 (null integrity) is excluded: its MAC is all-zero and gates
    //     nothing, so a backward step there could walk HFN backward unchecked.
    const uint32_t max_hfn_search = 64; // max forward HFN offset (search reaches hfn+max_hfn_search; SRB also tries hfn-1)
    static uint8_t tmp[8192];

    uint32_t start_hfn = hfn;
    if (mac_i != nullptr && hfn > 0 && integ != INTEGRITY_ALGORITHM_ID_EIA0)
        start_hfn = hfn - 1;

    for (uint32_t try_hfn = start_hfn; try_hfn <= hfn + max_hfn_search; try_hfn++) {
        uint32_t count = (try_hfn << bs.sn_bits) | sn;
        if (!cipher_block(key16, cipher, count, bearer_param, direction,
                          ct, ct_len, tmp))
            continue;

        // Validate
        if (mac_i) {
            // SRB: verify integrity
            uint8_t expected[4];
            if (!integrity_mac(int_key16, integ, count, bearer_param,
                               direction, tmp, ct_len, expected))
                continue;
            if (memcmp(expected, mac_i, 4) != 0) continue;
        } else {
            // DRB: heuristic IP check
            if (!is_valid_ip(tmp, ct_len)) continue;
        }

        // Found the right HFN — commit
        memcpy(plain_out, tmp, ct_len);
        bs.hfn     = try_hfn;
        bs.last_sn = sn;
        return true;
    }
    return false;
}

// ──────────────────────────────────────────────────────────────────────────────
// SRB decryption  (LCID 1 or 2)
// Returns plaintext RRC length, or 0 on failure.
// ──────────────────────────────────────────────────────────────────────────────

uint32_t KeyStore::decrypt_srb(UESecurityState& ue, uint8_t lcid,
                                const uint8_t* sdu, uint32_t sdu_len,
                                uint8_t direction, uint8_t* out)
{
    // Minimum: 2 (RLC-AM) + 1 (PDCP-hdr) + 4 (MAC-I) = 7 bytes
    if (sdu_len < 7) return 0;

    // RLC AM data PDU: D/C bit (bit 7) must be 1, RF bit (bit 6) must be 0
    if ((sdu[0] & 0xC0) != 0x80) return 0;
    // E bit (bit 2) = 0: no extension headers
    if (sdu[0] & 0x04) return 0;  // skip segmented/multi-SDU PDUs for now

    const uint8_t* pdcp = sdu + 2;                // after 2-byte RLC header
    uint32_t        pdcp_len = sdu_len - 2;

    // PDCP header for SRB: 1 byte, D/C=1, SN = lower 5 bits
    if ((pdcp[0] & 0x80) == 0) return 0;          // D/C must be 1 (data)
    uint32_t sn = pdcp[0] & 0x1Fu;

    const uint8_t* ct    = pdcp + 1;
    // MAC-I is the last 4 bytes of the PDCP PDU
    if (pdcp_len < 5) return 0;
    uint32_t ct_len      = pdcp_len - 1 - 4;      // subtract PDCP header + MAC-I
    const uint8_t* mac_i = pdcp + pdcp_len - 4;

    if (ct_len == 0) return 0;

    PdcpBearerState& bs = (direction == SECURITY_DIRECTION_DOWNLINK)
                          ? ue.srb_dl[lcid] : ue.srb_ul[lcid];
    if (bs.sn_bits == 0) {
        bs.sn_bits = 5;
        bs.hfn     = ue.hfn_hint;
    }

    // NOTE: HFN is advanced only inside do_decrypt() on a verified decrypt
    // (MAC-I match here). We deliberately do NOT speculatively bump bs.hfn on a
    // backward-SN jump: a dropped/reordered SRB PDU would otherwise poison the
    // bearer permanently. A real SN wrap is recovered by do_decrypt's forward
    // HFN search; a late PDU from the previous HFN by its SRB backward step.
    bs.last_sn = sn;  // temp — do_decrypt will re-read it

    // Temporarily set last_sn so do_decrypt can read the SN
    uint8_t bearer_param = (uint8_t)(lcid - 1);   // SRB1→0, SRB2→1

    static uint8_t plain[8192];
    bool ok = do_decrypt(ue.k_rrc_enc + 16, ue.k_rrc_int + 16,
                         ue.cipher_algo, ue.integ_algo,
                         bearer_param, direction,
                         bs, ct, ct_len, mac_i, plain, ue.hfn_hint);
    if (!ok) return 0;

    memcpy(out, plain, ct_len);
    return ct_len;
}

// ──────────────────────────────────────────────────────────────────────────────
// DRB decryption  (LCID 3+)
// Writes to IP pcap on success.
// ──────────────────────────────────────────────────────────────────────────────

void KeyStore::decrypt_drb(UESecurityState& ue, uint8_t lcid,
                            const uint8_t* sdu, uint32_t sdu_len,
                            uint8_t direction, uint32_t tti)
{
    // Need at least 2 (RLC) + 2 (PDCP) + 20 (min IP) = 24 bytes
    if (sdu_len < 24) return;

    // LIMITATION: this path assumes one whole PDCP SDU per RLC PDU with a fixed
    // header offset (2 or 1 bytes). It does NOT reassemble segmented RLC PDUs
    // (RLC-AM RF=1 / segmentation offset) nor walk RLC concatenation/extension
    // (LI) fields for multiple SDUs in one PDU. Such PDUs decrypt against a
    // mis-parsed boundary and are simply dropped by the is_valid_ip oracle —
    // they are skipped, never reassembled. (Matches the SRB E-bit skip above.)

    // Try two RLC header lengths: 2 bytes (AM/UM-10bit) and 1 byte (UM-5bit)
    static const int rlc_offsets[] = { 2, 1 };

    for (int rlc_off : rlc_offsets) {
        if ((int)sdu_len < rlc_off + 2 + 20) continue;

        const uint8_t* pdcp    = sdu + rlc_off;
        uint32_t        pdcp_len = sdu_len - rlc_off;

        // PDCP header for DRB: 2 bytes, D/C=1 (bit 7), SN = lower 12 bits
        if ((pdcp[0] & 0x80) == 0) continue;
        uint32_t sn      = ((uint32_t)(pdcp[0] & 0x0F) << 8) | pdcp[1];
        const uint8_t* ct = pdcp + 2;
        uint32_t ct_len  = pdcp_len - 2;

        if (ct_len < 20) continue;

        PdcpBearerState& bs = (direction == SECURITY_DIRECTION_DOWNLINK)
                              ? ue.drb_dl[lcid] : ue.drb_ul[lcid];
        if (bs.sn_bits == 0) {
            bs.sn_bits = 12;
            bs.hfn     = ue.hfn_hint;
        }

        // HFN is advanced only inside do_decrypt() on a verified decrypt
        // (is_valid_ip here). We deliberately do NOT speculatively bump bs.hfn
        // on a backward-SN jump: a dropped/reordered DRB PDU would otherwise
        // poison the bearer permanently and stall decryption. A real SN wrap is
        // recovered by do_decrypt's forward HFN search (try_hfn = hfn+1). The
        // DRB search stays forward-only (heuristic oracle → no backward step).
        bs.last_sn = sn;

        // bearer_param = LCID - 3 → DRB1(lcid=3)→0, DRB2(lcid=4)→1
        uint8_t bearer_param = (uint8_t)(lcid - 3);

        static uint8_t plain[8192];
        bool ok = do_decrypt(ue.k_up_enc + 16, nullptr,
                             ue.cipher_algo, ue.integ_algo,
                             bearer_param, direction,
                             bs, ct, ct_len, nullptr, plain, ue.hfn_hint);
        if (ok) {
            write_ip_pkt(plain, ct_len, tti);
            return;
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Main entry point: process one decoded MAC PDU
// ──────────────────────────────────────────────────────────────────────────────

void KeyStore::process_dl_mac_pdu(uint16_t rnti, uint8_t* mac_pdu,
                                   uint32_t mac_pdu_len, uint32_t tti)
{
    std::lock_guard<std::mutex> lk(mtx_);

    auto it = states_.find(rnti);
    if (it == states_.end()) return;

    UESecurityState& ue = it->second;
    if (!ue.keys_derived || !ue.security_active) return;

    // Parse the MAC PDU sub-headers to find individual SDUs
    srsran::sch_pdu pdu(20, srslog::fetch_basic_logger("MAC"));
    pdu.init_rx(mac_pdu_len, false);
    pdu.parse_packet(mac_pdu);

    static uint8_t plain[8192];

    while (pdu.next()) {
        if (!pdu.get()->is_sdu()) continue;
        uint8_t  lcid       = pdu.get()->get_sdu_lcid();
        uint32_t sdu_len    = pdu.get()->get_payload_size();
        uint8_t* sdu_ptr    = pdu.get()->get_sdu_ptr();

        if (sdu_len == 0 || sdu_ptr == nullptr) continue;

        if (lcid == 1 || lcid == 2) {
            // SRB — decrypt and log RRC message type
            if (ue.cipher_algo == CIPHERING_ALGORITHM_ID_EEA0) continue; // unencrypted
            uint32_t plain_len = decrypt_srb(ue, lcid, sdu_ptr, sdu_len,
                                             SECURITY_DIRECTION_DOWNLINK, plain);
            if (plain_len > 0) {
                printf("[KeyAttach] RNTI 0x%04x SRB%d DL: decrypted %u bytes\n",
                       rnti, lcid, plain_len);
            }
        } else if (lcid >= 3) {
            // DRB — decrypt and write IP to pcap
            decrypt_drb(ue, lcid, sdu_ptr, sdu_len, SECURITY_DIRECTION_DOWNLINK, tti);
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Uplink entry point: process one decoded PUSCH MAC PDU
// Same pipeline as process_dl_mac_pdu but uses SECURITY_DIRECTION_UPLINK
// so the cipher/integrity COUNT uses direction=1 as per 3GPP TS 33.401.
// ──────────────────────────────────────────────────────────────────────────────

void KeyStore::process_ul_mac_pdu(uint16_t rnti, uint8_t* mac_pdu,
                                   uint32_t mac_pdu_len, uint32_t tti)
{
    std::lock_guard<std::mutex> lk(mtx_);

    auto it = states_.find(rnti);
    if (it == states_.end()) return;

    UESecurityState& ue = it->second;
    if (!ue.keys_derived || !ue.security_active) return;

    srsran::sch_pdu pdu(20, srslog::fetch_basic_logger("MAC"));
    pdu.init_rx(mac_pdu_len, false);
    pdu.parse_packet(mac_pdu);

    static uint8_t plain[8192];

    while (pdu.next()) {
        if (!pdu.get()->is_sdu()) continue;
        uint8_t  lcid    = pdu.get()->get_sdu_lcid();
        uint32_t sdu_len = pdu.get()->get_payload_size();
        uint8_t* sdu_ptr = pdu.get()->get_sdu_ptr();

        if (sdu_len == 0 || sdu_ptr == nullptr) continue;

        if (lcid == 1 || lcid == 2) {
            if (ue.cipher_algo == CIPHERING_ALGORITHM_ID_EEA0) continue;
            uint32_t plain_len = decrypt_srb(ue, lcid, sdu_ptr, sdu_len,
                                             SECURITY_DIRECTION_UPLINK, plain);
            if (plain_len > 0) {
                printf("[KeyAttach] RNTI 0x%04x SRB%d UL: decrypted %u bytes\n",
                       rnti, lcid, plain_len);
            }
        } else if (lcid >= 3) {
            decrypt_drb(ue, lcid, sdu_ptr, sdu_len, SECURITY_DIRECTION_UPLINK, tti);
        }
    }
}
