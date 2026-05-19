/*
 * test_keystore_ul.cc — smoke test for KeyStore UL PDCP decryption path.
 *
 * Tests:
 *  1. Guard conditions: process_ul_mac_pdu is a no-op when RNTI unknown or
 *     security not yet active.
 *  2. UL direction: with EEA0 (null cipher, plaintext == ciphertext) a
 *     valid DRB MAC PDU is decrypted and written to the IP pcap.
 *  3. Rename regression: UL_DL_MODE constant is defined and equals 1.
 *
 * Build: linked via the 'test_keystore_ul' CMake target in src/test/.
 */

#include <cassert>
#include <cstdio>
#include <cstring>
#include <vector>

#include "srsran/srslog/srslog.h"
#include "include/KeyAttaching.h"
#include "include/Sniffer_dependency.h"

// ── helpers ──────────────────────────────────────────────────────────────────

static void write_tmp_key_file(const char* path, uint16_t rnti)
{
    // K_eNB = 32 zero bytes (valid length; EEA0 ignores the key value)
    FILE* f = fopen(path, "w");
    assert(f);
    fprintf(f,
        "[\n"
        "  {\n"
        "    \"rnti\"     : \"0x%04x\",\n"
        "    \"kenb\"     : \"%s\",\n"
        "    \"hfn_hint\" : 0\n"
        "  }\n"
        "]\n",
        rnti,
        "0000000000000000000000000000000000000000000000000000000000000000");
    fclose(f);
}

/*
 * Build a minimal UL MAC PDU with one DRB SDU on LCID 3 (last element).
 *
 * srsran sub-header format: R(1)|E(1)|LCID(5)
 *   E=0 → last element, no length byte; srsran computes size as remaining bytes.
 * Sub-header byte: 0b00_00011 = 0x03
 *
 * SDU = 2-byte RLC-UM header + 2-byte PDCP header (D/C=1, SN=0) + IP pkt.
 * With EEA0 the "ciphertext" == plaintext, so the IP packet is embedded raw.
 */
static std::vector<uint8_t> build_drb_mac_pdu(const uint8_t* ip_pkt, uint32_t ip_len)
{
    std::vector<uint8_t> pdu;

    // MAC sub-header: R=0, E=0 (last element), LCID=3 — no length byte follows
    pdu.push_back(0x03);

    // 2-byte RLC-UM header: FI=0b00 (full SDU), E=0, SN=0
    pdu.push_back(0x00);
    pdu.push_back(0x00);

    // 2-byte PDCP header: D/C=1 (bit 7), SN[11:8]=0, SN[7:0]=0
    pdu.push_back(0x80);
    pdu.push_back(0x00);

    // IP packet (plaintext == ciphertext under EEA0)
    pdu.insert(pdu.end(), ip_pkt, ip_pkt + ip_len);

    return pdu;
}

// Minimal valid IPv4 header (20 bytes, no payload)
static void make_ipv4_hdr(uint8_t* buf, uint16_t total_len)
{
    memset(buf, 0, 20);
    buf[0] = 0x45;                          // version=4, IHL=5
    buf[2] = (uint8_t)(total_len >> 8);
    buf[3] = (uint8_t)(total_len & 0xFF);
    buf[9] = 0x11;                          // protocol=UDP
}

// ── tests ────────────────────────────────────────────────────────────────────

static void test_rename_regression()
{
    // UL_DL_MODE must be 1 and DL_MODE must be 0
    assert(DL_MODE    == 0);
    assert(UL_DL_MODE == 1);
    printf("[PASS] rename regression: UL_DL_MODE=%d DL_MODE=%d\n",
           UL_DL_MODE, DL_MODE);
}

// Helper: assert with message (safe even with NDEBUG)
#define CHECK(expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "FAIL: %s  (line %d)\n", #expr, __LINE__); \
        exit(1); \
    } \
} while(0)

static void test_guard_unknown_rnti()
{
    KeyStore ks;
    uint8_t dummy[4] = {};
    ks.process_ul_mac_pdu(0x1234, dummy, sizeof(dummy), 0);  // must not crash
    printf("[PASS] guard: unknown RNTI is a no-op\n");
}

static void test_guard_security_not_active()
{
    const char* key_path = "/tmp/test_ks_ul_notactive.json";
    write_tmp_key_file(key_path, 0x5678);

    KeyStore ks;
    CHECK(ks.load(key_path));
    CHECK(ks.has_ue(0x5678));
    CHECK(!ks.is_security_active(0x5678));

    uint8_t dummy[4] = {};
    ks.process_ul_mac_pdu(0x5678, dummy, sizeof(dummy), 0);  // must not crash
    printf("[PASS] guard: security not active is a no-op\n");
}

static void test_ul_drb_eea0_decrypts_ip()
{
    const char* key_path      = "/tmp/test_ks_ul_eea0.json";
    const char* pcap_base     = "/tmp/test_ks_ul_eea0";
    const char* pcap_path     = "/tmp/test_ks_ul_eea0_decrypted_ip.pcap";
    write_tmp_key_file(key_path, 0xAAAA);

    KeyStore ks;
    CHECK(ks.load(key_path));

    bool opened = ks.open_output(pcap_base);   // NOT inside CHECK/assert
    CHECK(opened);

    ks.set_security_algo(0xAAAA,
                         CIPHERING_ALGORITHM_ID_EEA0,
                         INTEGRITY_ALGORITHM_ID_EIA0);
    ks.activate_security(0xAAAA);
    CHECK(ks.is_security_active(0xAAAA));

    // 40-byte IPv4 packet (header + 20 bytes payload)
    uint8_t ip_pkt[40];
    make_ipv4_hdr(ip_pkt, 40);
    memset(ip_pkt + 20, 0xAB, 20);

    auto mac_pdu = build_drb_mac_pdu(ip_pkt, sizeof(ip_pkt));
    ks.process_ul_mac_pdu(0xAAAA, mac_pdu.data(),
                          (uint32_t)mac_pdu.size(), 1000);

    ks.close_output();

    // pcap must exist and contain at least the 24-byte global header
    FILE* f = fopen(pcap_path, "rb");
    CHECK(f);  // file must have been created by open_output
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fclose(f);

    CHECK(sz >= 24);  // global header must be present

    // With EEA0 the IP packet passes is_valid_ip → full record should be written
    // 24-byte global hdr + 16-byte pkt hdr + 40-byte IP = 80 bytes minimum
    CHECK(sz >= 24 + 16 + 40);

    printf("[PASS] UL DRB EEA0: decrypted IP written to pcap (%ld bytes)\n", sz);
}

// ── main ─────────────────────────────────────────────────────────────────────

int main()
{
    srslog::init();

    test_rename_regression();
    test_guard_unknown_rnti();
    test_guard_security_not_active();
    test_ul_drb_eea0_decrypts_ip();

    printf("\nAll tests passed.\n");
    return 0;
}
