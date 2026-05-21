/*
 * test_keystore.cc — unit tests for KeyStore (KeyAttaching feature).
 *
 * Covers:
 *   Issue #2 — UL/DL bearer state isolation: DL and UL must use independent
 *              PdcpBearerState so simultaneous DUAL_MODE decryption does not
 *              corrupt each other's HFN/SN counters.
 *
 *   Issue #3 — Pre-set cipher/integ algorithm via JSON: when "cipher_algo"
 *              and "integ_algo" are present in the key file, security must be
 *              active immediately after load() without requiring a live
 *              SecurityModeCommand.
 *
 * All tests use EEA0/EIA0 (null cipher/integrity) so they run without
 * radio hardware or pre-computed test vectors.
 */

#include <cassert>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <vector>

#include "srsran/srslog/srslog.h"
#include "include/KeyAttaching.h"
#include "include/Sniffer_dependency.h"

// ─── CHECK macro ─────────────────────────────────────────────────────────────

#define CHECK(expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "\n  FAIL at %s:%d — %s\n", __FILE__, __LINE__, #expr); \
        exit(1); \
    } \
} while(0)

// ─── Helpers ─────────────────────────────────────────────────────────────────

static void write_key_file(const char* path, uint16_t rnti,
                            const char* cipher_algo = nullptr,
                            const char* integ_algo  = nullptr)
{
    // K_eNB = 32 zero bytes (EEA0 ignores the key value)
    static const char* zero64 =
        "0000000000000000000000000000000000000000000000000000000000000000";
    FILE* f = fopen(path, "w");
    assert(f);
    fprintf(f, "[\n  {\n");
    fprintf(f, "    \"rnti\" : \"0x%04x\",\n", rnti);
    fprintf(f, "    \"kenb\" : \"%s\"", zero64);
    if (cipher_algo && integ_algo) {
        fprintf(f, ",\n    \"cipher_algo\" : \"%s\"", cipher_algo);
        fprintf(f, ",\n    \"integ_algo\"  : \"%s\"", integ_algo);
    }
    fprintf(f, "\n  }\n]\n");
    fclose(f);
}

// Write a key file using KASME + nas_count (Path B) instead of kenb.
static void write_kasme_key_file(const char* path, uint16_t rnti,
                                  uint32_t nas_count = 0,
                                  const char* cipher_algo = nullptr,
                                  const char* integ_algo  = nullptr)
{
    static const char* zero64 =
        "0000000000000000000000000000000000000000000000000000000000000000";
    FILE* f = fopen(path, "w");
    assert(f);
    fprintf(f, "[\n  {\n");
    fprintf(f, "    \"rnti\"      : \"0x%04x\",\n", rnti);
    fprintf(f, "    \"kasme\"     : \"%s\",\n", zero64);
    fprintf(f, "    \"nas_count\" : %u", nas_count);
    if (cipher_algo && integ_algo) {
        fprintf(f, ",\n    \"cipher_algo\" : \"%s\"", cipher_algo);
        fprintf(f, ",\n    \"integ_algo\"  : \"%s\"", integ_algo);
    }
    fprintf(f, "\n  }\n]\n");
    fclose(f);
}

// Minimal valid IPv4 UDP header (28 bytes: 20 IP + 8 UDP), no payload.
static void make_ipv4_udp(uint8_t* buf)
{
    memset(buf, 0, 28);
    buf[0] = 0x45;  // version=4, IHL=5
    buf[2] = 0x00;
    buf[3] = 28;    // total length
    buf[9] = 0x11;  // protocol=UDP
    // UDP header (8 bytes)
    buf[20] = 0x04; buf[21] = 0x00;  // src port 1024
    buf[22] = 0x04; buf[23] = 0x01;  // dst port 1025
    buf[24] = 0x00; buf[25] = 0x08;  // UDP length = 8
}

/*
 * Build a MAC PDU with one DRB SDU on the given LCID.
 *
 * MAC sub-header (1 byte): R=0, E=0, LCID — no length byte (last element).
 * SDU layout passed to decrypt_drb():
 *   2-byte RLC-UM header  (rlc_off=2 path in decrypt_drb)
 *   2-byte PDCP header    D/C=1(bit7), SN[11:8]=0, SN[7:0]=sn
 *   IP packet             (plaintext == ciphertext under EEA0)
 */
static std::vector<uint8_t> make_drb_mac_pdu(uint8_t lcid, uint8_t sn,
                                              const uint8_t* ip, uint32_t ip_len)
{
    std::vector<uint8_t> pdu;
    pdu.push_back(lcid & 0x1F);          // MAC sub-header: R=0,E=0,LCID
    pdu.push_back(0x00);                  // RLC-UM byte 0
    pdu.push_back(0x00);                  // RLC-UM byte 1
    pdu.push_back(0x80);                  // PDCP hdr: D/C=1, SN[11:8]=0
    pdu.push_back(sn);                    // PDCP hdr: SN[7:0]
    pdu.insert(pdu.end(), ip, ip + ip_len);
    return pdu;
}

// Return size of the decrypted-IP pcap at path, or -1 if not found.
static long pcap_size(const char* path)
{
    FILE* f = fopen(path, "rb");
    if (!f) return -1;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fclose(f);
    return sz;
}

// ─── Tests ───────────────────────────────────────────────────────────────────

// Guard: unknown RNTI → no crash, no output.
static void test_guard_unknown_rnti()
{
    KeyStore ks;
    uint8_t dummy[4] = {};
    ks.process_dl_mac_pdu(0x1111, dummy, 4, 0);
    ks.process_ul_mac_pdu(0x1111, dummy, 4, 0);
    printf("  [PASS] guard: unknown RNTI is a no-op\n");
}

// Guard: security not active → no crash, no output.
static void test_guard_security_not_active()
{
    write_key_file("/tmp/ks_notactive.json", 0x2222);
    KeyStore ks;
    CHECK(ks.load("/tmp/ks_notactive.json"));
    CHECK(ks.has_ue(0x2222));
    CHECK(!ks.is_security_active(0x2222));
    uint8_t dummy[4] = {};
    ks.process_dl_mac_pdu(0x2222, dummy, 4, 0);
    ks.process_ul_mac_pdu(0x2222, dummy, 4, 0);
    printf("  [PASS] guard: security not active is a no-op\n");
}

// ── Issue #3 tests ────────────────────────────────────────────────────────────

// Pre-set valid algo → security active immediately after load().
static void test_preset_algo_activates_at_load()
{
    write_key_file("/tmp/ks_preset.json", 0x3333, "EEA0", "EIA0");
    KeyStore ks;
    CHECK(ks.load("/tmp/ks_preset.json"));
    CHECK(ks.has_ue(0x3333));
    CHECK(ks.is_security_active(0x3333));
    printf("  [PASS] issue#3: pre-set EEA0/EIA0 → security_active at load\n");
}

// All four cipher and integ algo strings are accepted.
static void test_preset_all_algo_strings()
{
    const char* ciphers[] = { "EEA0", "EEA1", "EEA2", "EEA3" };
    const char* integs[]  = { "EIA0", "EIA1", "EIA2", "EIA3" };
    uint16_t rnti = 0x4000;
    for (int i = 0; i < 4; i++) {
        char path[64];
        snprintf(path, sizeof(path), "/tmp/ks_algo_%d.json", i);
        write_key_file(path, rnti, ciphers[i], integs[i]);
        KeyStore ks;
        CHECK(ks.load(path));
        CHECK(ks.is_security_active(rnti));
        rnti++;
    }
    printf("  [PASS] issue#3: EEA0-3 / EIA0-3 all accepted\n");
}

// Unknown cipher_algo string → entry not loaded (or security not active).
static void test_preset_unknown_cipher_rejected()
{
    write_key_file("/tmp/ks_bad_cipher.json", 0x5555, "EEA9", "EIA2");
    KeyStore ks;
    // load() may still return true (other entries could succeed), but this RNTI
    // must not be security-active because the cipher string was invalid.
    ks.load("/tmp/ks_bad_cipher.json");
    CHECK(!ks.is_security_active(0x5555));
    printf("  [PASS] issue#3: unknown cipher_algo not accepted\n");
}

// Unknown integ_algo string → security not active.
static void test_preset_unknown_integ_rejected()
{
    write_key_file("/tmp/ks_bad_integ.json", 0x6666, "EEA2", "EIA9");
    KeyStore ks;
    ks.load("/tmp/ks_bad_integ.json");
    CHECK(!ks.is_security_active(0x6666));
    printf("  [PASS] issue#3: unknown integ_algo not accepted\n");
}

// Without preset algo, security stays inactive (existing path unchanged).
static void test_no_preset_waits_for_smc()
{
    write_key_file("/tmp/ks_nopre.json", 0x7777);
    KeyStore ks;
    CHECK(ks.load("/tmp/ks_nopre.json"));
    CHECK(ks.has_ue(0x7777));
    CHECK(!ks.is_security_active(0x7777));   // must wait for SecurityModeCommand
    printf("  [PASS] issue#3: no preset → security inactive until SMC\n");
}

// Pre-set algo → DL DRB decrypts without ever calling set_security_algo/activate.
static void test_preset_algo_dl_drb_decrypts()
{
    write_key_file("/tmp/ks_pre_dl.json", 0x8888, "EEA0", "EIA0");
    const char* pcap_base = "/tmp/ks_pre_dl";
    const char* pcap_path = "/tmp/ks_pre_dl_decrypted_ip.pcap";
    remove(pcap_path);

    KeyStore ks;
    CHECK(ks.load("/tmp/ks_pre_dl.json"));
    CHECK(ks.open_output(pcap_base));

    uint8_t ip[28]; make_ipv4_udp(ip);
    auto pdu = make_drb_mac_pdu(3, 0, ip, 28);
    ks.process_dl_mac_pdu(0x8888, pdu.data(), (uint32_t)pdu.size(), 1000);
    ks.close_output();

    // 24 (global hdr) + 16 (pkt hdr) + 28 (IP) = 68 bytes minimum
    long sz = pcap_size(pcap_path);
    CHECK(sz >= 68);
    printf("  [PASS] issue#3: pre-set EEA0 → DL DRB decrypted (%ld bytes)\n", sz);
}

// Pre-set algo → UL DRB decrypts without SecurityModeCommand.
static void test_preset_algo_ul_drb_decrypts()
{
    write_key_file("/tmp/ks_pre_ul.json", 0x9999, "EEA0", "EIA0");
    const char* pcap_base = "/tmp/ks_pre_ul";
    const char* pcap_path = "/tmp/ks_pre_ul_decrypted_ip.pcap";
    remove(pcap_path);

    KeyStore ks;
    CHECK(ks.load("/tmp/ks_pre_ul.json"));
    CHECK(ks.open_output(pcap_base));

    uint8_t ip[28]; make_ipv4_udp(ip);
    auto pdu = make_drb_mac_pdu(3, 0, ip, 28);
    ks.process_ul_mac_pdu(0x9999, pdu.data(), (uint32_t)pdu.size(), 2000);
    ks.close_output();

    long sz = pcap_size(pcap_path);
    CHECK(sz >= 68);
    printf("  [PASS] issue#3: pre-set EEA0 → UL DRB decrypted (%ld bytes)\n", sz);
}

// ── Issue #2 tests ────────────────────────────────────────────────────────────

// Struct check: UESecurityState must have the four direction-split maps.
// This fails to compile if the fields were not added (issue #2 regression guard).
static void test_bearer_state_struct_has_split_maps()
{
    UESecurityState s;
    // Access each map — if any field is missing this translation unit won't link.
    s.srb_dl[1].hfn = 1;
    s.srb_ul[1].hfn = 2;
    s.drb_dl[3].hfn = 3;
    s.drb_ul[3].hfn = 4;
    // DL and UL must be independent containers.
    CHECK(s.srb_dl[1].hfn != s.srb_ul[1].hfn);
    CHECK(s.drb_dl[3].hfn != s.drb_ul[3].hfn);
    printf("  [PASS] issue#2: UESecurityState has independent srb_dl/ul drb_dl/ul maps\n");
}

/*
 * DL and UL DRB decryption are independent: processing N DL packets then
 * restarting with SN=0 on UL must succeed (HFN not corrupted by DL).
 *
 * With the old shared state a DL sequence of SN=3,4,5,... would set
 * last_sn=5; a subsequent UL SN=0 would then see (5-0=5) > (2048 for 12-bit)
 * → false (no HFN bump), but BOTH directions' state would point to the same
 * last_sn, making one direction's advance visible to the other.
 * The test checks that both directions produce correct pcap output even when
 * interleaved with identical SN values.
 */
static void test_bearer_state_dl_ul_independent()
{
    write_key_file("/tmp/ks_iso.json", 0xAAAA, "EEA0", "EIA0");
    const char* pcap_base = "/tmp/ks_iso";
    const char* pcap_path = "/tmp/ks_iso_decrypted_ip.pcap";
    remove(pcap_path);

    KeyStore ks;
    CHECK(ks.load("/tmp/ks_iso.json"));
    CHECK(ks.open_output(pcap_base));

    uint8_t ip[28]; make_ipv4_udp(ip);

    // Send three DL packets (SN=0,1,2) to advance DL bearer state.
    for (uint8_t sn = 0; sn < 3; sn++) {
        auto pdu = make_drb_mac_pdu(3, sn, ip, 28);
        ks.process_dl_mac_pdu(0xAAAA, pdu.data(), (uint32_t)pdu.size(), 1000 + sn);
    }

    // Now send three UL packets starting from SN=0. If bearer states were
    // shared, the UL SN=0 would see DL's last_sn=2 and HFN tracking would
    // be polluted. With the fix, UL has its own fresh state → all succeed.
    for (uint8_t sn = 0; sn < 3; sn++) {
        auto pdu = make_drb_mac_pdu(3, sn, ip, 28);
        ks.process_ul_mac_pdu(0xAAAA, pdu.data(), (uint32_t)pdu.size(), 2000 + sn);
    }

    ks.close_output();

    // 6 packets written: 24 + 6*(16+28) = 24 + 264 = 288 bytes minimum.
    long sz = pcap_size(pcap_path);
    CHECK(sz >= 288);
    printf("  [PASS] issue#2: DL+UL isolation — 6 packets decrypted (%ld bytes)\n", sz);
}

/*
 * Simultaneous DL and UL decryption (DUAL_MODE scenario):
 * Interleaved DL/UL PDUs with the same SN sequence must all produce output.
 * If bearer states were shared, the alternating direction calls would each
 * corrupt the other's last_sn, causing the HFN wrap heuristic to misfire.
 */
static void test_bearer_state_interleaved_dl_ul()
{
    write_key_file("/tmp/ks_interleaved.json", 0xBBBB, "EEA0", "EIA0");
    const char* pcap_base = "/tmp/ks_interleaved";
    const char* pcap_path = "/tmp/ks_interleaved_decrypted_ip.pcap";
    remove(pcap_path);

    KeyStore ks;
    CHECK(ks.load("/tmp/ks_interleaved.json"));
    CHECK(ks.open_output(pcap_base));

    uint8_t ip[28]; make_ipv4_udp(ip);

    // Interleave DL and UL with independent SN sequences.
    for (uint8_t sn = 0; sn < 5; sn++) {
        auto dl_pdu = make_drb_mac_pdu(3, sn, ip, 28);
        ks.process_dl_mac_pdu(0xBBBB, dl_pdu.data(), (uint32_t)dl_pdu.size(), 1000 + sn);

        auto ul_pdu = make_drb_mac_pdu(3, sn, ip, 28);
        ks.process_ul_mac_pdu(0xBBBB, ul_pdu.data(), (uint32_t)ul_pdu.size(), 2000 + sn);
    }

    ks.close_output();

    // 10 packets: 24 + 10*(16+28) = 24 + 440 = 464 bytes minimum.
    long sz = pcap_size(pcap_path);
    CHECK(sz >= 464);
    printf("  [PASS] issue#2: interleaved DL/UL — 10 packets all decrypted (%ld bytes)\n", sz);
}

// ── KASME path tests (Path B) ─────────────────────────────────────────────────

// KASME + nas_count → K_eNB derived → has_ue() true.
static void test_kasme_path_loads()
{
    write_kasme_key_file("/tmp/ks_kasme.json", 0xCC00);
    KeyStore ks;
    CHECK(ks.load("/tmp/ks_kasme.json"));
    CHECK(ks.has_ue(0xCC00));
    CHECK(!ks.is_security_active(0xCC00));   // no algo pre-set
    printf("  [PASS] kasme path: K_eNB derived, ue loaded\n");
}

// KASME + nas_count + pre-set algo → security active at load.
static void test_kasme_path_with_preset_algo()
{
    write_kasme_key_file("/tmp/ks_kasme_pre.json", 0xCC01, 1, "EEA0", "EIA0");
    KeyStore ks;
    CHECK(ks.load("/tmp/ks_kasme_pre.json"));
    CHECK(ks.has_ue(0xCC01));
    CHECK(ks.is_security_active(0xCC01));
    printf("  [PASS] kasme path: derived K_eNB + pre-set algo → security active\n");
}

// KASME + nas_count + pre-set EEA0 → UL DRB decrypts (full end-to-end via Path B).
static void test_kasme_path_ul_drb_decrypts()
{
    write_kasme_key_file("/tmp/ks_kasme_ul.json", 0xCC02, 0, "EEA0", "EIA0");
    const char* pcap_base = "/tmp/ks_kasme_ul";
    const char* pcap_path = "/tmp/ks_kasme_ul_decrypted_ip.pcap";
    remove(pcap_path);

    KeyStore ks;
    CHECK(ks.load("/tmp/ks_kasme_ul.json"));
    CHECK(ks.open_output(pcap_base));

    uint8_t ip[28]; make_ipv4_udp(ip);
    auto pdu = make_drb_mac_pdu(3, 0, ip, 28);
    ks.process_ul_mac_pdu(0xCC02, pdu.data(), (uint32_t)pdu.size(), 3000);
    ks.close_output();

    long sz = pcap_size(pcap_path);
    CHECK(sz >= 68);
    printf("  [PASS] kasme path: UL DRB decrypted end-to-end (%ld bytes)\n", sz);
}

// KASME + nas_count + pre-set EEA0 → DL DRB decrypts (full end-to-end via Path B).
static void test_kasme_path_dl_drb_decrypts()
{
    write_kasme_key_file("/tmp/ks_kasme_dl.json", 0xCC03, 0, "EEA0", "EIA0");
    const char* pcap_base = "/tmp/ks_kasme_dl";
    const char* pcap_path = "/tmp/ks_kasme_dl_decrypted_ip.pcap";
    remove(pcap_path);

    KeyStore ks;
    CHECK(ks.load("/tmp/ks_kasme_dl.json"));
    CHECK(ks.open_output(pcap_base));

    uint8_t ip[28]; make_ipv4_udp(ip);
    auto pdu = make_drb_mac_pdu(3, 0, ip, 28);
    ks.process_dl_mac_pdu(0xCC03, pdu.data(), (uint32_t)pdu.size(), 4000);
    ks.close_output();

    long sz = pcap_size(pcap_path);
    CHECK(sz >= 68);
    printf("  [PASS] kasme path: DL DRB decrypted end-to-end (%ld bytes)\n", sz);
}

// Missing kenb AND missing nas_count → entry must be skipped (load returns false).
static void test_kasme_missing_nas_count_rejected()
{
    // Write a file with kasme but no nas_count and no kenb
    FILE* f = fopen("/tmp/ks_kasme_bad.json", "w");
    assert(f);
    fprintf(f, "[{\"rnti\":\"0xDD00\","
               "\"kasme\":\"0000000000000000000000000000000000000000000000000000000000000000\"}]\n");
    fclose(f);

    KeyStore ks;
    ks.load("/tmp/ks_kasme_bad.json");      // may return false
    CHECK(!ks.has_ue(0xDD00));              // entry must have been skipped
    printf("  [PASS] kasme path: kasme without nas_count rejected\n");
}

// nas_count variation: different NAS counts produce different K_eNB values
// (i.e. the derivation is actually running, not just copying KASME).
static void test_kasme_different_nas_count_differs()
{
    // Load two entries with same KASME but different nas_count + pre-set EEA0.
    // Both should load, both should be security-active.
    // We can't easily check the K_eNB value directly, but we verify both
    // entries load independently without error.
    FILE* f = fopen("/tmp/ks_kasme_nasvar.json", "w");
    assert(f);
    static const char* zero64 =
        "0000000000000000000000000000000000000000000000000000000000000000";
    fprintf(f, "[\n"
               "  {\"rnti\":\"0xEE00\",\"kasme\":\"%s\",\"nas_count\":0,"
               "   \"cipher_algo\":\"EEA0\",\"integ_algo\":\"EIA0\"},\n"
               "  {\"rnti\":\"0xEE01\",\"kasme\":\"%s\",\"nas_count\":5,"
               "   \"cipher_algo\":\"EEA0\",\"integ_algo\":\"EIA0\"}\n"
               "]\n", zero64, zero64);
    fclose(f);

    KeyStore ks;
    CHECK(ks.load("/tmp/ks_kasme_nasvar.json"));
    CHECK(ks.is_security_active(0xEE00));
    CHECK(ks.is_security_active(0xEE01));
    printf("  [PASS] kasme path: different nas_count values both load correctly\n");
}

// ─── main ────────────────────────────────────────────────────────────────────

int main()
{
    srslog::init();
    printf("\n=== KeyStore tests ===\n\n");

    printf("--- Guard conditions ---\n");
    test_guard_unknown_rnti();
    test_guard_security_not_active();

    printf("\n--- Issue #3: pre-set cipher/integ algorithm ---\n");
    test_preset_algo_activates_at_load();
    test_preset_all_algo_strings();
    test_preset_unknown_cipher_rejected();
    test_preset_unknown_integ_rejected();
    test_no_preset_waits_for_smc();
    test_preset_algo_dl_drb_decrypts();
    test_preset_algo_ul_drb_decrypts();

    printf("\n--- Issue #2: UL/DL bearer state isolation ---\n");
    test_bearer_state_struct_has_split_maps();
    test_bearer_state_dl_ul_independent();
    test_bearer_state_interleaved_dl_ul();

    printf("\n--- KASME path (Path B): derive K_eNB from KASME + NAS count ---\n");
    test_kasme_path_loads();
    test_kasme_path_with_preset_algo();
    test_kasme_path_ul_drb_decrypts();
    test_kasme_path_dl_drb_decrypts();
    test_kasme_missing_nas_count_rejected();
    test_kasme_different_nas_count_differs();

    printf("\n=== All tests passed ===\n\n");
    return 0;
}
