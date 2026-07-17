#include "include/UL_Sniffer_PUSCH.h"
#include "include/RawIQRecorder.h"
#include "include/UlIqCapture.h"
#include "include/UplinkSyncAdapter.h"
#include <cassert>
#include <atomic>
#include <chrono>
#include <algorithm>
#include <vector>
#include <cmath>

bool valid_prb_ul[101] = {true, true, true, true, true, true, true, false, true, true, true, false, true,
                          false, false, true, true, false, true, false, true, false, false, false, true, true,
                          false, true, false, false, true, false, true, false, false, false, true, false, false,
                          false, true, false, false, false, false, true, false, false, true, false, true, false,
                          false, false, true, false, false, false, false, false, true, false, false, false, true,
                          false, false, false, false, false, false, false, true, false, false, true, false, false,
                          false, false, true, true, false, false, false, false, false, false, false, false, true,
                          false, false, false, false, false, true, false, false, false, true};

/* Process-wide UplinkSyncAdapter live counters (all worker threads), reported by
   the UL_RATE_DIAG summary so the adapter's live contribution is visible. */
static std::atomic<uint64_t> g_sync_fired{0}, g_sync_recovered{0};
/* HARQ soft-combining: retransmissions seen, and those that decoded at nominal. */
static std::atomic<uint64_t> g_harq_recovered{0}, g_harq_retx_seen{0};

PUSCH_Decoder::PUSCH_Decoder(srsran_enb_ul_t &enb_ul,
                             srsran_ul_sf_cfg_t &ul_sf,
                             ULSchedule *ulsche,
                             cf_t **original_buffer,
                             cf_t **buffer_offset,
                             srsran_ul_cfg_t &ul_cfg,
                             LTESniffer_pcap_writer *pcapwriter,
                             MCSTracking *mcstracking,
                             bool en_debug) : enb_ul(enb_ul),
                                              ul_sf(ul_sf),
                                              dci_ul(),
                                              ulsche(ulsche),
                                              original_buffer(original_buffer),
                                              buffer_offset(buffer_offset),
                                              ul_cfg(ul_cfg),
                                              pcapwriter(pcapwriter),
                                              sf_power(),
                                              mcstracking(mcstracking),
                                              en_debug(en_debug)
{
    set_target_rnti(ulsche->get_rnti());
    set_debug_mode(ulsche->get_debug_mode());
    set_api_mode(mcstracking->get_api_mode());
    multi_ul_offset = ulsche->get_multi_ul_offset_cfg();
    pusch_res.data = srsran_vec_u8_malloc(2000 * 8);
    ul_cfg.pusch.softbuffers.rx = new srsran_softbuffer_rx_t;
    srsran_softbuffer_rx_init(ul_cfg.pusch.softbuffers.rx, SRSRAN_MAX_PRB);
    default_sb_ = ul_cfg.pusch.softbuffers.rx;
    harq_on_ = (getenv("UL_HARQ_COMBINE") != nullptr);

    /* Scratch for the nominal-window symbols (used by the offset-retry pass).
       enb_ul.sf_symbols is allocated for max_prb=110, CP normal. */
    sf_symbols_len     = SRSRAN_SF_LEN_RE(110, SRSRAN_CP_NORM);
    sf_symbols_nominal = srsran_vec_cf_malloc(sf_symbols_len);

    /* UL 2-RX selection diversity: only meaningful for decoder_a (it owns the
       antenna-0 enb_ul and drives the per-grant retries). Antenna-1 samples land
       in original_buffer[1] when rf_b is opened with 2 channels (env UL_DIVERSITY). */
    ul_diversity    = (getenv("UL_DIVERSITY") != nullptr);
    sf_symbols_ant1 = srsran_vec_cf_malloc(sf_symbols_len);
}

PUSCH_Decoder::~PUSCH_Decoder()
{
    srsran_vec_u8_zero(pusch_res.data, 2000 * 8);
    srsran_softbuffer_rx_free(ul_cfg.pusch.softbuffers.rx);
    if (sf_symbols_nominal) { free(sf_symbols_nominal); sf_symbols_nominal = nullptr; }
    if (sf_symbols_ant1)    { free(sf_symbols_ant1);    sf_symbols_ant1 = nullptr; }
    if (sync_adapter_)  { delete sync_adapter_;  sync_adapter_ = nullptr; }
    if (adapter_enb_ul_){ srsran_enb_ul_free(adapter_enb_ul_); delete adapter_enb_ul_; adapter_enb_ul_ = nullptr; }
    for (auto& kv : harq_buffers_) { srsran_softbuffer_rx_free(kv.second); delete kv.second; }
    harq_buffers_.clear();
}

/* Fetch (or create) the persistent rx softbuffer for this UE's HARQ process.
   Reset it only on a new transmission; on a retransmission it keeps the prior
   soft bits so srsran_pusch_decode accumulates. Bounded map with FIFO eviction
   so a long capture with many RNTIs cannot grow without limit. */
srsran_softbuffer_rx_t* PUSCH_Decoder::harq_get(uint16_t rnti, uint32_t pid, bool is_new_tx)
{
    uint64_t key = ((uint64_t)rnti << 8) | (pid & 0xff);
    auto it = harq_buffers_.find(key);
    srsran_softbuffer_rx_t* sb;
    if (it == harq_buffers_.end()) {
        if (harq_buffers_.size() >= 128) {  // bound live HARQ buffers (each ~MAX_PRB)
            auto victim = harq_buffers_.begin();
            srsran_softbuffer_rx_free(victim->second); delete victim->second;
            harq_buffers_.erase(victim);
        }
        sb = new srsran_softbuffer_rx_t;
        srsran_softbuffer_rx_init(sb, SRSRAN_MAX_PRB);
        harq_buffers_[key] = sb;
        is_new_tx = true;  // first sighting => treat as a fresh transmission
    } else {
        sb = it->second;
    }
    if (is_new_tx) srsran_softbuffer_rx_reset(sb);
    return sb;
}

/* Lazily build the UplinkSyncAdapter and its PRIVATE enb_ul (own FFT + input
   buffer) so the wide per-grant search runs entirely on scratch — the live
   original_buffer / enb_ul are never mutated by the search. Cell + DMRS are copied
   from the live enb_ul / ul_cfg exactly as the nominal decoder was configured. */
void PUSCH_Decoder::ensure_sync_adapter()
{
    if (sync_adapter_) return;
    adapter_in_buf_.assign(3 * SRSRAN_SF_LEN_PRB(100), cf_t{});
    adapter_enb_ul_ = new srsran_enb_ul_t;
    memset(adapter_enb_ul_, 0, sizeof(*adapter_enb_ul_));
    if (srsran_enb_ul_init(adapter_enb_ul_, adapter_in_buf_.data(), 110)) {
        delete adapter_enb_ul_; adapter_enb_ul_ = nullptr; return;
    }
    srsran_enb_ul_set_cell(adapter_enb_ul_, enb_ul.cell, &ul_cfg.dmrs, NULL);

    UplinkSyncConfig scfg;
    scfg.search_range   = []{ const char* e = getenv("UL_SYNC_RANGE");   return e ? atoi(e) : 1024; }();
    scfg.coarse_step    = []{ const char* e = getenv("UL_SYNC_STEP");    return e ? atoi(e) : 16;   }();
    scfg.max_candidates = []{ const char* e = getenv("UL_SYNC_CAND");    return e ? atoi(e) : 3;    }();
    scfg.timing_mode    = TimingMode::FULL;

    sync_adapter_ = new UplinkSyncAdapter();
    if (!sync_adapter_->configure(adapter_enb_ul_, enb_ul.cell, ul_cfg.dmrs, scfg)) {
        delete sync_adapter_; sync_adapter_ = nullptr;
    }
}

int PUSCH_Decoder::decode_rrc_connection_request(DCI_UL &decoding_mem, uint8_t *sdu_ptr, int length)
{
    int ret = SRSRAN_ERROR;
    ul_ccch_msg_s ul_ccch_msg;
    asn1::cbit_ref bref(sdu_ptr, length);
    int asn1_result = ul_ccch_msg.unpack(bref);
    if (asn1_result == asn1::SRSASN_SUCCESS && ul_ccch_msg.msg.type() == ul_ccch_msg_type_c::types_opts::c1)
    {
        if (ul_ccch_msg.msg.c1().type().value == ul_ccch_msg_type_c::c1_c_::types::rrc_conn_request)
        {
            asn1::rrc::rrc_conn_request_s con_request = ul_ccch_msg.msg.c1().rrc_conn_request();
            rrc_conn_request_r8_ies_s *msg_r8 = &con_request.crit_exts.rrc_conn_request_r8();
            if (msg_r8->ue_id.type() == init_ue_id_c::types::s_tmsi)
            {
                uint32_t m_tmsi = msg_r8->ue_id.s_tmsi().m_tmsi.to_number();
                uint8_t mmec = msg_r8->ue_id.s_tmsi().mmec.to_number();
                std::stringstream ss;
                ss << std::hex << m_tmsi;
                std::string m_tmsi_str = ss.str();
                print_api(ul_sf.tti, decoding_mem.rnti, ID_TMSI, m_tmsi_str, MSG_CON_REQ);
                mcstracking->increase_nof_api_msg();
                ret = SRSRAN_SUCCESS;
            }
            else if (msg_r8->ue_id.type() == init_ue_id_c::types::random_value)
            {
                std::string rd_value_bitstream = msg_r8->ue_id.random_value().to_string();
                std::stringstream ss;
                for (int i = 0; i < rd_value_bitstream.length(); i += 4)
                {
                    std::string hex_str = rd_value_bitstream.substr(i, 4);
                    int hex_value = stoi(hex_str, nullptr, 2);
                    ss << std::hex << hex_value;
                }
                std::string random_value_str = ss.str();
                random_value_str = random_value_str.substr(2);
                print_api(ul_sf.tti, decoding_mem.rnti, ID_RAN_VAL, random_value_str, MSG_CON_REQ);
                mcstracking->increase_nof_api_msg();
                ret = SRSRAN_SUCCESS;
            }
        }
        else if (ul_ccch_msg.msg.c1().type().value == ul_ccch_msg_type_c::c1_c_::types::rrc_conn_reest_request)
        {
            // Do nothing
        }
    }
    return ret;
}

/*UEcapability information or RRC Connection Setup Complete + Attach request*/
int PUSCH_Decoder::decode_ul_dcch(DCI_UL &decoding_mem, uint8_t *sdu_ptr, int length)
{
    int ret = SRSRAN_ERROR;
    ul_dcch_msg_s ul_dcch_msg;
    asn1::cbit_ref bref(sdu_ptr, length);
    int asn1_result = ul_dcch_msg.unpack(bref);
    if (asn1_result == asn1::SRSASN_SUCCESS && ul_dcch_msg.msg.type() == ul_dcch_msg_type_c::types_opts::c1)
    {
        if (ul_dcch_msg.msg.c1().type() == ul_dcch_msg_type_c::c1_c_::types::ue_cap_info && (api_mode == 1 || api_mode == 3))
        { //&& UECapability
            // printf("[API] SF: %d-%d, RNTI: %d, Found UECapabilityInformation messages \n", ul_sf.tti/10, ul_sf.tti%10, decoding_mem.rnti);
            print_api(ul_sf.tti, decoding_mem.rnti, -1, "-", MSG_UE_CAP);
            mcstracking->increase_nof_api_msg();
            ret = SRSRAN_SUCCESS;
        }
        else if (ul_dcch_msg.msg.c1().type() == ul_dcch_msg_type_c::c1_c_::types::rrc_conn_setup_complete && (api_mode == 2 || api_mode == 3))
        { // IMSI catching, IMSI attach
            // printf("[API] SF: %d-%d, RNTI: %d, Found RRC Connection Setup Complete \n", ul_sf.tti/10, ul_sf.tti%10, decoding_mem.rnti);
            asn1::rrc::rrc_conn_setup_complete_s msg = ul_dcch_msg.msg.c1().rrc_conn_setup_complete();
            rrc_conn_setup_complete_r8_ies_s *msg_r8 = &msg.crit_exts.c1().rrc_conn_setup_complete_r8();
            srsran::unique_byte_buffer_t nas_msg = srsran::make_byte_buffer();
            nas_msg->N_bytes = msg_r8->ded_info_nas.size();
            memcpy(nas_msg->msg, msg_r8->ded_info_nas.data(), nas_msg->N_bytes);
            // parse nas_msg inside rrc connection setup complete to nas decoder
            ret = decode_nas_ul(decoding_mem, nas_msg->msg, nas_msg->N_bytes);
        }
        else if (ul_dcch_msg.msg.c1().type() == ul_dcch_msg_type_c::c1_c_::types::ul_info_transfer && (api_mode == 2 || api_mode == 3))
        { // IMSI catching, Identity response
            // printf("[API] SF: %d-%d, RNTI: %d, Found UL Infor Transfer \n", ul_sf.tti/10, ul_sf.tti%10, decoding_mem.rnti);
            srsran::unique_byte_buffer_t nas_msg = srsran::make_byte_buffer();
            nas_msg->N_bytes = ul_dcch_msg.msg.c1()
                                   .ul_info_transfer()
                                   .crit_exts.c1()
                                   .ul_info_transfer_r8()
                                   .ded_info_type.ded_info_nas()
                                   .size();
            memcpy(nas_msg->msg,
                   ul_dcch_msg.msg.c1()
                       .ul_info_transfer()
                       .crit_exts.c1()
                       .ul_info_transfer_r8()
                       .ded_info_type.ded_info_nas()
                       .data(),
                   nas_msg->N_bytes);
            ret = decode_nas_ul(decoding_mem, nas_msg->msg, nas_msg->N_bytes);
        }
    }
    return ret;
}

/*Identity response with IMSI/IMEI or IMSI attach*/
int PUSCH_Decoder::decode_nas_ul(DCI_UL &decoding_mem, uint8_t *sdu_ptr, int length)
{
    int ret = SRSRAN_ERROR;
    s1ap_pdu_c rx_pdu; // asn1::s1ap::s1ap_pdu_c //using s1ap_pdu_t = asn1::s1ap::s1ap_pdu_c;
    cbit_ref bref(sdu_ptr, length);
    int asn1_result = rx_pdu.unpack(bref);
    srsran::unique_byte_buffer_t nas_msg = srsran::make_byte_buffer();
    memcpy(nas_msg->msg, sdu_ptr, length);
    nas_msg->N_bytes = length;
    uint8_t pd, msg_type, sec_hdr_type;
    LIBLTE_ERROR_ENUM err;
    liblte_mme_parse_msg_sec_header((LIBLTE_BYTE_MSG_STRUCT *)nas_msg.get(), &pd, &sec_hdr_type);
    if (sec_hdr_type != LIBLTE_MME_SECURITY_HDR_TYPE_INTEGRITY_AND_CIPHERED &&
        sec_hdr_type != LIBLTE_MME_SECURITY_HDR_TYPE_INTEGRITY_AND_CIPHERED_WITH_NEW_EPS_SECURITY_CONTEXT)
    {
        liblte_mme_parse_msg_header((LIBLTE_BYTE_MSG_STRUCT *)nas_msg.get(), &pd, &msg_type);

        if (msg_type == LIBLTE_MME_MSG_TYPE_IDENTITY_RESPONSE)
        {
            LIBLTE_MME_ID_RESPONSE_MSG_STRUCT identity_response;
            LIBLTE_BYTE_MSG_STRUCT msg;
            memcpy(&msg.msg, nas_msg->msg, nas_msg->N_bytes);
            msg.N_bytes = nas_msg->N_bytes;
            err = liblte_mme_unpack_identity_response_msg(&msg, &identity_response);
            if (err == LIBLTE_SUCCESS && identity_response.mobile_id.type_of_id == LIBLTE_MME_MOBILE_ID_TYPE_IMSI)
            {
                std::string imsi_str = "";
                for (int z = 0; z < 15; z++)
                {
                    imsi_str.append(std::to_string(identity_response.mobile_id.imsi[z]));
                }
                print_api(ul_sf.tti, decoding_mem.rnti, ID_IMSI, imsi_str, MSG_ID_RES);
                mcstracking->increase_nof_api_msg();
                ret = SRSRAN_SUCCESS;
            }
            else if (err == LIBLTE_SUCCESS && identity_response.mobile_id.type_of_id == LIBLTE_MME_MOBILE_ID_TYPE_IMEI)
            {
                std::string imei_str = "";
                for (int z = 0; z < 15; z++)
                {
                    imei_str.append(std::to_string(identity_response.mobile_id.imei[z]));
                }
                print_api(ul_sf.tti, decoding_mem.rnti, ID_IMEI, imei_str, MSG_ID_RES);
                mcstracking->increase_nof_api_msg();
                ret = SRSRAN_SUCCESS;
            }
            else if (err == LIBLTE_SUCCESS && identity_response.mobile_id.type_of_id == LIBLTE_MME_MOBILE_ID_TYPE_IMEISV)
            {
                std::string imei_str = "";
                for (int z = 0; z < 16; z++)
                {
                    imei_str.append(std::to_string(identity_response.mobile_id.imeisv[z]));
                }
                print_api(ul_sf.tti, decoding_mem.rnti, ID_IMEISV, imei_str, MSG_ID_RES);
                mcstracking->increase_nof_api_msg();
                ret = SRSRAN_SUCCESS;
            }
        }
        else if (err == LIBLTE_SUCCESS && msg_type == LIBLTE_MME_MSG_TYPE_ATTACH_REQUEST)
        {
            LIBLTE_MME_ATTACH_REQUEST_MSG_STRUCT attach_req;
            LIBLTE_BYTE_MSG_STRUCT msg;
            memcpy(&msg.msg, nas_msg->msg, nas_msg->N_bytes);
            msg.N_bytes = nas_msg->N_bytes;
            /*Unpack Attach request*/
            err = liblte_mme_unpack_attach_request_msg(&msg, &attach_req);
            if (attach_req.eps_mobile_id.type_of_id == LIBLTE_MME_EPS_MOBILE_ID_TYPE_IMSI)
            {
                std::string imsi_str = "";
                for (int z = 0; z < 15; z++)
                {
                    imsi_str.append(std::to_string(attach_req.eps_mobile_id.imsi[z]));
                }
                print_api(ul_sf.tti, decoding_mem.rnti, ID_IMSI, imsi_str, MSG_ATT_REQ);
                mcstracking->increase_nof_api_msg();
                ret = SRSRAN_SUCCESS;
            }
            else if (attach_req.eps_mobile_id.type_of_id == LIBLTE_MME_EPS_MOBILE_ID_TYPE_GUTI)
            {
                std::stringstream ss;
                ss << std::hex << attach_req.eps_mobile_id.guti.m_tmsi;
                std::string m_tmsi_str = ss.str();
                print_api(ul_sf.tti, decoding_mem.rnti, ID_TMSI, m_tmsi_str, MSG_ATT_REQ);
                mcstracking->increase_nof_api_msg();
                ret = SRSRAN_SUCCESS;
            }
            else if (attach_req.eps_mobile_id.type_of_id == LIBLTE_MME_EPS_MOBILE_ID_TYPE_IMEI)
            {
                std::string imei_str = "";
                for (int z = 0; z < 15; z++)
                {
                    imei_str.append(std::to_string(attach_req.eps_mobile_id.imei[z]));
                }
                print_api(ul_sf.tti, decoding_mem.rnti, ID_IMEI, imei_str, MSG_ATT_REQ);
                mcstracking->increase_nof_api_msg();
                ret = SRSRAN_SUCCESS;
            }
        }
    }
    return ret;
}

/* Run decode function after setup config, grant*/
void PUSCH_Decoder::decode_run(std::string info, DCI_UL &decoding_mem, std::string modulation_mode, float falcon_signal_power)
{
    int mcs_idx = ul_cfg.pusch.grant.tb.mcs_idx;
    // HARQ combining: on a retransmission we must NOT reset — the soft bits from
    // prior transmissions must remain so this decode accumulates onto them.
    if (!harq_no_reset_)
        srsran_softbuffer_rx_reset_tbs(ul_cfg.pusch.softbuffers.rx, ul_cfg.pusch.grant.tb.tbs);

    /*Do channel estimation to calculate timing difference between UL & DL subframes, because of diffrent propagation times*/
    int ret = srsran_chest_ul_estimate_pusch(&enb_ul.chest, &ul_sf, &ul_cfg.pusch, enb_ul.sf_symbols, &enb_ul.chest_res);

    /*Use channel estimation result to perform channel equalizer to compensate the time delay*/
    pusch_res.crc = false; // reset crc result
    if (ret == SRSRAN_SUCCESS)
    {
        ret = srsran_pusch_decode(&enb_ul.pusch, &ul_sf, &ul_cfg.pusch, &enb_ul.chest_res, enb_ul.sf_symbols, &pusch_res);
    }

    /* Reject all-zero transport blocks (turbo-on-noise false positives).
       At low SNR the turbo decoder converges to the all-zeros codeword; since
       CRC-24 of all-zeros is all-zeros, that TB PASSES CRC and would be written
       as a spurious frame (Wireshark dissects an all-zero UL-CCCH as
       rrcConnectionReestablishmentRequest with zero identity). A valid MAC PDU is
       never all-zero — even a CCCH message carries a non-zero RRC SDU, and any
       data/padding subheader byte is non-zero — so an all-zero TB is always noise.
       Force CRC=fail so it is excluded from the pcap, the yield counter, HARQ
       combining and the offset-retry alike. Disable with UL_KEEP_ZERO_TB=1. */
    if (pusch_res.crc && ul_cfg.pusch.grant.tb.tbs > 0)
    {
        static const bool keep_zero = (getenv("UL_KEEP_ZERO_TB") != nullptr);
        if (!keep_zero)
        {
            const int nbytes = ul_cfg.pusch.grant.tb.tbs / 8;
            bool all_zero = true;
            for (int b = 0; b < nbytes; b++) { if (pusch_res.data[b] != 0) { all_zero = false; break; } }
            if (all_zero)
            {
                pusch_res.crc = false;
                static std::atomic<uint64_t> zc{0};
                uint64_t n = zc.fetch_add(1) + 1;
                if (getenv("UL_RATE_DIAG") && (n <= 5 || n % 100 == 0))
                    printf("[ZEROTB] rejected all-zero TB #%llu (rnti=0x%x tti=%u tbs=%u snr=%.1f) — noise false positive\n",
                           (unsigned long long)n, ul_cfg.pusch.rnti, ul_sf.tti,
                           ul_cfg.pusch.grant.tb.tbs, enb_ul.chest_res.snr_db);
            }
        }
    }

    /*Only print debug when SNR of RNTI >= 1 */
    if ((en_debug) && (enb_ul.chest_res.snr_db >= 2) ) // && (enb_ul.chest_res.snr_db >= 1)
    { //|| target_rnti !=0
        float signal_power = enb_ul.chest_res.snr_db;
        float falcon_signal_power = 0.0f;
        float tmp_sum = 0.0f;
        {
            const auto& rbpow = sf_power->getRBPowerUL();
            for (uint32_t rb_idx = 0; rb_idx < ul_cfg.pusch.grant.L_prb; rb_idx++)
            {
                uint32_t prb = ul_cfg.pusch.grant.n_prb[0] + rb_idx;
                if (prb < rbpow.size()) tmp_sum += rbpow[prb];   // was .at() -> threw & killed the worker on bad grants
            }
        }
        falcon_signal_power = (ul_cfg.pusch.grant.L_prb > 0) ? tmp_sum / ul_cfg.pusch.grant.L_prb : 0.0f;
        print_debug(decoding_mem, info, modulation_mode, signal_power, enb_ul.chest_res.noise_estimate_dbm, falcon_signal_power);
    }

    if (pusch_res.crc == true && ul_cfg.pusch.grant.tb.tbs != 0)
    {
        int length = ul_cfg.pusch.grant.tb.tbs / 8;
        pcapwriter->write_ul_crnti(pusch_res.data, length, ul_cfg.pusch.rnti, ul_sf.tti);

        if (key_store_ &&
            key_store_->has_ue(ul_cfg.pusch.rnti) &&
            key_store_->is_security_active(ul_cfg.pusch.rnti)) {
            key_store_->process_ul_mac_pdu(ul_cfg.pusch.rnti,
                                           pusch_res.data, length, ul_sf.tti);
        }

        /*Update max UL modulation scheme 16/64/256QAM when mcs index > 20*/
        if (mcs_idx > 20 && decoding_mem.mcs_mod == UL_SNIFFER_UNKNOWN_MOD)
        {
            if (info == "[PUSCH-16 ]")
            {
                mcstracking->update_RNTI_ul(decoding_mem.rnti, UL_SNIFFER_16QAM_MAX);
            }
            else if (info == "[PUSCH-64 ]")
            {
                mcstracking->update_RNTI_ul(decoding_mem.rnti, UL_SNIFFER_64QAM_MAX);
            }
            else if (info == "[PUSCH-256]")
            {
                mcstracking->update_RNTI_ul(decoding_mem.rnti, UL_SNIFFER_256QAM_MAX);
            }
            /*When mcs index < 20, only 2 possible max modulation scheme 16/256QAM */
        }
        else if (mcs_idx > 0 && decoding_mem.mcs_mod == UL_SNIFFER_UNKNOWN_MOD && info == "[PUSCH-256]")
        {
            mcstracking->update_RNTI_ul(decoding_mem.rnti, UL_SNIFFER_256QAM_MAX);
        }
        decoding_mem.decoded = 1;

        /* [API] Decode RRC Connection Setup and UECapabilityInformation*/
        int api_ret = SRSRAN_ERROR;
        if (decoding_mem.is_rar_gant && (api_mode == 0 || api_mode == 3))
        {
            srsran::sch_pdu pdu(10, srslog::fetch_basic_logger("MAC"));
            pdu.init_rx(length, true);
            pdu.parse_packet(pusch_res.data);
            while (pdu.next())
            {
                if (pdu.get()->is_sdu())
                {
                    int payload_length = pdu.get()->get_payload_size();
                    uint8_t *sdu_ptr = pdu.get()->get_sdu_ptr();
                    /* Decode RRC Connection Request when found valid sdu from MAC pdu*/
                    ret = decode_rrc_connection_request(decoding_mem, sdu_ptr, payload_length);
                }
            }
            if (ret == SRSRAN_SUCCESS)
            {
                pcapwriter->write_ul_crnti_api(pusch_res.data, length, ul_cfg.pusch.rnti, ul_sf.tti);
                api_ret = SRSRAN_ERROR;
            }
        }
        else if (api_mode > 0)
        { // Decode DCCH (api mode 1,2,3)
            srsran::sch_pdu pdu(10, srslog::fetch_basic_logger("MAC"));
            pdu.init_rx(length, true);
            pdu.parse_packet(pusch_res.data);
            while (pdu.next())
            {
                /*LCID 1 & 2*/
                if (pdu.get()->is_sdu() && (pdu.get()->get_sdu_lcid() == 1 || pdu.get()->get_sdu_lcid() == 2))
                {
                    int payload_length = pdu.get()->get_payload_size();
                    uint8_t *sdu_ptr = pdu.get()->get_sdu_ptr();
                    /*Only RLC data pdu*/
                    if (!rlc_am_is_control_pdu(sdu_ptr))
                    {
                        rlc_amd_pdu_header_t header = {};
                        uint32_t payload_len = payload_length;
                        rlc_am_read_data_pdu_header(&sdu_ptr, &payload_len, &header);
                        /*Only decode full frame, not fragment of frame (fi == 0 means full RRC frame)*/
                        if (!header.rf && header.fi == 0)
                        {
                            srsran::unique_byte_buffer_t pdcp_pdu = srsran::make_byte_buffer();
                            pdcp_pdu->N_bytes = payload_len;
                            memcpy(pdcp_pdu->msg, sdu_ptr, pdcp_pdu->N_bytes);
                            /*Discard pdcp header , assume that pdcp header size = 1 byte*/
                            pdcp_pdu->msg += 1;
                            pdcp_pdu->N_bytes -= 1;
                            uint8_t pd, msg_type, sec_hdr_type;
                            liblte_mme_parse_msg_sec_header((LIBLTE_BYTE_MSG_STRUCT *)pdcp_pdu.get(), &pd, &sec_hdr_type);
                            /*Only decode NAS without encryption*/
                            if ((sec_hdr_type == LIBLTE_MME_SECURITY_HDR_TYPE_PLAIN_NAS) ||
                                (sec_hdr_type == LIBLTE_MME_SECURITY_HDR_TYPE_INTEGRITY) ||
                                (sec_hdr_type == LIBLTE_MME_SECURITY_HDR_TYPE_INTEGRITY_WITH_NEW_EPS_SECURITY_CONTEXT))
                            {
                                // /*Discard pdcp header , assume that pdcp header size = 1 byte*/
                                // pdcp_pdu->msg       += 1;
                                // pdcp_pdu->N_bytes   -= 1;

                                /* Decode UL DCCH messages*/
                                api_ret = decode_ul_dcch(decoding_mem, pdcp_pdu->msg, pdcp_pdu->N_bytes);
                            }
                        }
                    }
                }
            }
            if (api_ret == SRSRAN_SUCCESS)
            {
                pcapwriter->write_ul_crnti_api(pusch_res.data, length, ul_cfg.pusch.rnti, ul_sf.tti);
                api_ret = SRSRAN_ERROR;
            }
        }
    }

    /* ================= UL DMRS diagnostic (opt-in) =================
     * Enabled only when the env var UL_DMRS_DIAG is set. For grants whose raw
     * post-FFT RB power clears UL_DMRS_DIAG_PWR (dB, default 0), dump the parsed
     * DMRS common config once, then re-run the SAME estimator this decode uses
     * across all 8 DMRS cyclic shifts (n_dmrs 0..7) on the current sf_symbols.
     *
     * Purpose: distinguish a DMRS *sequence mismatch* (strong RB power but the
     * DMRS-correlation SNR is pinned low for the signaled n_dmrs) from a genuine
     * RF/interference limit. If a cyclic shift OTHER than the DCI-signaled one
     * yields a markedly higher SNR, our n_dmrs extraction is wrong; if ALL eight
     * cap at the same low SNR, the sequence base/hopping config is wrong or the
     * energy is not the target UE's. Clobbers enb_ul.chest_res, so it runs after
     * the real decode for this attempt is complete. */
    if (getenv("UL_DMRS_DIAG"))
    {
        float diag_thr = 0.0f;
        if (const char* t = getenv("UL_DMRS_DIAG_PWR")) diag_thr = atof(t);

        /* raw post-FFT power across the grant's PRBs (same measure as the
           existing debug block / §9 rawRBpow) */
        float raw_pow = 0.0f;
        {
            const auto& rbpow = sf_power->getRBPowerUL();
            for (uint32_t rb_idx = 0; rb_idx < ul_cfg.pusch.grant.L_prb; rb_idx++)
            {
                uint32_t prb = ul_cfg.pusch.grant.n_prb[0] + rb_idx;
                if (prb < rbpow.size()) raw_pow += rbpow[prb];
            }
            raw_pow = (ul_cfg.pusch.grant.L_prb > 0) ? raw_pow / ul_cfg.pusch.grant.L_prb : 0.0f;
        }

        if (raw_pow >= diag_thr && ul_cfg.pusch.grant.L_prb > 0)
        {
            static bool printed_cfg = false;
            if (!printed_cfg)
            {
                printed_cfg = true;
                printf("[ULDIAG] cell.id=%d cp=%d nof_prb=%d | DMRS cfg: "
                       "cyclic_shift=%u delta_ss=%u group_hop=%d seq_hop=%d\n",
                       enb_ul.cell.id, enb_ul.cell.cp, enb_ul.cell.nof_prb,
                       ul_cfg.dmrs.cyclic_shift, ul_cfg.dmrs.delta_ss,
                       (int)ul_cfg.dmrs.group_hopping_en,
                       (int)ul_cfg.dmrs.sequence_hopping_en);
            }

            srsran_pusch_cfg_t sweep_cfg = ul_cfg.pusch;
            sweep_cfg.meas_ta_en = true;
            uint32_t signaled = ul_cfg.pusch.grant.n_dmrs;
            printf("[ULDIAG] SF %d.%d RNTI %d L_prb=%u n_prb=%u mcs=%d rawRBpow=%.1f "
                   "signaled_n_dmrs=%u crc=%d | SNR(dB) by cyclic-shift:",
                   ul_sf.tti / 10, ul_sf.tti % 10, ul_cfg.pusch.rnti,
                   ul_cfg.pusch.grant.L_prb, ul_cfg.pusch.grant.n_prb[0],
                   ul_cfg.pusch.grant.tb.mcs_idx, raw_pow, signaled, (int)pusch_res.crc);
            for (uint32_t cs = 0; cs < 8; cs++)
            {
                sweep_cfg.grant.n_dmrs = cs;
                int r = srsran_chest_ul_estimate_pusch(&enb_ul.chest, &ul_sf, &sweep_cfg,
                                                       enb_ul.sf_symbols, &enb_ul.chest_res);
                float s = (r == SRSRAN_SUCCESS) ? enb_ul.chest_res.snr_db : NAN;
                printf(" [%u]%s%.1f", cs, (cs == signaled) ? "*" : "=", s);
            }
            printf("\n");

            /* TIME-OFFSET sweep (UL_TOFF_DIAG). Re-FFT the raw subframe at a
               range of sample offsets and report chest SNR at the signaled
               n_dmrs for each. Tests whether a FIXED inter-radio time
               misalignment is capping SNR: a clear peak well away from 0 that
               beats offset-0 by many dB means the UL radio window is offset
               (fixable by applying that global shift); a flat profile means the
               ~3 dB ceiling is genuine RF. Needs the pre-FFT snapshot, which is
               only taken when offset retry is enabled (multi_ul_offset != 0,
               i.e. UL/DUAL). Restores the nominal window (refft at 0) so the
               live decode is unaffected. */
            if (getenv("UL_TOFF_DIAG") && multi_ul_offset != 0)
            {
                srsran_pusch_cfg_t toff_cfg = ul_cfg.pusch;
                toff_cfg.meas_ta_en = true;
                toff_cfg.grant.n_dmrs = signaled;
                float best_s = -1e9f; int best_off = 0;
                printf("[ULTOFF] SF %d.%d RNTI %d rawRBpow=%.1f | SNR(dB) by sample-offset:",
                       ul_sf.tti / 10, ul_sf.tti % 10, ul_cfg.pusch.rnti, raw_pow);
                for (int off = -600; off <= 600; off += 60)
                {
                    if (!refft_at_offset(off)) { printf(" [%d]oob", off); continue; }
                    int r = srsran_chest_ul_estimate_pusch(&enb_ul.chest, &ul_sf, &toff_cfg,
                                                           enb_ul.sf_symbols, &enb_ul.chest_res);
                    float s = (r == SRSRAN_SUCCESS) ? enb_ul.chest_res.snr_db : NAN;
                    if (r == SRSRAN_SUCCESS && s > best_s) { best_s = s; best_off = off; }
                    printf(" %d:%.1f", off, s);
                }
                printf(" | PEAK %.1fdB @ offset %d samples\n", best_s, best_off);
                refft_at_offset(0); // restore nominal window for the live decode
            }
        }
    }
}

void print_ul_grant_dci_0(srsran_pusch_grant_t &ul_grant, uint16_t tti, uint16_t rnti)
{
    std::cout << "[DCI] SF: " << tti / 10 << ":" << tti % 10 << "-RNTI: " << rnti << " -L_prb: " << ul_grant.L_prb << " -MOD: " << ul_grant.tb.mod << " -tbs: " << ul_grant.tb.tbs << " -RV: " << ul_grant.tb.rv << std::endl;
}

/* Re-run the UL FFT on a window shifted by sample_offset samples.
 *
 * DSP background: the working enb_ul FFT object (built with the GURU plan) is
 * permanently bound to original_buffer[0] and applies its frequency shift in
 * place, so it cannot be retargeted to a different window after the nominal
 * pass. Instead we keep a clean pre-FFT snapshot of the raw subframe in
 * sf_buffer_offset[0] and run the explicit-buffer variant srsran_ofdm_rx_sf_ng
 * on a shifted copy held in sf_buffer_offset[1]. The output goes straight into
 * enb_ul.sf_symbols, so decode_run()/chest see the re-centred symbols with no
 * other change.
 *
 * Window math: sample_offset > 0 reads later samples (use when the UL arrives
 * late at our receiver, i.e. chest_res.ta_us > 0); sample_offset < 0 reads
 * earlier samples. The copy is done into the scratch with leading zero guard so
 * negative offsets never underflow original_buffer[0].
 */
bool PUSCH_Decoder::refft_at_offset(int sample_offset)
{
    const uint32_t sf_len   = SRSRAN_SF_LEN_PRB(enb_ul.cell.nof_prb);
    // FFT needs the whole subframe plus a little look-back/ahead; the scratch
    // buffers are allocated for 3*SF_LEN(100) so 2*SF_LEN is always safe.
    const uint32_t copy_len = 2 * sf_len;
    // original_buffer[0] has 3*SF_LEN(100) headroom; reading [off, off+copy_len)
    // must stay inside that. Reject offsets that would exceed it.
    const uint32_t headroom = 3 * SRSRAN_SF_LEN_PRB(100);
    if (sample_offset >= 0) {
        if ((uint32_t)sample_offset + copy_len > headroom) return false;
    } else {
        if ((uint32_t)(-sample_offset) > copy_len) return false; // guard too small
    }

    cf_t* snap    = buffer_offset[0]; // clean pre-FFT snapshot (== sf_buffer_offset[0])
    cf_t* working = buffer_offset[1]; // shifted copy fed to the FFT (== sf_buffer_offset[1])
    // working is freq-shifted in place by srsran_ofdm_rx_sf_ng; snap must stay
    // pristine so it can seed every offset. They are distinct allocations.
    assert(snap != working);

    srsran_vec_cf_zero(working, copy_len);
    if (sample_offset >= 0) {
        // Source window [off, off+copy_len) -> working[0..]
        memcpy(working, snap + sample_offset, sizeof(cf_t) * copy_len);
    } else {
        // Shift right by |off|: leading |off| samples stay zero (guard), so the
        // FFT's internal look-back lands on zeros instead of underflowing.
        uint32_t shift = (uint32_t)(-sample_offset);
        memcpy(working + shift, snap, sizeof(cf_t) * (copy_len - shift));
    }

    srsran_ofdm_rx_sf_ng(&enb_ul.fft, working, enb_ul.sf_symbols);
    return true;
}

/* Full per-grant MCS-table decode sequence, run on the symbols currently in
 * enb_ul.sf_symbols. Returns the final CRC result. Side effects on success
 * (pcap write, key store, MCS update) happen inside decode_run exactly once. */
bool PUSCH_Decoder::decode_grant(DCI_UL &decoding_mem)
{
    /*Setup uplink config for decoding*/
    ul_cfg.pusch.rnti = decoding_mem.rnti;
    ul_cfg.pusch.enable_64qam = false; // check here for 64/16QAM
    ul_cfg.pusch.meas_ta_en = true;    // enable ta measurement
    ul_cfg.pusch.grant = *decoding_mem.ran_ul_grant;
    int mcs_idx = ul_cfg.pusch.grant.tb.mcs_idx;
    pusch_res.crc = false;
    /*Get Number of ack which was calculated in Subframe worker last 4 ms*/
    ul_cfg.pusch.uci_cfg.ack[0].nof_acks = decoding_mem.nof_ack;

    /*get UE-specific configuration from database*/
    ltesniffer_ue_spec_config_t ue_config = mcstracking->get_ue_config_rnti(decoding_mem.rnti);
    ul_cfg.pusch.uci_cfg.cqi.type = ue_config.cqi_config.type;
    ul_cfg.pusch.uci_offset = ue_config.uci_config;
    /* The UE-specific UCI offsets come from dedicated RRC config we often never
       captured; an unlearned UE leaves I_offset_cqi=0, which srsran_sch_beta_cqi
       rejects (valid range 2..15) and floods stderr with "Invalid input 0" on
       every aperiodic-CSI grant. Fall back to the standard default (36.213
       Table 8.6.3-3 index 8) when the learned value is out of range. */
    if (ul_cfg.pusch.uci_offset.I_offset_cqi < 2 || ul_cfg.pusch.uci_offset.I_offset_cqi > 15) {
        ul_cfg.pusch.uci_offset.I_offset_cqi = 8;
    }
    /*If eNB requests for Aperiodic CSI report*/
    if (decoding_mem.ran_ul_dci->cqi_request == true)
    {
        ul_cfg.pusch.uci_cfg.cqi.four_antenna_ports = false;
        ul_cfg.pusch.uci_cfg.cqi.data_enable = true;
        ul_cfg.pusch.uci_cfg.cqi.pmi_present = false;
        ul_cfg.pusch.uci_cfg.cqi.rank_is_not_one = false;
        ul_cfg.pusch.uci_cfg.cqi.N = ul_sniffer_cqi_hl_get_no_subbands(enb_ul.cell.nof_prb);
        ul_cfg.pusch.uci_cfg.cqi.ri_len = 1; // only for TM3 and TM4 // srsran_ri_nof_bits(&enb_ul.cell)
    }
    else
    {
        ul_cfg.pusch.uci_cfg.cqi.data_enable = false;
        ul_cfg.pusch.uci_cfg.cqi.ri_len = 0;
    }
    /*Find correct mcs table from database*/
    ul_sniffer_mod_tracking_t mcs_mod = mcstracking->find_tracking_info_RNTI_ul(decoding_mem.rnti);
    std::string modulation_mode = "Unknown";
    int ret = SRSRAN_ERROR;
    /*If mcs_idx > 20 then check mcstracking to decode properly*/
    if (mcs_idx > 20 && mcs_idx < 29)
    {
        switch (mcs_mod)
        {
        case UL_SNIFFER_16QAM_MAX:
            decoding_mem.mcs_mod = UL_SNIFFER_16QAM_MAX;
            ul_cfg.pusch.enable_64qam = false;
            modulation_mode = modulation_mode_string(mcs_idx, false);
            decode_run("[PUSCH-16 ]", decoding_mem, modulation_mode, 0);
            break;
        case UL_SNIFFER_64QAM_MAX:
            decoding_mem.mcs_mod = UL_SNIFFER_64QAM_MAX;
            ul_cfg.pusch.enable_64qam = true;
            modulation_mode = modulation_mode_string(mcs_idx, true);
            decode_run("[PUSCH-64 ]", decoding_mem, modulation_mode, 0);
            break;
        case UL_SNIFFER_256QAM_MAX:
            decoding_mem.mcs_mod = UL_SNIFFER_256QAM_MAX;
            ul_cfg.pusch.enable_64qam = true;
            modulation_mode = modulation_mode_string_256(mcs_idx);
            ul_cfg.pusch.grant = *decoding_mem.ran_ul_grant_256;
            if (ul_cfg.pusch.grant.L_prb < 110 && ul_cfg.pusch.grant.L_prb > 0)
            {
                decode_run("[PUSCH-256]", decoding_mem, modulation_mode, 0);
            }
            break;
        case UL_SNIFFER_UNKNOWN_MOD:
            // string for debug:
            modulation_mode = modulation_mode_string(mcs_idx, true);
            /* reset buffer and CRC checking */
            pusch_res.crc = false;
            if (mcs_idx <= 28)
            {
                /*Compute avg signal power for PRB in UL grant*/
                float falcon_signal_power = 0.0f;
                float tmp_sum = 0.0f;
                {
                    const auto& rbpow = sf_power->getRBPowerUL();
                    for (uint32_t rb_idx = 0; rb_idx < ul_cfg.pusch.grant.L_prb; rb_idx++)
                    {
                        uint32_t prb = ul_cfg.pusch.grant.n_prb[0] + rb_idx;
                        if (prb < rbpow.size()) tmp_sum += rbpow[prb];
                    }
                }
                falcon_signal_power = (ul_cfg.pusch.grant.L_prb > 0) ? tmp_sum / ul_cfg.pusch.grant.L_prb : 0.0f;
                decode_run("[PUSCH-16 ]", decoding_mem, modulation_mode, falcon_signal_power);

                if (pusch_res.crc == false && mcs_idx > 20)
                {
                    /* Try 64QAM table if 16QAM failed*/
                    ul_cfg.pusch.rnti = decoding_mem.rnti;
                    ul_cfg.pusch.enable_64qam = true; // 64QAM
                    ul_cfg.pusch.meas_ta_en = true;   // enable ta measurement
                    ul_cfg.pusch.grant = *decoding_mem.ran_ul_grant;

                    decode_run("[PUSCH-64 ]", decoding_mem, modulation_mode, falcon_signal_power);

                    if (pusch_res.crc == false)
                    { // try 256QAM table if 2 cases above failed
                        ul_cfg.pusch.rnti = decoding_mem.rnti;
                        ul_cfg.pusch.enable_64qam = true;
                        ul_cfg.pusch.meas_ta_en = true; // enable ta measurement
                        ul_cfg.pusch.grant = *decoding_mem.ran_ul_grant_256;
                        modulation_mode = modulation_mode_string_256(mcs_idx);
                        if (ul_cfg.pusch.grant.L_prb < 110 && ul_cfg.pusch.grant.L_prb > 0)
                        {
                            decode_run("[PUSCH-256]", decoding_mem, modulation_mode, 0);
                        }
                    }
                }
            }
            else
            {
                // Do nothing if mimo ret error
            }
            break;
        default:
            break;
        }
    }
    else if (mcs_idx <= 20)
    { // if mcs_idx <= 20 then try only 16QAM or 256QAM (64QAM is enabled when mcs idx > 20)
        switch (mcs_mod)
        {
        case UL_SNIFFER_16QAM_MAX:
        case UL_SNIFFER_64QAM_MAX:
            ul_cfg.pusch.enable_64qam = false;
            modulation_mode = modulation_mode_string(mcs_idx, false);
            decode_run("[PUSCH-16 ]", decoding_mem, modulation_mode, 0);
            break;
        case UL_SNIFFER_256QAM_MAX:
            ul_cfg.pusch.enable_64qam = true;
            ul_cfg.pusch.grant = *decoding_mem.ran_ul_grant_256;
            modulation_mode = modulation_mode_string_256(mcs_idx);
            if (ul_cfg.pusch.grant.L_prb < 110 && ul_cfg.pusch.grant.L_prb > 0)
            {
                decode_run("[PUSCH-256]", decoding_mem, modulation_mode, 0);
            }
            break;
        case UL_SNIFFER_UNKNOWN_MOD:
            ul_cfg.pusch.enable_64qam = false;
            modulation_mode = modulation_mode_string(mcs_idx, false);
            decode_run("[PUSCH-16 ]", decoding_mem, modulation_mode, 0);
            if (pusch_res.crc == false)
            { // try 256QAM table if case above failed
                ul_cfg.pusch.grant = *decoding_mem.ran_ul_grant_256;
                modulation_mode = modulation_mode_string_256(mcs_idx);
                if (ul_cfg.pusch.grant.L_prb < 110 && ul_cfg.pusch.grant.L_prb > 0)
                {
                    ul_cfg.pusch.enable_64qam = true;
                    decode_run("[PUSCH-256]", decoding_mem, modulation_mode, 0);
                }
            }
        default:
            // do nothing
            break;
        }
    }
    return pusch_res.crc;
}

void PUSCH_Decoder::maybe_capture_iq(DCI_UL &decoding_mem, bool crc,
                                     float nominal_snr, float nominal_ta_us,
                                     bool offset_retry_enabled)
{
    /* Store the pre-FFT snapshot the NOMINAL decode used (buffer_offset[0], valid
       only when offset retry / UL mode is on) plus this grant's exact config and
       the nominal result. The offline replay tool reruns the same nominal FFT ->
       chest -> decode and must reproduce chest_sinr + CRC bit-for-bit; the timing
       search / estimator variants are then explored offline, not here. */
    if (!RawIQRecorder::instance().enabled() || !offset_retry_enabled ||
        buffer_offset[0] == nullptr || RawIQRecorder::instance().quota_reached())
        return;

    // Chest-independent energy SNR: mean allocated-RB power minus the
    // 10th-percentile RB-power floor (SubframePower is already in dB).
    float e_snr = -100.0f, p_alloc = 0.0f, floor_db = 0.0f;
    {
        const auto& rbpow = sf_power->getRBPowerUL();
        uint32_t np = ul_cfg.pusch.grant.n_prb[0], L = ul_cfg.pusch.grant.L_prb;
        if (L > 0 && rbpow.size() >= (size_t)np + L) {
            for (uint32_t k = 0; k < L; k++) p_alloc += rbpow[np + k];
            p_alloc /= (float)L;
            std::vector<float> tmp(rbpow.begin(), rbpow.end());
            size_t p10 = tmp.size() / 10;
            std::nth_element(tmp.begin(), tmp.begin() + p10, tmp.end());
            floor_db = tmp[p10];
            e_snr = p_alloc - floor_db;
        }
    }
    const bool nan_chest = !std::isfinite(nominal_snr);

    // Bounded policy: keep the scientifically useful cases in full — successes,
    // retransmissions, REAL timing outliers (|ta|>5us on a VALID finite chest),
    // strong failures, and high-energy chest failures. Everything driven by the
    // weak RF bulk — including NaN-chest bursts with garbage TA, which must NOT
    // be mislabelled timing outliers — is subsampled so the quota is spent on
    // boundary cases, not thousands of sub-2 dB failures.
    static std::atomic<uint64_t> pol_ctr{0};
    uint64_t c = pol_ctr.fetch_add(1);
    bool cap = false; const char* cat = "weak_fail";
    if      (crc)                                    { cap = true;           cat = "crc_ok"; }
    else if (decoding_mem.is_retx == 1)              { cap = true;           cat = "retx"; }
    else if (nan_chest && e_snr >= 4.f)              { cap = true;           cat = "chest_nan"; }
    else if (nan_chest)                              { cap = (c % 50 == 0);  cat = "chest_nan_weak"; }
    else if (fabsf(nominal_ta_us) > 5.0f)            { cap = true;           cat = "timing_outlier"; }
    else if (e_snr >= 4.f)                           { cap = true;           cat = "strong_fail"; }
    else if (e_snr >= 2.f)                           { cap = (c % 10 == 0);  cat = "moderate_fail"; }
    else if (e_snr >= 0.f)                           { cap = (c % 50 == 0);  cat = "weak_fail"; }
    else                                             { cap = (c % 200 == 0); cat = "weak_fail"; }
    if (!cap) return;

    CaptureMeta m;
    m.category = cat;
    m.nof_prb  = enb_ul.cell.nof_prb;
    m.cell_id  = enb_ul.cell.id;
    m.cp       = (int)enb_ul.cell.cp;
    m.tti = ul_sf.tti; m.sfn = ul_sf.tti / 10; m.sf_idx = ul_sf.tti % 10;
    m.dmrs_cyclic_shift = ul_cfg.dmrs.cyclic_shift;
    m.delta_ss          = ul_cfg.dmrs.delta_ss;
    m.group_hop         = ul_cfg.dmrs.group_hopping_en ? 1 : 0;
    m.seq_hop           = ul_cfg.dmrs.sequence_hopping_en ? 1 : 0;
    m.rnti    = ul_cfg.pusch.rnti;
    m.mcs_idx = ul_cfg.pusch.grant.tb.mcs_idx;
    m.mod     = (int)ul_cfg.pusch.grant.tb.mod;
    m.tbs     = ul_cfg.pusch.grant.tb.tbs;
    m.rv      = ul_cfg.pusch.grant.tb.rv;
    m.n_prb0  = ul_cfg.pusch.grant.n_prb[0];
    m.L_prb   = ul_cfg.pusch.grant.L_prb;
    m.n_dmrs  = ul_cfg.pusch.grant.n_dmrs;
    m.is_retx = decoding_mem.is_retx;
    m.energy_snr = e_snr;         m.chest_sinr = nominal_snr;
    m.p_alloc = p_alloc;          m.noise_floor = floor_db;
    m.ta_us = nominal_ta_us;      m.cfo_hz = enb_ul.chest_res.cfo_hz;
    m.crc = crc ? 1 : 0;
    // Internally-consistent rate for the stored snapshot: the decoder FFTs
    // SRSRAN_SF_LEN_PRB(nof_prb) samples/subframe; the snapshot is 100-PRB sized.
    const uint32_t snap_len = 3 * SRSRAN_SF_LEN_PRB(100);
    m.requested_samples  = snap_len;
    m.pusch_start_sample = 0; // target subframe begins at the snapshot start
    m.sample_rate = (double)SRSRAN_SF_LEN_PRB(enb_ul.cell.nof_prb) * 1000.0;

    // Exact decode context (POD) so the burst replays bit-for-bit.
    DecodeCtxBlob ctx{};
    ctx.magic = UL_IQ_CTX_MAGIC; ctx.version = UL_IQ_CTX_VERSION;
    ctx.cell_id = enb_ul.cell.id; ctx.nof_prb = enb_ul.cell.nof_prb;
    ctx.cp = (int32_t)enb_ul.cell.cp; ctx.nof_ports = enb_ul.cell.nof_ports;
    ctx.tti = ul_sf.tti; ctx.rnti = ul_cfg.pusch.rnti;
    ctx.enable_64qam = ul_cfg.pusch.enable_64qam ? 1 : 0;
    ctx.grant = ul_cfg.pusch.grant;
    ctx.dmrs = ul_cfg.dmrs;
    ctx.hopping = ul_cfg.hopping;
    ctx.uci_cfg = ul_cfg.pusch.uci_cfg;
    ctx.uci_offset = ul_cfg.pusch.uci_offset;
    ctx.live_crc = crc ? 1 : 0;
    ctx.live_snr_db = nominal_snr; ctx.live_ta_us = nominal_ta_us;
    ctx.live_noise_estimate = enb_ul.chest_res.noise_estimate;
    // Hash the live-decoded transport block so replay can prove byte-exact
    // payload equivalence. pusch_res.data holds the TB from the nominal decode.
    ctx.live_payload_hash = (crc && ul_cfg.pusch.grant.tb.tbs > 0)
        ? ul_iq_fnv1a(pusch_res.data, ul_cfg.pusch.grant.tb.tbs / 8) : 0;
    const uint8_t* cb = reinterpret_cast<const uint8_t*>(&ctx);
    m.ctx_blob.assign(cb, cb + sizeof(ctx));

    RawIQRecorder::instance().request_capture(buffer_offset[0], snap_len, m);
}

void PUSCH_Decoder::decode()
{
    // One-time init of the raw-IQ recorder (env-gated; no-op unless UL_IQ_REC set).
    static std::once_flag iqrec_once;
    std::call_once(iqrec_once, [] { RawIQRecorder::instance().configure(); });

    if (decoder_a){
        enb_ul.in_buffer = original_buffer[0]; // 0 for downlink, 1 for uplink, now 0 because there are 2 separate buffers
    }else if (decoder_b){
        enb_ul.in_buffer = original_buffer[1]; // 0 for downlink, 1 for uplink, now 0 because there are 2 separate buffers
    }

    /* Snapshot the raw subframe BEFORE the FFT. srsran_enb_ul_fft applies its
       frequency shift in place on original_buffer[0], so once the nominal FFT
       runs the raw samples are destroyed. We need a clean copy to re-FFT at
       alternate window offsets in the retry pass. Only needed when offset retry
       is enabled (UL/DUAL mode). */
    const bool offset_retry_enabled = (multi_ul_offset != 0);
    if (offset_retry_enabled)
    {
        const uint32_t snap_len = 3 * SRSRAN_SF_LEN_PRB(100);
        /* Snapshot the SAME window the nominal FFT consumes: decoder_a runs on
           original_buffer[0] (USRP A), decoder_b on original_buffer[1] (USRP B).
           Hardcoding [0] here would feed decoder_b USRP-A samples on every retry.
           NOTE: buffer_offset[] scratch is shared between the two decoder
           instances (both are constructed with sfb.sf_buffer_offset), so
           decoder_b must NOT run concurrently with decoder_a until it is given
           its own scratch pair — decoder_b's decode() is currently disabled in
           SubframeWorker, so this is latent today. */
        cf_t* raw_src = decoder_b ? original_buffer[1] : original_buffer[0];
        memcpy(buffer_offset[0], raw_src, sizeof(cf_t) * snap_len);
    }

    srsran_enb_ul_fft(&enb_ul);            // run FFT to uplink samples
    sf_power->computePower(enb_ul.sf_symbols);

    /* Save the nominal-window symbols. The FFT applies its frequency shift in
       place on original_buffer[0], so it cannot be re-run to regenerate these;
       the offset-retry pass restores from this copy instead. */
    if ((offset_retry_enabled || ul_diversity) && sf_symbols_nominal)
    {
        memcpy(sf_symbols_nominal, enb_ul.sf_symbols, sizeof(cf_t) * sf_symbols_len);
    }

    /* UL 2-RX selection diversity: FFT antenna 1 (original_buffer[1]) ONCE per
       subframe and cache it, so a CRC-failed grant can retry on the second UL
       antenna without re-FFT (the FFT is in-place / non-repeatable). Only
       decoder_a drives this; antenna-1 samples are present only when rf_b was
       opened with 2 channels (env UL_DIVERSITY). Restores antenna-0 buffer +
       symbols so the nominal path is unchanged. */
    if (ul_diversity && decoder_a && sf_symbols_ant1 && sf_symbols_nominal)
    {
        cf_t* saved_in   = enb_ul.in_buffer;
        enb_ul.in_buffer = original_buffer[1];
        srsran_enb_ul_fft(&enb_ul);                 // sf_symbols := antenna 1
        memcpy(sf_symbols_ant1, enb_ul.sf_symbols, sizeof(cf_t) * sf_symbols_len);
        enb_ul.in_buffer = saved_in;                // restore antenna-0 raw buffer
        memcpy(enb_ul.sf_symbols, sf_symbols_nominal, sizeof(cf_t) * sf_symbols_len);
    }

    /*combine Uplink grant detected from RAR response (msg 2) and Uplink grant detected from DCI0*/
    if (!dci_ul.empty() || !rar_dci_ul.empty())
    {
        if (!rar_dci_ul.empty() && !dci_ul.empty())
        {
            for (const auto& rar_dci : rar_dci_ul)
            {
                dci_ul.push_back(rar_dci);
            }
        }
        else if (!rar_dci_ul.empty() && dci_ul.empty())
        {
            dci_ul = rar_dci_ul;
        }
        /*Try to decode all member in grant list*/
        for (auto decoding_mem : dci_ul)
        {
            /*Investigate current decoding member to know it has a valid UL grant or not*/
            valid_ul_grant = investigate_valid_ul_grant(decoding_mem);
            /*Only decode member with valid UL grant*/
            if (((decoding_mem.rnti == target_rnti) || (valid_ul_grant == SRSRAN_SUCCESS))&&decoding_mem.rnti != 0)
            {
                /* PASS 1: nominal FFT window (sf_symbols already holds the
                   nominal FFT). Behaves exactly as before, except that when HARQ
                   combining is on this decode goes into the UE's per-HARQ-process
                   softbuffer and accumulates across retransmissions. */
                if (harq_on_)
                {
                    uint32_t pid = ul_sf.tti % 8;             // FDD UL: 8 processes, 8 ms RTT
                    uint64_t key = ((uint64_t)decoding_mem.rnti << 8) | (pid & 0xff);
                    int ndi = decoding_mem.ran_ul_dci ? decoding_mem.ran_ul_dci->tb.ndi : 0;
                    auto it = harq_last_ndi_.find(key);
                    bool new_tx = (it == harq_last_ndi_.end()) || (it->second != ndi);
                    harq_last_ndi_[key] = ndi;
                    if (!new_tx) g_harq_retx_seen.fetch_add(1, std::memory_order_relaxed);
                    ul_cfg.pusch.softbuffers.rx = harq_get(decoding_mem.rnti, pid, new_tx);
                    harq_no_reset_ = !new_tx;                 // retx => accumulate, don't reset
                }
                bool crc = decode_grant(decoding_mem);
                if (harq_on_)
                {
                    // Count retransmissions that decoded (the combining payoff), then
                    // hand the offset-retry / adapter back the default scratch buffer
                    // so their alternate-window probes never corrupt HARQ state.
                    if (crc && decoding_mem.is_retx == 1)
                        g_harq_recovered.fetch_add(1, std::memory_order_relaxed);
                    ul_cfg.pusch.softbuffers.rx = default_sb_;
                    harq_no_reset_ = false;
                }

                /* Capture the nominal channel-estimate outcome for statistics and
                   for steering the retry. ta_us gives the signed residual timing
                   in microseconds; snr tells us whether the signal was even
                   present. */
                float nominal_snr   = enb_ul.chest_res.snr_db;
                float nominal_ta_us = enb_ul.chest_res.ta_us;

                /* Grant-keyed raw-IQ capture of THIS nominal-window decode, taken
                   before any offset retry mutates sf_symbols so the stored burst
                   replays bit-for-bit. Env-gated (UL_IQ_REC); no-op otherwise. */
                maybe_capture_iq(decoding_mem, crc, nominal_snr, nominal_ta_us,
                                 offset_retry_enabled);

                /* PASS 2: FFT-window-offset retry. Only for grants that FAILED
                   CRC at the nominal window AND only when offset retry is enabled
                   (UL/DUAL mode). A passive sniffer sees the UE's TA-precompensated
                   UL with a geometry-dependent residual; when that residual pushes
                   symbols past the CP tolerance, a strong signal still fails CRC.
                   We re-FFT on a shifted window to re-centre it. */
                if (!crc && offset_retry_enabled)
                {
                    const uint32_t sf_len = SRSRAN_SF_LEN_PRB(enb_ul.cell.nof_prb);

                    /* PER-UE TIMING: a passive sniffer sees every UE's UL with its
                       OWN geometry-dependent arrival offset (measured spread here:
                       +/-10 us). A real eNB avoids this — it commands each UE's
                       Timing Advance so all UL arrives ALIGNED at the eNB, so one
                       FFT window fits everyone. We can't command TA, so ~1/3 of UEs
                       land OUTSIDE the CP (~4.7 us) and cannot decode at the nominal
                       window at ANY SNR. srsRAN's ta_us is a phase-SLOPE estimate,
                       only valid WITHIN the CP, so it cannot steer us to a beyond-CP
                       UE (chicken-and-egg). The fix below is the software equivalent
                       of per-UE TA: for grants that actually carry energy, scan a
                       WIDE window range and center on the chest-SNR peak for THAT UE. */

                    // Chest-free allocated-RB energy (dB above the 10th-pctile floor)
                    // — gates the expensive wide search so noise grants stay cheap
                    // (the RT thread must never fall behind; a blind wide sweep on
                    // every grant drops subframes).
                    float e_snr = -100.0f;
                    {
                        const auto& rbpow = sf_power->getRBPowerUL();
                        uint32_t np = ul_cfg.pusch.grant.n_prb[0], L = ul_cfg.pusch.grant.L_prb;
                        if (L > 0 && rbpow.size() >= (size_t)np + L) {
                            float pa = 0.0f;
                            for (uint32_t k = 0; k < L; k++) pa += rbpow[np + k];
                            pa /= (float)L;
                            std::vector<float> tmp(rbpow.begin(), rbpow.end());
                            size_t p10 = tmp.size() / 10;
                            std::nth_element(tmp.begin(), tmp.begin() + p10, tmp.end());
                            e_snr = pa - tmp[p10];
                        }
                    }

                    // Wide per-UE timing acquisition — opt-in (UL_TIMING_ACQ), and
                    // only for grants clearing UL_TIMING_ACQ_MINDB of energy so it
                    // costs nothing on the ~99% of grants that are noise.
                    static const bool  acq_on    = (getenv("UL_TIMING_ACQ") != nullptr);
                    static const int   acq_max    = []{ const char* e=getenv("UL_TIMING_ACQ_MAX");
                        int v = e?atoi(e):240; return v<48?48:(v>720?720:v); }();
                    static const float acq_mindb  = []{ const char* e=getenv("UL_TIMING_ACQ_MINDB");
                        return e?(float)atof(e):3.0f; }();

                    if (acq_on && e_snr >= acq_mindb)
                    {
                        // Stage 1: coarse scan (chest only) for the SNR peak window.
                        int   best_off = 0; float best_s = -1e9f;
                        const int coarse = 48;
                        for (int off = -acq_max; off <= acq_max; off += coarse) {
                            if (!refft_at_offset(off)) continue;
                            if (srsran_chest_ul_estimate_pusch(&enb_ul.chest, &ul_sf, &ul_cfg.pusch,
                                    enb_ul.sf_symbols, &enb_ul.chest_res) != SRSRAN_SUCCESS) continue;
                            float s = enb_ul.chest_res.snr_db;
                            if (std::isfinite(s) && s > best_s) { best_s = s; best_off = off; }
                        }
                        // Stage 2: fine scan +/- one coarse step around the peak.
                        for (int off = best_off - coarse; off <= best_off + coarse; off += 8) {
                            if (!refft_at_offset(off)) continue;
                            if (srsran_chest_ul_estimate_pusch(&enb_ul.chest, &ul_sf, &ul_cfg.pusch,
                                    enb_ul.sf_symbols, &enb_ul.chest_res) != SRSRAN_SUCCESS) continue;
                            float s = enb_ul.chest_res.snr_db;
                            if (std::isfinite(s) && s > best_s) { best_s = s; best_off = off; }
                        }
                        // Decode at the per-UE peak window.
                        if (refft_at_offset(best_off)) {
                            crc = decode_grant(decoding_mem);
                            if (crc) { nominal_snr = enb_ul.chest_res.snr_db; nominal_ta_us = enb_ul.chest_res.ta_us; }
                        }
                    }
                    else
                    {
                    /* Default (baseline) narrow retry: the measured ta_us candidate
                       plus a small +/- one-CP fallback set. */
                    int  cand[8];
                    int  ncand = 0;
                    if (nominal_snr >= 0.0f && nominal_ta_us != 0.0f)
                    {
                        // samples = ta_us * 1e-6 * srate; srate = sf_len * 1000
                        int meas = (int)lroundf(nominal_ta_us * (float)sf_len / 1000.0f);
                        if (meas != 0) { cand[ncand++] = meas; cand[ncand++] = -meas; }
                    }
                    // Fixed fallback offsets (samples).
                    static const int fixed_off[] = {32, -32, 64, -64, 16, -16};
                    for (uint32_t i = 0; i < sizeof(fixed_off)/sizeof(fixed_off[0]) &&
                                         ncand < (int)(sizeof(cand)/sizeof(cand[0])); i++)
                    {
                        bool dup = false;
                        for (int j = 0; j < ncand; j++) { if (cand[j] == fixed_off[i]) { dup = true; break; } }
                        if (!dup) cand[ncand++] = fixed_off[i];
                    }

                    for (int i = 0; i < ncand && !crc; i++)
                    {
                        if (!refft_at_offset(cand[i])) continue; // out-of-range guard
                        crc = decode_grant(decoding_mem);
                        if (crc)
                        {
                            // Keep the successful estimate for statistics below.
                            nominal_snr   = enb_ul.chest_res.snr_db;
                            nominal_ta_us = enb_ul.chest_res.ta_us;
                        }
                    }
                    }

                    /* Grant-specific UplinkSyncAdapter fallback (env UL_SYNC_ADAPTER).
                       Runs the staged per-UE timing/CFO estimator on the pre-FFT
                       snapshot when the nominal window AND the narrow/acq retry both
                       failed and the grant carries real energy (UL_SYNC_MINDB). Uses
                       a PRIVATE enb_ul scratch (own FFT + input buffer), so the wide
                       search never mutates the shared raw buffer; on acceptance it
                       leaves corrected symbols we copy into the live enb_ul and
                       decode with the standard MCS-table sequence. Accept-CRC-only,
                       so it can never turn a nominal success into a failure. */
                    {
                        static const bool  sync_on    = (getenv("UL_SYNC_ADAPTER") != nullptr);
                        static const float sync_mindb = []{ const char* e=getenv("UL_SYNC_MINDB"); return e?(float)atof(e):4.0f; }();
                        if (!crc && sync_on && e_snr >= sync_mindb && buffer_offset[0] != nullptr)
                        {
                            ensure_sync_adapter();
                            if (sync_adapter_)
                            {
                                g_sync_fired.fetch_add(1, std::memory_order_relaxed);
                                ul_cfg.pusch.rnti  = decoding_mem.rnti;
                                ul_cfg.pusch.grant = *decoding_mem.ran_ul_grant;
                                UplinkSyncResult sr = sync_adapter_->run(buffer_offset[0],
                                        3 * SRSRAN_SF_LEN_PRB(100), sf_len, ul_sf, ul_cfg);
                                if (sr.corrected_iq_available)
                                {
                                    memcpy(enb_ul.sf_symbols, adapter_enb_ul_->sf_symbols,
                                           sizeof(cf_t) * sf_symbols_len);
                                    crc = decode_grant(decoding_mem);
                                    if (crc)
                                    {
                                        g_sync_recovered.fetch_add(1, std::memory_order_relaxed);
                                        nominal_snr   = enb_ul.chest_res.snr_db;
                                        nominal_ta_us = enb_ul.chest_res.ta_us;
                                    }
                                }
                            }
                        }
                    }

                    /* Restore sf_symbols to the nominal window so the next
                       grant's pass-1 decode sees the correct (nominal) symbols.
                       We cannot re-run srsran_enb_ul_fft (it shifts the raw
                       buffer in place and is not idempotent), so restore from the
                       saved copy. Skip the restore only if the last attempted
                       offset was 0 (it never is here). */
                    if (sf_symbols_nominal)
                    {
                        memcpy(enb_ul.sf_symbols, sf_symbols_nominal, sizeof(cf_t) * sf_symbols_len);
                    }
                }

                /* UL 2-RX selection diversity: if the grant STILL failed after
                   antenna-0 (nominal + offset retry), retry on antenna 1 using
                   its cached symbols. Selection combining — we take whichever
                   antenna's CRC passes. Pure fallback: it can only rescue grants
                   antenna-0 missed, never degrade them. (MRC would add ~3 dB over
                   this but needs combining the two antennas' channel estimates;
                   selection is the safe first step.) */
                if (!crc && ul_diversity && sf_symbols_ant1)
                {
                    memcpy(enb_ul.sf_symbols, sf_symbols_ant1, sizeof(cf_t) * sf_symbols_len);
                    crc = decode_grant(decoding_mem);
                    if (crc)
                    {
                        nominal_snr   = enb_ul.chest_res.snr_db;
                        nominal_ta_us = enb_ul.chest_res.ta_us;
                    }
                    if (sf_symbols_nominal)
                        memcpy(enb_ul.sf_symbols, sf_symbols_nominal, sizeof(cf_t) * sf_symbols_len);
                }

                /* ===== UL rate diagnostic (opt-in via UL_RATE_DIAG) =====
                   Aggregate UL grant attempts vs CRC successes across ALL worker
                   threads and print a per-second summary with wall-clock elapsed
                   time and the current tti/sfn. This exposes the TEMPORAL shape
                   of UL yield: an RF limit gives a steady low trickle, whereas a
                   drift/SFN-rollover bug shows success collapsing to ~0 after the
                   first few seconds while attempts continue. Counters are process-
                   wide (all workers), atomic, zero-cost when the env var is off. */
                if (getenv("UL_RATE_DIAG"))
                {
                    static std::atomic<uint64_t> att{0}, suc{0};
                    static std::atomic<uint64_t> att_prev{0}, suc_prev{0};
                    static std::atomic<long long> t0_ms{0}, last_ms{0};
                    // windowed timing/quality: peak SNR and the ta at that peak,
                    // reset each print. A monotonic ta drift with time == the two
                    // radios diverging (UL losing DL alignment); a flat ta with
                    // low SNR == genuine RF weakness.
                    static std::atomic<int>   win_best_snr_mdb{-100000}; // milli-dB
                    static std::atomic<int>   win_best_ta_mus{0};        // milli-us
                    att.fetch_add(1, std::memory_order_relaxed);
                    if (crc) suc.fetch_add(1, std::memory_order_relaxed);
                    int snr_mdb = (int)lroundf(nominal_snr * 1000.0f);
                    int prev = win_best_snr_mdb.load(std::memory_order_relaxed);
                    while (snr_mdb > prev &&
                           !win_best_snr_mdb.compare_exchange_weak(prev, snr_mdb)) {}
                    if (snr_mdb >= win_best_snr_mdb.load())
                        win_best_ta_mus.store((int)lroundf(nominal_ta_us * 1000.0f));
                    auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now().time_since_epoch()).count();
                    long long expect0 = 0;
                    t0_ms.compare_exchange_strong(expect0, now_ms);
                    long long lm = last_ms.load(std::memory_order_relaxed);
                    if (now_ms - lm >= 1000 &&
                        last_ms.compare_exchange_strong(lm, now_ms))
                    {
                        uint64_t a = att.load(), s = suc.load();
                        uint64_t da = a - att_prev.exchange(a);
                        uint64_t ds = s - suc_prev.exchange(s);
                        int bsnr = win_best_snr_mdb.exchange(-100000);
                        int bta  = win_best_ta_mus.load();
                        printf("[ULRATE] t=%llds tti=%u | last1s: attempts=%llu success=%llu"
                               " peakSNR=%.1fdB ta@peak=%.1fus | cum: att=%llu suc=%llu"
                               " | adapter: fired=%llu recovered=%llu | harq_retx_seen=%llu ok=%llu\n",
                               (now_ms - t0_ms.load()) / 1000, ul_sf.tti,
                               (unsigned long long)da, (unsigned long long)ds,
                               bsnr / 1000.0f, bta / 1000.0f,
                               (unsigned long long)a, (unsigned long long)s,
                               (unsigned long long)g_sync_fired.load(),
                               (unsigned long long)g_sync_recovered.load(),
                               (unsigned long long)g_harq_retx_seen.load(),
                               (unsigned long long)g_harq_recovered.load());
                        fflush(stdout);
                    }
                }

                /* ===== P1: UL failure-cause breakdown (opt-in UL_FAIL_DIAG) =====
                   Classify EVERY UL grant's final outcome so "0.26% yield" becomes
                   an actionable split. Buckets (process-wide atomics), printed every
                   ~5 s and cumulative:
                     ok        : CRC passed
                     noise     : failed, SNR < 0 dB  -> no real signal / false DCI /
                                 UE far below floor (nothing any lever can recover)
                     weak      : failed, 0..6 dB     -> real but marginal; HARQ combine
                                 / MRC (~+3 dB each) could push some of these over
                     timing    : failed, SNR>=6 dB but |ta|>CP(4.5us) -> mis-aligned,
                                 not weak; tighter timing could rescue
                     strong_x  : failed, SNR>=6 dB and |ta|<=CP -> strong+aligned yet
                                 failed => config/interference/decoder issue to chase
                   retx counts grants flagged as HARQ retransmissions (== soft-combine
                   opportunity). */
                if (getenv("UL_FAIL_DIAG"))
                {
                    static std::atomic<uint64_t> c_ok{0}, c_noise{0}, c_weak{0}, c_tim{0}, c_str{0}, c_retx{0};
                    static std::atomic<long long> t0{0}, last{0};
                    const float CP_US = 4.5f;
                    if (crc) c_ok.fetch_add(1, std::memory_order_relaxed);
                    else if (nominal_snr < 0.0f)  c_noise.fetch_add(1, std::memory_order_relaxed);
                    else if (nominal_snr < 6.0f)  c_weak.fetch_add(1, std::memory_order_relaxed);
                    else if (fabsf(nominal_ta_us) > CP_US) c_tim.fetch_add(1, std::memory_order_relaxed);
                    else c_str.fetch_add(1, std::memory_order_relaxed);
                    if (decoding_mem.is_retx == 1) c_retx.fetch_add(1, std::memory_order_relaxed);
                    auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now().time_since_epoch()).count();
                    long long e0 = 0; t0.compare_exchange_strong(e0, now);
                    long long lm = last.load(std::memory_order_relaxed);
                    if (now - lm >= 5000 && last.compare_exchange_strong(lm, now))
                    {
                        uint64_t ok=c_ok,no=c_noise,wk=c_weak,ti=c_tim,st=c_str,rx=c_retx;
                        uint64_t tot = ok+no+wk+ti+st; if (!tot) tot=1;
                        printf("[ULFAIL] t=%llds tot=%llu | ok=%llu(%.2f%%) noise=%llu(%.0f%%) "
                               "weak=%llu(%.0f%%) timing=%llu(%.1f%%) strong_fail=%llu(%.2f%%) | retx=%llu\n",
                               (now-t0.load())/1000, (unsigned long long)tot,
                               (unsigned long long)ok,100.0*ok/tot, (unsigned long long)no,100.0*no/tot,
                               (unsigned long long)wk,100.0*wk/tot, (unsigned long long)ti,100.0*ti/tot,
                               (unsigned long long)st,100.0*st/tot, (unsigned long long)rx);
                        fflush(stdout);
                    }
                }

                /* ===== INDEPENDENT energy-domain SNR (opt-in UL_ENERGY_DIAG) =====
                   The chest SINR (nominal_snr) is derived from the SAME DMRS
                   channel estimate used for equalization, so a mis-estimated
                   channel is indistinguishable from low SNR. This metric bypasses
                   the estimator entirely: it uses the post-FFT per-RB POWER only.
                     P_alloc = mean power (dB) in the grant's allocated RBs
                     floor   = MEDIAN power (dB) of all RBs (most are unused/noise
                               in a lightly-loaded UL) -> a chest-free noise floor
                     ENERGY_SNR = P_alloc - floor
                   For grants with real energy (ENERGY_SNR >= 5 dB) we print the
                   chest SINR beside it. If chest_SINR is far BELOW ENERGY_SNR, the
                   signal power was there but the estimator/timing lost it = real
                   implementation loss, NOT RF. If chest tracks ENERGY_SNR, the
                   grant is genuinely weak = RF-limited. */
                if (getenv("UL_ENERGY_DIAG"))
                {
                    const auto& rbpow = sf_power->getRBPowerUL();
                    uint32_t np = ul_cfg.pusch.grant.n_prb[0], L = ul_cfg.pusch.grant.L_prb;
                    if (L > 0 && rbpow.size() >= (size_t)np + L)
                    {
                        float p_alloc = 0.0f;
                        for (uint32_t k = 0; k < L; k++) p_alloc += rbpow[np + k];
                        p_alloc /= L;
                        // Noise floor = 10th-percentile RB power (robust to a busy
                        // cell where the median RB is occupied, not noise).
                        std::vector<float> tmp(rbpow.begin(), rbpow.end());
                        size_t p10 = tmp.size() / 10;
                        std::nth_element(tmp.begin(), tmp.begin() + p10, tmp.end());
                        float floor_db = tmp[p10];
                        float e_snr = p_alloc - floor_db;
                        // Aggregate chest_SINR binned by energy_SNR: if chest tracks
                        // energy -> RF-limited; if chest stays low while energy is
                        // high -> estimator loss. Bins: [ -,2,4,6,8,+ ].
                        static std::atomic<uint64_t> bn[6]{}; static std::atomic<long long> bs[6]{};
                        static std::atomic<uint64_t> n_e3{0}, n_lost{0};
                        static std::atomic<long long> t0e{0}, laste{0};
                        int bi = e_snr < 2 ? 0 : e_snr < 4 ? 1 : e_snr < 6 ? 2 : e_snr < 8 ? 3 : e_snr < 12 ? 4 : 5;
                        bn[bi].fetch_add(1, std::memory_order_relaxed);
                        bs[bi].fetch_add((long long)lroundf(nominal_snr * 100), std::memory_order_relaxed);
                        if (e_snr >= 3.0f) {
                            n_e3.fetch_add(1, std::memory_order_relaxed);
                            if (nominal_snr < e_snr - 3.0f) n_lost.fetch_add(1, std::memory_order_relaxed);
                        }
                        // per-grant line for clearly-energetic grants
                        if (e_snr >= 5.0f)
                            printf("[ULNRG] SF %d.%d RNTI %d L=%u | P_alloc=%.1f floor=%.1f | "
                                   "ENERGY_SNR=%.1f  chest_SINR=%.1f  ta=%.1fus crc=%d %s\n",
                                   ul_sf.tti/10, ul_sf.tti%10, ul_cfg.pusch.rnti, L, p_alloc, floor_db,
                                   e_snr, nominal_snr, nominal_ta_us, (int)crc,
                                   (nominal_snr < e_snr-3.0f) ? "<< SIGNAL PRESENT, chest LOSES it" : "");
                        // periodic binned summary (the decisive scatter)
                        auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::steady_clock::now().time_since_epoch()).count();
                        long long e0 = 0; t0e.compare_exchange_strong(e0, now);
                        long long lm = laste.load();
                        if (now - lm >= 5000 && laste.compare_exchange_strong(lm, now)) {
                            printf("[ULNRGBIN] energy_SNR bin -> [count, mean chest_SINR]:");
                            const char* lb[6]={"<2","2-4","4-6","6-8","8-12","12+"};
                            for (int i=0;i<6;i++){uint64_t c=bn[i];double m=c?(double)bs[i]/c/100.0:0;printf(" %s:[%llu,%.1f]",lb[i],(unsigned long long)c,m);}
                            printf(" | energy>=3dB=%llu chest-lost=%llu\n",(unsigned long long)n_e3.load(),(unsigned long long)n_lost.load());
                            fflush(stdout);
                        }
                    }
                }

                /*Update statistic when SNR is higher than 1, the statistic showed on terminal is only for RNTIs with SNR >=1*/
                /* Count each grant exactly once with its FINAL outcome (crc),
                   using the channel estimate from the attempt that produced it. */
                if (nominal_snr >= 1)
                { // enb_ul.chest_res.snr_db >= 1
                    mcstracking->update_statistic_ul(decoding_mem.rnti, crc, decoding_mem, nominal_snr, nominal_ta_us);
                }
            }
            else
            {
                // Do nothing
            }
        }
    }
}

void PUSCH_Decoder::init_pusch_decoder(std::vector<DCI_UL> dci_ul_,
                                       std::vector<DCI_UL> rar_dci_ul_,
                                       srsran_ul_sf_cfg_t &ul_sf_,
                                       SubframePower *sf_power_)
{
    dci_ul = std::move(dci_ul_);
    rar_dci_ul = std::move(rar_dci_ul_);
    ul_sf = ul_sf_;
    sf_power = sf_power_;
}

int PUSCH_Decoder::check_valid_prb_ul(uint32_t nof_prb)
{
    if (nof_prb <= 100)
    {
        return valid_prb_ul[nof_prb];
    }
    return false;
}

std::string PUSCH_Decoder::modulation_mode_string(int idx, bool max_64qam)
{
    std::string ret = "";
    if (idx <= 10)
    {
        ret = "QPSK";
    }
    else if (idx <= 20)
    {
        ret = "16QAM";
    }
    else if (idx <= 28 && max_64qam)
    {
        ret = "64QAM";
    }
    else if (idx <= 28 && !max_64qam)
    {
        ret = "16QAM";
    }
    else
    {
        ret = "ReTx";
    }
    return ret;
}

std::string PUSCH_Decoder::modulation_mode_string_256(int idx)
{
    std::string ret = "";
    if (idx <= 5)
    {
        ret = "QPSK";
    }
    else if (idx <= 13)
    {
        ret = "16QAM";
    }
    else if (idx <= 22)
    {
        ret = "64QAM";
    }
    else if (idx <= 28)
    {
        ret = "256QAM";
    }
    else
    {
        ret = "ReTx";
    }
    return ret;
}

void PUSCH_Decoder::set_rach_config(srsran_prach_cfg_t prach_cfg_)
{
    prach_cfg = prach_cfg_;
    if (srsran_prach_init(&prach, srsran_symbol_sz(enb_ul.cell.nof_prb)))
    {
        std::cout << "Init PRACH failed" << std::endl;
    }
    if (srsran_prach_set_cfg(&prach, &prach_cfg, enb_ul.cell.nof_prb))
    {
        std::cout << "Config PRACH failed" << std::endl;
    }
    srsran_prach_set_detect_factor(&prach, 60);
    nof_sf = (uint32_t)ceilf(prach.T_tot * 1000);

    uint32_t sig_len_per_sf = SRSRAN_SF_LEN_PRB(enb_ul.cell.nof_prb) - prach.N_cp;
    prach_detection_enabled = (sig_len_per_sf >= prach.N_ifft_prach);
    if (!prach_detection_enabled) {
        printf("[PRACH] Detection disabled: cell uses PRACH format %u "
               "(needs %u samples, only %u available within one subframe; "
               "multi-subframe buffering not implemented). "
               "User-plane decoding is unaffected.\n",
               prach.f, prach.N_ifft_prach, sig_len_per_sf);
    }
}

void PUSCH_Decoder::work_prach()
{
    if (!prach_detection_enabled) return;

    uint32_t prach_nof_det = 0;
    if (srsran_prach_tti_opportunity(&prach, ul_sf.tti, -1))
    {
        memcpy(&samples[0],
               original_buffer[0],
               sizeof(cf_t) * SRSRAN_SF_LEN_PRB(enb_ul.cell.nof_prb));
        srsran_prach_detect_offset(&prach,
                                   prach_cfg.freq_offset,
                                   &samples[prach.N_cp],
                                   SRSRAN_SF_LEN_PRB(enb_ul.cell.nof_prb) - prach.N_cp,
                                   prach_indices,
                                   prach_offsets,
                                   prach_p2avg,
                                   &prach_nof_det);

        if (prach_nof_det)
        {
            int max_idx = 0;
            float peak = 0;
            for (uint32_t i = 0; i < prach_nof_det; i++)
            {
                if (prach_p2avg[i] > peak)
                {
                    peak = prach_p2avg[i];
                    max_idx = i;
                }
            }
            if (en_debug)
            {
                printf("PRACH: %d/%d, preamble=%d, offset=%.1f us, peak2avg=%.1f \n",
                       max_idx + 1,
                       prach_nof_det,
                       prach_indices[max_idx],
                       prach_offsets[max_idx] * 1e6,
                       prach_p2avg[max_idx]);
            }
        }
    }
}

void PUSCH_Decoder::print_debug(DCI_UL &decoding_mem, std::string offset_name, std::string modulation_mode, float signal_pw, double noise, double falcon_sgl_pwr)
{
    std::cout << "[" << debug_str << "]";
    std::cout << std::left << std::setw(12) << offset_name << " SF: ";
    std::cout << std::left << std::setw(4) << (int)ul_sf.tti / 10 << "." << (int)ul_sf.tti % 10;
    std::cout << " -- RNTI: ";
    std::cout << std::left << std::setw(6) << decoding_mem.rnti;

    std::cout << GREEN << " -- DL-UL(us): ";
    if (enb_ul.chest_res.ta_us > 0)
    {
        std::cout << "+";
    }
    else if (enb_ul.chest_res.ta_us < 0)
    {
        std::cout << "-";
    }
    else
    {
        std::cout << " ";
    }
    std::cout << std::left << std::setw(5) << abs(enb_ul.chest_res.ta_us) << RESET;
    std::cout << " -- SNR(db): ";
    std::cout << std::left << std::setw(6) << std::setprecision(3) << enb_ul.chest_res.snr_db;

    // std::cout << " -- F_Pwr: ";
    // std::string pwr_sign;
    // int width = 0;
    // if (falcon_sgl_pwr < 0) {
    //     pwr_sign = "";
    //     width = 7;

    // } else {
    //     pwr_sign = " ";
    //     width = 6;
    // }
    // std::cout << std::left << pwr_sign << std::setw(width) << std::setprecision(3) << falcon_sgl_pwr;

    std::cout << " -- CQI RQ: ";
    std::cout << decoding_mem.ran_ul_dci->cqi_request << "|" << decoding_mem.ran_ul_dci->multiple_csi_request_present;

    std::cout << " -- Noise Pwr: ";
    std::cout << std::left << std::setw(6) << std::setprecision(3) << noise;

    std::cout << YELLOW << " -- MCS: ";
    std::cout << std::left << std::setw(3) << ul_cfg.pusch.grant.tb.mcs_idx << RESET;

    std::cout << YELLOW << " -- ";
    std::cout << std::left << std::setw(6) << modulation_mode << RESET;

    std::cout << " -- ";
    if (pusch_res.crc == false)
    {
        std::cout << RED << std::setw(7) << "FAILED" << RESET;
        std::cout << " -- Len: " << ul_cfg.pusch.grant.tb.tbs / 8;
    }
    else
    {
        std::cout << BOLDGREEN << std::setw(7) << "SUCCESS" << RESET;
        std::cout << " -- Len: " << ul_cfg.pusch.grant.tb.tbs / 8;
    }
    if (decoding_mem.is_rar_gant)
    {
        std::cout << " -- RAR";
    }
    if (decoding_mem.is_retx == 1)
    {
        std::cout << " -- ReTX-UL";
    }
    std::cout << std::endl;
}

void PUSCH_Decoder::print_success(DCI_UL &decoding_mem, std::string offset_name, int table)
{
    std::cout << offset_name << "------->>>>>>"
              << " SF: " << (int)ul_sf.tti / 10 << "-" << (int)ul_sf.tti % 10;
    std::cout << " Success RNTI: " << decoding_mem.rnti;
    std::cout << " -- length: " << ul_cfg.pusch.grant.tb.tbs / 8;
    std::cout << " -- table: " << (table == 1) ? "64QAM" : "16QAM";
    std::cout << " -- TA(us): " << enb_ul.chest_res.ta_us;
    std::cout << " -- SNR: " << enb_ul.chest_res.snr_db << std::endl;
}

void PUSCH_Decoder::print_ul_grant(srsran_pusch_grant_t &grant)
{
    std::cout << "Decoding PUSCH grant: " << std::endl;
    std::cout << "L_prb: " << grant.L_prb << std::endl;
    std::cout << "n_prb: " << grant.n_prb[0] << ":" << grant.n_prb[1] << std::endl;
    std::cout << "n_prb_tilde: " << grant.n_prb_tilde[0] << ":" << grant.n_prb_tilde[1] << std::endl;
    std::cout << "freq_hopping: " << grant.freq_hopping << std::endl;
    std::cout << "nof_re: " << grant.nof_re << std::endl;
    std::cout << "nof_symb: " << grant.nof_symb << std::endl;
    std::cout << "n_dmrs: " << grant.n_dmrs << std::endl;
    std::cout << "tb: "
              << "mod: " << grant.tb.mod << " -- tbs: " << grant.tb.tbs << " -- rv: " << grant.tb.rv << "--mcs: " << grant.tb.mcs_idx << std::endl;
    std::cout << "last_tb: "
              << "mod: " << grant.last_tb.mod << " -- tbs: " << grant.last_tb.tbs << " -- rv: " << grant.last_tb.rv << "--mcs: " << grant.last_tb.mcs_idx;
    std::cout << "---------------------------------------" << std::endl;
}

void PUSCH_Decoder::print_uci(srsran_uci_value_t *uci)
{
    if (uci->cqi.data_crc == true)
    {
        std::cout << "[UCI] ";
        std::cout << " SR: " << uci->scheduling_request;
        std::cout << " -- RI: " << uci->ri << std::endl;
        std::cout << " -- CQI wideband: " << uci->cqi.wideband.wideband_cqi << "|" << uci->cqi.wideband.pmi << "|" << uci->cqi.wideband.spatial_diff_cqi << std::endl;
        std::cout << " -- CQI ue: " << uci->cqi.subband_ue.subband_label << "|" << uci->cqi.subband_ue.subband_cqi << std::endl;
        std::cout << " -- CQI hl sub cw0: " << uci->cqi.subband_hl.wideband_cqi_cw0 << " -- CQI hl sub cw1: " << uci->cqi.subband_hl.wideband_cqi_cw1 << std::endl;
    }
}

std::string convert_id_name(int id)
{
    std::string ret = "-";
    switch (id)
    {
    case ID_RAN_VAL:
        ret = "RandomValue";
        break;
    case ID_TMSI:
        ret = "TMSI";
        break;
    case ID_CON_RES:
        ret = "Contention Resolution";
        break;
    case ID_IMSI:
        ret = "IMSI";
        break;
    case ID_IMEI:
        ret = "IMEI";
        break;
    case ID_IMEISV:
        ret = "IMEISV";
        break;
    default:
        ret = "-";
        break;
    }
    return ret;
}
std::string convert_msg_name(int msg)
{
    std::string ret = "-";
    switch (msg)
    {
    case 0:
        ret = "RRC Connection Request";
        break;
    case 1:
        ret = "RRC Connection Setup";
        break;
    case 2:
        ret = "Attach Request";
        break;
    case 3:
        ret = "Identity Response";
        break;
    case 4:
        ret = "UECapability";
        break;
    default:
        ret = "-";
        break;
    }
    return ret;
}
void PUSCH_Decoder::print_api(uint32_t tti, uint16_t rnti, int id, std::string value, int msg)
{
    std::cout << std::left << std::setw(4) << tti / 10 << "-" << std::left << std::setw(5) << tti % 10;
    std::string id_name = convert_id_name(id);
    std::cout << std::left << std::setw(26) << id_name;
    std::cout << std::left << std::setw(17) << value;
    std::cout << std::left << std::setw(11) << rnti;
    std::string msg_name = convert_msg_name(msg);
    std::cout << std::left << std::setw(25) << msg_name;
    std::cout << std::endl;
}

int PUSCH_Decoder::investigate_valid_ul_grant(DCI_UL &decoding_mem)
{
    int ret = SRSRAN_SUCCESS;
    if (decoding_mem.is_rar_gant)
    {
        return SRSRAN_SUCCESS;
    }
    /*if RNTI == 0*/
    if (decoding_mem.rnti == 0)
    {
        ret = SRSRAN_ERROR;
    }
    /*if Transport Block size = 0 (wrong DCI detection or retransmission or pdsch for ack and uci)*/
    // Reject only when BOTH MCS tables produce TBS=0. Using || here previously
    // rejected nearly every grant because 256-QAM tables are rarely populated
    // in real traffic, so ran_ul_grant_256->tb.tbs is almost always 0 — that
    // left the PUSCH PCAP with just the 24-byte file header.
    if (decoding_mem.ran_ul_grant->tb.tbs == 0 && decoding_mem.ran_ul_grant_256->tb.tbs == 0)
    {
        ret = SRSRAN_ERROR;
    }
    /*if number of PRB is invalid*/
    if (!check_valid_prb_ul(decoding_mem.ran_ul_grant->L_prb))
    {
        ret = SRSRAN_ERROR;
    }

    return ret;
}
