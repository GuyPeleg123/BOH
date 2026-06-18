#include "include/UL_Sniffer_PUSCH.h"
#include <cassert>

bool valid_prb_ul[101] = {true, true, true, true, true, true, true, false, true, true, true, false, true,
                          false, false, true, true, false, true, false, true, false, false, false, true, true,
                          false, true, false, false, true, false, true, false, false, false, true, false, false,
                          false, true, false, false, false, false, true, false, false, true, false, true, false,
                          false, false, true, false, false, false, false, false, true, false, false, false, true,
                          false, false, false, false, false, false, false, true, false, false, true, false, false,
                          false, false, true, true, false, false, false, false, false, false, false, false, true,
                          false, false, false, false, false, true, false, false, false, true};

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
    /* Each PUSCH_Decoder owns its softbuffer. decoder_a and decoder_b share the
       same ul_cfg reference, so writing ul_cfg.pusch.softbuffers.rx here would
       have both decoders alias (and double-free) one buffer. decode_run() points
       ul_cfg at this instance's own_softbuf right before each decode. */
    own_softbuf = new srsran_softbuffer_rx_t;
    srsran_softbuffer_rx_init(own_softbuf, SRSRAN_MAX_PRB);

    /* Scratch for the nominal-window symbols (used by the offset-retry pass).
       enb_ul.sf_symbols is allocated for max_prb=110, CP normal. */
    sf_symbols_len     = SRSRAN_SF_LEN_RE(110, SRSRAN_CP_NORM);
    sf_symbols_nominal = srsran_vec_cf_malloc(sf_symbols_len);
}

PUSCH_Decoder::~PUSCH_Decoder()
{
    srsran_vec_u8_zero(pusch_res.data, 2000 * 8);
    if (own_softbuf) { srsran_softbuffer_rx_free(own_softbuf); delete own_softbuf; own_softbuf = nullptr; }
    if (sf_symbols_nominal) { free(sf_symbols_nominal); sf_symbols_nominal = nullptr; }
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
    /* Point the shared ul_cfg at THIS decoder's own softbuffer before resetting/
       decoding, so decoder_a and decoder_b never reset or decode into each
       other's scratch (sequential A-then-B-fallback per grant). */
    ul_cfg.pusch.softbuffers.rx = own_softbuf;
    srsran_softbuffer_rx_reset_tbs(ul_cfg.pusch.softbuffers.rx, ul_cfg.pusch.grant.tb.tbs);

    /*Do channel estimation to calculate timing difference between UL & DL subframes, because of diffrent propagation times*/
    int ret = srsran_chest_ul_estimate_pusch(&enb_ul.chest, &ul_sf, &ul_cfg.pusch, enb_ul.sf_symbols, &enb_ul.chest_res);

    /*Use channel estimation result to perform channel equalizer to compensate the time delay*/
    pusch_res.crc = false; // reset crc result
    if (ret == SRSRAN_SUCCESS)
    {
        ret = srsran_pusch_decode(&enb_ul.pusch, &ul_sf, &ul_cfg.pusch, &enb_ul.chest_res, enb_ul.sf_symbols, &pusch_res);
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

/* Prepare this decoder's antenna for the current subframe: point the FFT at the
   right raw buffer, snapshot the raw samples for the offset-retry pass, run the
   nominal FFT, compute power and save the nominal symbols. Idempotent within a
   subframe (guarded by fft_prepared) so decoder_b can prepare lazily. */
void PUSCH_Decoder::prepare_fft()
{
    if (fft_prepared) return;

    if (decoder_a){
        enb_ul.in_buffer = original_buffer[0]; // 0 for downlink, 1 for uplink, now 0 because there are 2 separate buffers
    }else if (decoder_b){
        enb_ul.in_buffer = original_buffer[1]; // 0 for downlink, 1 for uplink, now 0 because there are 2 separate buffers
    }

    /* Snapshot the raw subframe BEFORE the FFT. srsran_enb_ul_fft applies its
       frequency shift in place on the in_buffer, so once the nominal FFT runs
       the raw samples are destroyed. We need a clean copy to re-FFT at alternate
       window offsets in the retry pass. Only needed when offset retry is enabled
       (UL/DUAL mode). buffer_offset[] is this decoder's OWN scratch pair
       (sf_buffer_offset[0] for A, sf_buffer_offset[1] for B), so the two
       decoders never race on it. */
    const bool offset_retry_enabled = (multi_ul_offset != 0);
    if (offset_retry_enabled)
    {
        const uint32_t snap_len = 3 * SRSRAN_SF_LEN_PRB(100);
        /* Snapshot the SAME window the nominal FFT consumes: decoder_a runs on
           original_buffer[0] (USRP A), decoder_b on original_buffer[1] (USRP B). */
        cf_t* raw_src = decoder_b ? original_buffer[1] : original_buffer[0];
        memcpy(buffer_offset[0], raw_src, sizeof(cf_t) * snap_len);
    }

    srsran_enb_ul_fft(&enb_ul);            // run FFT to uplink samples
    sf_power->computePower(enb_ul.sf_symbols);

    /* Save the nominal-window symbols. The FFT applies its frequency shift in
       place on the raw buffer, so it cannot be re-run to regenerate these; the
       offset-retry pass restores from this copy instead. */
    if (offset_retry_enabled && sf_symbols_nominal)
    {
        memcpy(sf_symbols_nominal, enb_ul.sf_symbols, sizeof(cf_t) * sf_symbols_len);
    }

    fft_prepared = true;
}

/* Nominal pass + FFT-window-offset retry pass for ONE grant, on the symbols this
   decoder's antenna currently holds. Side effects (pcap write, key store, MCS
   update) happen inside decode_run on CRC success exactly once. Restores the
   nominal symbols afterwards so the next grant's nominal pass is correct.
   Reports the winning channel estimate via out_snr / out_ta. */
bool PUSCH_Decoder::decode_grant_with_retry(DCI_UL &decoding_mem, float &out_snr, float &out_ta)
{
    const bool offset_retry_enabled = (multi_ul_offset != 0);

    /* PASS 1: nominal FFT window (sf_symbols already holds the nominal FFT). */
    bool crc = decode_grant(decoding_mem);

    /* Capture the nominal channel-estimate outcome for statistics and for
       steering the retry. ta_us gives the signed residual timing in
       microseconds; snr tells us whether the signal was even present. */
    out_snr = enb_ul.chest_res.snr_db;
    out_ta  = enb_ul.chest_res.ta_us;

    /* PASS 2: FFT-window-offset retry. Only for grants that FAILED CRC at the
       nominal window AND only when offset retry is enabled (UL/DUAL mode). A
       passive sniffer sees the UE's TA-precompensated UL with a geometry-
       dependent residual; when that residual pushes symbols past the CP
       tolerance, a strong signal still fails CRC. We re-FFT on a shifted window
       to re-centre it. */
    if (!crc && offset_retry_enabled)
    {
        const uint32_t sf_len = SRSRAN_SF_LEN_PRB(enb_ul.cell.nof_prb);

        /* Build candidate sample offsets, most-likely first:
           1) the measured residual ta_us -> samples (and its negation, to be
              robust to sign convention) when the nominal estimate was usable
              (snr >= ~0 dB);
           2) a small fixed fallback set spanning roughly +/- one CP for grants
              whose DMRS was too misaligned to give a reliable ta. */
        int  cand[8];
        int  ncand = 0;
        if (out_snr >= 0.0f && out_ta != 0.0f)
        {
            // samples = ta_us * 1e-6 * srate; srate = sf_len * 1000
            int meas = (int)lroundf(out_ta * (float)sf_len / 1000.0f);
            if (meas != 0) { cand[ncand++] = meas; cand[ncand++] = -meas; }
        }
        // Fixed fallback offsets (samples). At 15.36 Msps: 16->~1us, 32->~2us,
        // 64->~4us (~ one normal CP). Skip any that already equal the measured
        // candidate so we don't re-FFT+decode an identical window for nothing.
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
                // Keep the successful estimate for statistics.
                out_snr = enb_ul.chest_res.snr_db;
                out_ta  = enb_ul.chest_res.ta_us;
            }
        }

        /* Restore sf_symbols to the nominal window so the next grant's pass-1
           decode sees the correct (nominal) symbols. We cannot re-run
           srsran_enb_ul_fft (it shifts the raw buffer in place and is not
           idempotent), so restore from the saved copy. */
        if (sf_symbols_nominal)
        {
            memcpy(enb_ul.sf_symbols, sf_symbols_nominal, sizeof(cf_t) * sf_symbols_len);
        }
    }

    return crc;
}

/* Fallback entry point: decoder_a calls this on decoder_b for a grant that
   failed on antenna A. We lazily prepare antenna B's FFT (once per subframe) and
   then run the same per-antenna decode unit. No statistics here — decoder_a owns
   the count-once update_statistic_ul for the grant. */
bool PUSCH_Decoder::try_grant_fallback(DCI_UL &decoding_mem, float &out_snr, float &out_ta)
{
    out_snr = 0.0f;
    out_ta  = 0.0f;
    prepare_fft();                       // no-op after the first fallback this subframe
    return decode_grant_with_retry(decoding_mem, out_snr, out_ta);
}

void PUSCH_Decoder::decode()
{
    /* Always (re)prepare antenna A's FFT for this subframe. Reset the fallback
       decoder's per-subframe FFT flag so antenna B re-prepares lazily on its
       first use this subframe. */
    fft_prepared = false;
    prepare_fft();
    if (fallback_decoder) fallback_decoder->reset_fft_prepared();

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
                /* Antenna A: nominal pass + offset retry for this grant. */
                float win_snr = 0.0f, win_ta = 0.0f;
                bool crc = decode_grant_with_retry(decoding_mem, win_snr, win_ta);

                /* Antenna B fallback: only for grants that A could not decode.
                   This preserves the count-once invariant — at most one of A/B
                   produces a CRC success for a given grant, so decode_run fires
                   the pcap write / key store / MCS update at most once. With a
                   single UL antenna (no fallback registered) this is skipped and
                   behaviour is identical to before. */
                if (!crc && fallback_decoder)
                {
                    float b_snr = 0.0f, b_ta = 0.0f;
                    bool b_crc = fallback_decoder->try_grant_fallback(decoding_mem, b_snr, b_ta);
                    if (b_crc)
                    {
                        crc     = true;
                        win_snr = b_snr;   // report the antenna that actually decoded
                        win_ta  = b_ta;
                    }
                    else if (b_snr > win_snr)
                    {
                        // Both failed: keep the better-SNR estimate so the failure
                        // statistic reflects the stronger antenna's view.
                        win_snr = b_snr;
                        win_ta  = b_ta;
                    }
                }

                /*Update statistic when SNR is higher than 1, the statistic showed on terminal is only for RNTIs with SNR >=1*/
                /* Count each grant EXACTLY ONCE with its FINAL outcome (crc),
                   regardless of how many antennas/offsets were tried, using the
                   channel estimate from the attempt that produced it. */
                if (win_snr >= 1)
                { // chest_res.snr_db >= 1
                    mcstracking->update_statistic_ul(decoding_mem.rnti, crc, decoding_mem, win_snr, win_ta);
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
