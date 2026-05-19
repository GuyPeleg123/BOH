add_executable(test_keystore_ul test_keystore_ul.cc)

target_include_directories(test_keystore_ul PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/..
    ${PROJECT_SOURCE_DIR}/src)

target_link_libraries(test_keystore_ul
    DL_Sniffer_lib
    falcon_common
    srsran_phy
    srsran_asn1
    s1ap_asn1
    rrc_asn1
    asn1_utils
    ${FFT_LIBRARIES}
    ${Boost_LIBRARIES}
    ${SRSRAN_LIBRARIES}
    pthread)

add_test(NAME keystore_ul COMMAND test_keystore_ul)
