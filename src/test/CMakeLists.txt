add_executable(test_keystore test_keystore.cc)

target_include_directories(test_keystore PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/..
    ${CMAKE_CURRENT_SOURCE_DIR}/../include)

target_compile_options(test_keystore PRIVATE $<$<COMPILE_LANGUAGE:CXX>:-std=c++11>)

target_link_libraries(test_keystore
    DL_Sniffer_lib
    srsran_common
    srsran_phy
    srslog
    pthread)

add_test(NAME keystore_tests COMMAND test_keystore)
