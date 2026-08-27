idf_component_register(
    SRCS "parity_main.c" "../../main/native_frame_v1.c" "../../main/provisioning_v1.c"
         "../../main/csi_capture_v1.c" "../../main/sender_v1.c"
    INCLUDE_DIRS "." "../../main" "${CMAKE_CURRENT_BINARY_DIR}"
    REQUIRES app_update esp_netif esp_timer esp_wifi mbedtls nvs_flash lwip)
target_compile_definitions(${COMPONENT_LIB} PRIVATE CSI_CAPTURE_V1_TEST=1)

if(NOT CMAKE_BUILD_EARLY_EXPANSION)
    set(CAPABILITY_HEADER "${CMAKE_CURRENT_BINARY_DIR}/capability_build_facts.h")
    set(CAPABILITY_JSON "${CMAKE_BINARY_DIR}/capability-build-facts.json")
    set(WIFI_ABI_GENERIC "${IDF_PATH}/components/esp_wifi/include/esp_wifi_types_generic.h")
    set(WIFI_ABI_NATIVE "${IDF_PATH}/components/esp_wifi/include/local/esp_wifi_types_native.h")
    add_custom_command(
        OUTPUT "${CAPABILITY_HEADER}" "${CAPABILITY_JSON}"
        COMMAND "${PYTHON}" "${CMAKE_CURRENT_LIST_DIR}/../../build_capability_facts.py"
                "${CAPABILITY_HEADER}" "${CAPABILITY_JSON}"
                "${WIFI_ABI_GENERIC}" "${WIFI_ABI_NATIVE}"
        DEPENDS "${CMAKE_CURRENT_LIST_DIR}/../../build_capability_facts.py"
                "${WIFI_ABI_GENERIC}" "${WIFI_ABI_NATIVE}"
        VERBATIM)
    add_custom_target(capability_build_facts DEPENDS "${CAPABILITY_HEADER}" "${CAPABILITY_JSON}")
    add_dependencies(${COMPONENT_LIB} capability_build_facts)
endif()

if(NOT CMAKE_BUILD_EARLY_EXPANSION)
    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    set(FROZEN_HEADER "${CMAKE_CURRENT_BINARY_DIR}/frozen_vectors.h")
    add_custom_command(
        OUTPUT "${FROZEN_HEADER}"
        COMMAND "${Python3_EXECUTABLE}"
                "${CMAKE_CURRENT_LIST_DIR}/../generate_frozen_vectors.py"
                "${CMAKE_CURRENT_LIST_DIR}/../../../../tests/fixtures/native-frame"
                "${FROZEN_HEADER}"
        DEPENDS "${CMAKE_CURRENT_LIST_DIR}/../generate_frozen_vectors.py"
                "${CMAKE_CURRENT_LIST_DIR}/../../../../tests/fixtures/native-frame/capabilities-v1.hex"
                "${CMAKE_CURRENT_LIST_DIR}/../../../../tests/fixtures/native-frame/csi-non-ht-3-pairs.hex"
                "${CMAKE_CURRENT_LIST_DIR}/../../../../tests/fixtures/native-frame/csi-ht-5-pairs-first-invalid.hex"
                "${CMAKE_CURRENT_LIST_DIR}/../../../../tests/fixtures/native-frame/csi-ht-stbc-7-pairs.hex"
                "${CMAKE_CURRENT_LIST_DIR}/../../../../tests/fixtures/native-frame/health-v1.hex"
        VERBATIM)
    add_custom_target(frozen_vectors DEPENDS "${FROZEN_HEADER}")
    add_dependencies(${COMPONENT_LIB} frozen_vectors)
endif()
