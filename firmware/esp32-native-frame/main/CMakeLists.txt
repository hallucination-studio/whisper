idf_component_register(
    SRCS "main.c" "native_frame_v1.c" "provisioning_v1.c" "csi_capture_v1.c" "sender_v1.c"
    INCLUDE_DIRS "." "${CMAKE_CURRENT_BINARY_DIR}"
    REQUIRES app_update esp_event esp_netif esp_timer esp_wifi mbedtls nvs_flash lwip)

if(NOT CMAKE_BUILD_EARLY_EXPANSION)
    set(CAPABILITY_HEADER "${CMAKE_CURRENT_BINARY_DIR}/capability_build_facts.h")
    set(CAPABILITY_JSON "${CMAKE_BINARY_DIR}/capability-build-facts.json")
    set(WIFI_ABI_GENERIC "${IDF_PATH}/components/esp_wifi/include/esp_wifi_types_generic.h")
    set(WIFI_ABI_NATIVE "${IDF_PATH}/components/esp_wifi/include/local/esp_wifi_types_native.h")
    add_custom_command(
        OUTPUT "${CAPABILITY_HEADER}" "${CAPABILITY_JSON}"
        COMMAND "${PYTHON}" "${CMAKE_CURRENT_LIST_DIR}/../build_capability_facts.py"
                "${CAPABILITY_HEADER}" "${CAPABILITY_JSON}"
                "${WIFI_ABI_GENERIC}" "${WIFI_ABI_NATIVE}"
        DEPENDS "${CMAKE_CURRENT_LIST_DIR}/../build_capability_facts.py"
                "${WIFI_ABI_GENERIC}" "${WIFI_ABI_NATIVE}"
        VERBATIM)
    add_custom_target(capability_build_facts DEPENDS "${CAPABILITY_HEADER}" "${CAPABILITY_JSON}")
    add_dependencies(${COMPONENT_LIB} capability_build_facts)
endif()
