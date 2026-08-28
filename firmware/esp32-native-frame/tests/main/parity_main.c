#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "csi_capture_v1.h"
#include "esp_netif.h"
#include "frozen_vectors.h"
#include "native_frame_v1.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "provisioning_v1.h"
#include "sender_v1.h"

static const uint8_t KEY[32] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
};

static bool seal_matches(
    nf_v1_message_kind_t kind,
    uint64_t message_sequence,
    const uint8_t *body,
    size_t body_length,
    const uint8_t *expected,
    size_t expected_length)
{
    const nf_v1_envelope_t envelope = {
        .device_id = UINT64_C(0x0102030405060708),
        .key_epoch = 7,
        .boot_generation = 9,
        .message_sequence = message_sequence,
        .datagram_budget_bytes = 1024,
    };
    uint8_t datagram[NF_V1_HEADER_BYTES + NF_V1_MAX_PLAINTEXT_BYTES + NF_V1_TAG_BYTES];
    size_t datagram_length = 0;
    return nf_v1_seal(
               &envelope,
               kind,
               KEY,
               body,
               body_length,
               datagram,
               sizeof(datagram),
               &datagram_length)
            == NF_V1_OK
        && datagram_length == expected_length
        && memcmp(datagram, expected, expected_length) == 0;
}

static bool check_capabilities(uint8_t digest[32])
{
    const nf_v1_capability_descriptor_t descriptor = {
        .firmware_build_digest = {[0 ... 31] = 0x11},
        .idf_wifi_abi_digest = {[0 ... 31] = 0x22},
        .datagram_budget_bytes = 1024,
    };
    uint8_t body[NF_V1_CAPABILITIES_BODY_BYTES];
    size_t body_length = 0;
    return nf_v1_encode_capabilities(&descriptor, body, sizeof(body), &body_length, digest)
            == NF_V1_OK
        && body_length == NF_V1_CAPABILITIES_BODY_BYTES
        && memcmp(body, digest, 32) == 0
        && body[32] == NF_V1_DESCRIPTOR_BYTES && body[33] == 0
        && body[34] == 1 && body[42] == 0x07
        && seal_matches(
            NF_V1_CAPABILITIES,
            11,
            body,
            body_length,
            FROZEN_CAPABILITIES,
            FROZEN_CAPABILITIES_BYTES);
}

static bool check_csi(
    const uint8_t digest[32],
    uint64_t message_sequence,
    const nf_v1_csi_data_t *csi,
    const uint8_t *expected,
    size_t expected_length,
    uint16_t expected_pairs)
{
    uint8_t body[NF_V1_MAX_PLAINTEXT_BYTES];
    size_t body_length = 0;
    nf_v1_csi_data_t input = *csi;
    memcpy(input.capability_digest, digest, 32);
    return nf_v1_encode_csi_data(&input, body, sizeof(body), &body_length) == NF_V1_OK
        && body[70] == input.block_count
        && body[73] == (uint8_t)expected_pairs && body[74] == (uint8_t)(expected_pairs >> 8)
        && seal_matches(NF_V1_CSI_DATA, message_sequence, body, body_length, expected, expected_length);
}

static bool check_all(void)
{
    uint8_t digest[32];
    if (!check_capabilities(digest)) {
        return false;
    }
    static const uint8_t SOURCE_MAC[6] = {2, 0, 0, 0, 0, 10};
    static const uint8_t NON_HT_RAW[] = {1, 2, 0x80, 0x7f, 0xff, 0};
    static const nf_v1_ltf_block_t NON_HT_BLOCKS[] = {
        {.kind = NF_V1_LTF_LLTF, .sample_count = 3, .raw_offset_bytes = 0},
    };
    const nf_v1_csi_data_t non_ht = {
        .capture_sequence = 21,
        .driver_rx_timestamp_us = 22,
        .callback_tick_us = 23,
        .source_mac = {2, 0, 0, 0, 0, 10},
        .radio = {.channel = 1, .secondary = NF_V1_SECONDARY_NONE, .phy = NF_V1_PHY_NON_HT,
            .bandwidth = NF_V1_BANDWIDTH_20_MHZ, .stbc = 0, .rssi_dbm = -42,
            .noise_floor_dbm = -95, .rate = 6, .mcs = 0, .rx_antenna = 0},
        .blocks = NON_HT_BLOCKS, .block_count = 1,
        .raw_csi = NON_HT_RAW, .raw_csi_bytes = sizeof(NON_HT_RAW),
    };
    static const uint8_t HT_RAW[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa5, 0x5a};
    static const nf_v1_ltf_block_t HT_BLOCKS[] = {
        {.kind = NF_V1_LTF_LLTF, .sample_count = 2, .raw_offset_bytes = 0},
        {.kind = NF_V1_LTF_HTLTF, .sample_count = 3, .raw_offset_bytes = 4},
    };
    const nf_v1_csi_data_t ht = {
        .capture_sequence = 31, .driver_rx_timestamp_us = 32, .callback_tick_us = 33,
        .source_mac = {2, 0, 0, 0, 0, 10},
        .radio = {.channel = 6, .secondary = NF_V1_SECONDARY_ABOVE, .phy = NF_V1_PHY_HT,
            .bandwidth = NF_V1_BANDWIDTH_40_MHZ, .stbc = 0, .rssi_dbm = -50,
            .noise_floor_dbm = -96, .rate = 0, .mcs = 7, .rx_antenna = 1},
        .first_invalid_bytes = 4, .trailing_invalid_bytes = 2,
        .blocks = HT_BLOCKS, .block_count = 2, .raw_csi = HT_RAW, .raw_csi_bytes = sizeof(HT_RAW),
    };
    static const uint8_t STBC_RAW[] = {10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23};
    static const nf_v1_ltf_block_t STBC_BLOCKS[] = {
        {.kind = NF_V1_LTF_LLTF, .sample_count = 2, .raw_offset_bytes = 0},
        {.kind = NF_V1_LTF_HTLTF, .sample_count = 2, .raw_offset_bytes = 4},
        {.kind = NF_V1_LTF_STBC_HTLTF, .sample_count = 3, .raw_offset_bytes = 8},
    };
    const nf_v1_csi_data_t stbc = {
        .capture_sequence = 41, .driver_rx_timestamp_us = 42, .callback_tick_us = 43,
        .source_mac = {2, 0, 0, 0, 0, 10},
        .radio = {.channel = 11, .secondary = NF_V1_SECONDARY_BELOW, .phy = NF_V1_PHY_HT,
            .bandwidth = NF_V1_BANDWIDTH_40_MHZ, .stbc = 1, .rssi_dbm = -55,
            .noise_floor_dbm = -97, .rate = 0, .mcs = 3, .rx_antenna = 0},
        .blocks = STBC_BLOCKS, .block_count = 3,
        .raw_csi = STBC_RAW, .raw_csi_bytes = sizeof(STBC_RAW),
    };
    if (memcmp(SOURCE_MAC, non_ht.source_mac, sizeof(SOURCE_MAC)) != 0
        || !check_csi(digest, 12, &non_ht, FROZEN_CSI_NON_HT, FROZEN_CSI_NON_HT_BYTES, 3)
        || !check_csi(digest, 13, &ht, FROZEN_CSI_HT, FROZEN_CSI_HT_BYTES, 5)
        || !check_csi(digest, 14, &stbc, FROZEN_CSI_HT_STBC, FROZEN_CSI_HT_STBC_BYTES, 7)) {
        return false;
    }
    nf_v1_health_t health = {
        .callback_tick_us = 51, .capture_seen = 52, .queue_drop_no_slot = 53,
        .queue_drop_full = 54, .oversize_reject = 55, .encode_reject = 56,
        .send_failure = 57, .pool_high_water_slots = 3, .callback_max_us = 58,
        .encoder_max_us = 59,
    };
    memcpy(health.capability_digest, digest, 32);
    uint8_t health_body[NF_V1_HEALTH_BODY_BYTES];
    size_t health_length = 0;
    return nf_v1_encode_health(&health, health_body, sizeof(health_body), &health_length) == NF_V1_OK
        && health_length == NF_V1_HEALTH_BODY_BYTES
        && seal_matches(
            NF_V1_HEALTH, 15, health_body, health_length, FROZEN_HEALTH, FROZEN_HEALTH_BYTES);
}

static bool seed_test_nvs(bool include_key, bool include_runtime, uint32_t generation)
{
    static const uint8_t DIGEST[32] = {[0 ... 31] = 0x5a};
    nvs_flash_deinit();
    if (nvs_flash_erase() != ESP_OK || nvs_flash_init() != ESP_OK) {
        return false;
    }
    nvs_handle_t handle;
    if (nvs_open("provision", NVS_READWRITE, &handle) != ESP_OK) {
        return false;
    }
    bool ok = nvs_set_u16(handle, "schema", PROVISIONING_V1_SCHEMA) == ESP_OK
        && nvs_set_u64(handle, "device_id", 0) == ESP_OK
        && nvs_set_u16(handle, "key_epoch", 7) == ESP_OK
        && (!include_key || nvs_set_blob(handle, "aes_key", KEY, sizeof(KEY)) == ESP_OK)
        && nvs_set_str(handle, "ssid", "native-frame-test") == ESP_OK
        && nvs_set_str(handle, "wifi_pass", "test-only-password") == ESP_OK
        && nvs_set_u16(handle, "probe_port", 9000) == ESP_OK
        && nvs_set_str(handle, "collector_ip", "192.0.2.10") == ESP_OK
        && nvs_set_u16(handle, "collect_port", 9000) == ESP_OK
        && nvs_set_blob(handle, "cap_digest", DIGEST, sizeof(DIGEST)) == ESP_OK
        && nvs_commit(handle) == ESP_OK;
    nvs_close(handle);
    if (!ok || !include_runtime || nvs_open("runtime", NVS_READWRITE, &handle) != ESP_OK) {
        return ok && !include_runtime;
    }
    ok = nvs_set_u32(handle, "boot_generation", generation) == ESP_OK
        && nvs_commit(handle) == ESP_OK;
    nvs_close(handle);
    return ok;
}

static bool overwrite_provisioning_schema(uint16_t schema)
{
    nvs_handle_t handle;
    if (nvs_open("provision", NVS_READWRITE, &handle) != ESP_OK) {
        return false;
    }
    bool ok = nvs_set_u16(handle, "schema", schema) == ESP_OK
        && nvs_commit(handle) == ESP_OK;
    nvs_close(handle);
    return ok;
}

static bool check_provisioning(void)
{
    provisioning_v1_t provisioning;
    uint32_t generation = 0;
    if (!seed_test_nvs(true, true, 4)
        || provisioning_v1_load(&provisioning) != ESP_OK
        || provisioning.device_id != 0
        || strcmp(provisioning.station_ssid, "native-frame-test") != 0
        || boot_generation_v1_advance(&generation) != ESP_OK || generation != 5
        || !seed_test_nvs(true, true, 0)
        || boot_generation_v1_advance(&generation) != ESP_OK || generation != 1
        || !seed_test_nvs(false, true, 1)
        || provisioning_v1_load(&provisioning) == ESP_OK
        || !seed_test_nvs(true, false, 0)
        || boot_generation_v1_advance(&generation) == ESP_OK
        || !seed_test_nvs(true, true, UINT32_MAX)
        || boot_generation_v1_advance(&generation) == ESP_OK
        || !overwrite_provisioning_schema(1)
        || provisioning_v1_load(&provisioning) == ESP_OK) {
        return false;
    }
    nvs_handle_t handle;
    uint32_t stored = 0;
    return nvs_open("runtime", NVS_READONLY, &handle) == ESP_OK
        && nvs_get_u32(handle, "boot_generation", &stored) == ESP_OK
        && (nvs_close(handle), stored == UINT32_MAX);
}

static wifi_csi_info_t test_csi(int8_t *raw, uint16_t length)
{
    wifi_csi_info_t info = {
        .rx_ctrl = {
            .rssi = -42, .rate = 6, .sig_mode = 1, .mcs = 7, .cwb = 1, .stbc = 1,
            .noise_floor = -95, .channel = 6, .secondary_channel = 1,
            .timestamp = 1234, .ant = 1, .rx_state = 0,
        },
        .mac = {2, 0, 0, 0, 0, 10},
        .dmac = {2, 0, 0, 0, 0, 11},
        .first_word_invalid = true,
        .buf = raw,
        .len = length,
        .rx_seq = 77,
    };
    return info;
}

static bool check_csi_radio_combinations(void)
{
    const csi_capture_v1_config_t config = {
        .station_bssid = {2, 0, 0, 0, 0, 10},
        .station_mac = {2, 0, 0, 0, 0, 11},
        .channel = 14,
    };
    csi_capture_v1_t capture;
    int8_t raw[] = {1, 2};
    wifi_csi_info_t info = test_csi(raw, sizeof(raw));
    info.rx_ctrl.channel = 14;
    const uint8_t valid[][4] = {
        {0, 0, 0, 0}, /* Non-HT, 20 MHz, none, non-STBC. */
        {1, 0, 0, 1}, /* HT, 20 MHz, none. */
        {1, 1, 2, 1}, /* HT, 40 MHz, below. */
    };
    if (!csi_capture_v1_init(&capture, &config)) {
        return false;
    }
    for (size_t index = 0; index < sizeof(valid) / sizeof(valid[0]); ++index) {
        info.rx_ctrl.sig_mode = valid[index][0];
        info.rx_ctrl.cwb = valid[index][1];
        info.rx_ctrl.secondary_channel = valid[index][2];
        info.rx_ctrl.stbc = valid[index][3];
        csi_capture_v1_callback(&capture, &info);
        uint8_t slot_index;
        if (csi_capture_v1_take_ready(&capture, &slot_index) == NULL
            || !csi_capture_v1_release(&capture, slot_index)) {
            return false;
        }
    }
    const uint8_t invalid[][4] = {
        {0, 1, 1, 0}, /* Non-HT at 40 MHz. */
        {1, 0, 1, 0}, /* HT 20 MHz with a secondary channel. */
        {1, 1, 0, 0}, /* HT 40 MHz without a secondary channel. */
    };
    for (size_t index = 0; index < sizeof(invalid) / sizeof(invalid[0]); ++index) {
        info.rx_ctrl.sig_mode = invalid[index][0];
        info.rx_ctrl.cwb = invalid[index][1];
        info.rx_ctrl.secondary_channel = invalid[index][2];
        info.rx_ctrl.stbc = invalid[index][3];
        csi_capture_v1_callback(&capture, &info);
    }
    return atomic_load(&capture.counters.capture_seen) == 3
        && atomic_load(&capture.counters.encode_reject) == 3;
}

static bool check_csi_capture(void)
{
    const csi_capture_v1_config_t config = {
        .station_bssid = {2, 0, 0, 0, 0, 10},
        .station_mac = {2, 0, 0, 0, 0, 11},
        .channel = 6,
    };
    csi_capture_v1_t capture;
    static int8_t raw[NF_V1_MAX_RAW_CSI_BYTES];
    for (size_t index = 0; index < sizeof(raw); ++index) {
        raw[index] = (int8_t)index;
    }
    wifi_csi_info_t info = test_csi(raw, 4);
    if (!csi_capture_v1_init(&capture, &config)) {
        return false;
    }
    csi_capture_v1_callback(&capture, &info);
    uint8_t first_index;
    const csi_capture_v1_slot_t *slot = csi_capture_v1_take_ready(&capture, &first_index);
    if (slot == NULL || slot->capture_sequence != 1 || slot->callback_tick_us == 0
        || slot->raw_csi_bytes != 4 || memcmp(slot->raw_csi, raw, 4) != 0
        || memcmp(slot->source_mac, info.mac, 6) != 0
        || slot->driver_rx_timestamp_us != 1234 || slot->first_invalid_bytes != 4
        || slot->radio.channel != 6 || slot->radio.secondary != NF_V1_SECONDARY_ABOVE
        || slot->radio.phy != NF_V1_PHY_HT || slot->radio.bandwidth != NF_V1_BANDWIDTH_40_MHZ
        || slot->radio.stbc != 1 || slot->radio.rssi_dbm != -42
        || slot->radio.noise_floor_dbm != -95 || slot->radio.rate != 0
        || slot->radio.mcs != 7 || slot->radio.rx_antenna != 1
        || !csi_capture_v1_release(&capture, first_index)
        || csi_capture_v1_release(&capture, first_index)
        || csi_capture_v1_release(&capture, CSI_CAPTURE_V1_SLOT_COUNT)) {
        return false;
    }

    info.len = sizeof(raw);
    csi_capture_v1_callback(&capture, &info);
    uint8_t held_index;
    slot = csi_capture_v1_take_ready(&capture, &held_index);
    if (slot == NULL || slot->capture_sequence != 2 || slot->raw_csi_bytes != sizeof(raw)
        || memcmp(slot->raw_csi, raw, sizeof(raw)) != 0) {
        return false;
    }
    info.len = sizeof(raw) + 1;
    csi_capture_v1_callback(&capture, &info);
    info.len = 4;
    info.mac[5]++;
    csi_capture_v1_callback(&capture, &info);
    info.mac[5]--;
    info.rx_ctrl.sig_mode = 3;
    csi_capture_v1_callback(&capture, &info);
    info.rx_ctrl.sig_mode = 1;

    csi_capture_v1_callback(&capture, &info); /* sequence 3: ready */
    csi_capture_v1_callback(&capture, &info); /* sequence 4: no slot */
    if (!csi_capture_v1_release(&capture, held_index)) {
        return false;
    }
    csi_capture_v1_callback(&capture, &info); /* sequence 5: ready queue full */

    uint8_t reused_index;
    if (csi_capture_v1_take_ready(&capture, &reused_index) == NULL) {
        return false;
    }
    csi_capture_v1_callback(&capture, &info); /* sequence 6: ready */
    csi_capture_v1_callback(&capture, &info); /* sequence 7: no slot */

    uint8_t ready_a;
    const csi_capture_v1_slot_t *ready_slot_a = csi_capture_v1_take_ready(&capture, &ready_a);
    if (ready_slot_a == NULL || ready_slot_a->capture_sequence != 6
        || atomic_load(&capture.counters.capture_seen) != 7
        || atomic_load(&capture.counters.oversize_reject) != 1
        || atomic_load(&capture.counters.encode_reject) != 2
        || atomic_load(&capture.counters.queue_drop_no_slot) != 2
        || atomic_load(&capture.counters.queue_drop_full) != 1
        || !csi_capture_v1_release(&capture, reused_index)
        || !csi_capture_v1_release(&capture, ready_a)) {
        return false;
    }
    csi_capture_v1_callback(&capture, &info); /* sequence 8: released slot reused */
    slot = csi_capture_v1_take_ready(&capture, &first_index);
    if (slot == NULL || slot->capture_sequence != 8 || first_index != reused_index
        || atomic_load(&capture.counters.capture_seen) != 8
        || !csi_capture_v1_release(&capture, first_index)) {
        return false;
    }
    atomic_store(&capture.counters.encode_reject, UINT32_MAX);
    info.mac[5]++;
    csi_capture_v1_callback(&capture, &info);
    return atomic_load(&capture.counters.encode_reject) == UINT32_MAX;
}

static uint16_t test_u16_le(const uint8_t *bytes)
{
    return (uint16_t)bytes[0] | ((uint16_t)bytes[1] << 8);
}

static uint64_t test_u64_le(const uint8_t *bytes)
{
    uint64_t value = 0;
    for (size_t index = 0; index < 8; ++index) {
        value |= (uint64_t)bytes[index] << (index * 8);
    }
    return value;
}

static bool queue_sender_csi(csi_capture_v1_t *capture, wifi_csi_info_t *info,
    uint8_t secondary, uint16_t length)
{
    info->rx_ctrl.secondary_channel = secondary;
    info->len = length;
    csi_capture_v1_callback(capture, info);
    return true;
}

static bool check_sender(void)
{
    const csi_capture_v1_config_t capture_config = {
        .station_bssid = {2, 0, 0, 0, 0, 10},
        .station_mac = {2, 0, 0, 0, 0, 11},
        .channel = 6,
    };
    static csi_capture_v1_t capture;
    static int8_t raw[NF_V1_MAX_RAW_CSI_BYTES];
    for (size_t index = 0; index < sizeof(raw); ++index) {
        raw[index] = (int8_t)index;
    }
    wifi_csi_info_t info = test_csi(raw, sizeof(raw));
    const struct sockaddr_in collector = {
        .sin_family = AF_INET,
        .sin_port = htons(9),
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
    };
    const nf_v1_envelope_t envelope = {
        .device_id = 1,
        .key_epoch = 1,
        .boot_generation = 1,
        .message_sequence = 1,
        .datagram_budget_bytes = NF_V1_MIN_DATAGRAM_BUDGET_BYTES,
    };
    const nf_v1_capability_descriptor_t descriptor = {
        .firmware_build_digest = {[0 ... 31] = 0x11},
        .idf_wifi_abi_digest = {[0 ... 31] = 0x22},
        .datagram_budget_bytes = NF_V1_MIN_DATAGRAM_BUDGET_BYTES,
    };
    if (esp_netif_init() != ESP_OK) {
        return false;
    }
    const int socket_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    static sender_v1_t sender;
    if (socket_fd < 0 || !csi_capture_v1_init(&capture, &capture_config)
        || !sender_v1_init(&sender, socket_fd, (const struct sockaddr *)&collector,
            sizeof(collector), &envelope, KEY)
        || sender_v1_send_capabilities(&sender, &descriptor) != SENDER_V1_OK) {
        if (socket_fd >= 0) {
            close(socket_fd);
        }
        return false;
    }

    queue_sender_csi(&capture, &info, NF_V1_SECONDARY_ABOVE, sizeof(raw));
    if (sender_v1_send_next_csi(&sender, &capture) != SENDER_V1_OK
        || sender.datagram_length != NF_V1_MIN_DATAGRAM_BUDGET_BYTES
        || test_u64_le(&sender.datagram[20]) != 2 || sender.body[68] != 4
        || sender.body[70] != 3 || test_u16_le(&sender.body[71]) != 612
        || sender.body[75] != NF_V1_LTF_LLTF || test_u16_le(&sender.body[77]) != 64
        || test_u16_le(&sender.body[79]) != 0
        || sender.body[81] != NF_V1_LTF_HTLTF || test_u16_le(&sender.body[83]) != 121
        || test_u16_le(&sender.body[85]) != 128
        || sender.body[87] != NF_V1_LTF_STBC_HTLTF
        || test_u16_le(&sender.body[89]) != 121 || test_u16_le(&sender.body[91]) != 370) {
        close(socket_fd);
        return false;
    }
    queue_sender_csi(&capture, &info, NF_V1_SECONDARY_BELOW, sizeof(raw));
    if (sender_v1_send_next_csi(&sender, &capture) != SENDER_V1_OK
        || sender.body[59] != NF_V1_SECONDARY_BELOW || test_u64_le(&sender.datagram[20]) != 3) {
        close(socket_fd);
        return false;
    }

    queue_sender_csi(&capture, &info, NF_V1_SECONDARY_ABOVE, sizeof(raw) - 2);
    if (sender_v1_send_next_csi(&sender, &capture) != SENDER_V1_CSI_DROPPED
        || sender.next_message_sequence != 4) {
        close(socket_fd);
        return false;
    }
    sender.socket_fd = -1;
    queue_sender_csi(&capture, &info, NF_V1_SECONDARY_ABOVE, sizeof(raw));
    if (sender_v1_send_next_csi(&sender, &capture) != SENDER_V1_SEND_FAILED
        || sender.health.send_failure != 1 || test_u64_le(&sender.datagram[20]) != 4) {
        close(socket_fd);
        return false;
    }
    sender.socket_fd = socket_fd;
    queue_sender_csi(&capture, &info, NF_V1_SECONDARY_ABOVE, sizeof(raw));
    if (sender_v1_send_next_csi(&sender, &capture) != SENDER_V1_OK
        || test_u64_le(&sender.datagram[20]) != 5) {
        close(socket_fd);
        return false;
    }

    sender.next_message_sequence = UINT64_MAX;
    queue_sender_csi(&capture, &info, NF_V1_SECONDARY_ABOVE, sizeof(raw));
    if (sender_v1_send_next_csi(&sender, &capture) != SENDER_V1_OK
        || test_u64_le(&sender.datagram[20]) != UINT64_MAX) {
        close(socket_fd);
        return false;
    }
    queue_sender_csi(&capture, &info, NF_V1_SECONDARY_ABOVE, sizeof(raw));
    if (sender_v1_send_next_csi(&sender, &capture) != SENDER_V1_SEQUENCE_EXHAUSTED) {
        close(socket_fd);
        return false;
    }
    queue_sender_csi(&capture, &info, NF_V1_SECONDARY_ABOVE, sizeof(raw));
    uint8_t released_index;
    if (csi_capture_v1_take_ready(&capture, &released_index) == NULL
        || !csi_capture_v1_release(&capture, released_index)) {
        close(socket_fd);
        return false;
    }

    nf_v1_envelope_t health_envelope = envelope;
    health_envelope.message_sequence = 10;
    static sender_v1_t health_sender;
    if (!sender_v1_init(&health_sender, socket_fd, (const struct sockaddr *)&collector,
            sizeof(collector), &health_envelope, KEY)
        || sender_v1_send_health(&health_sender, &capture, 100, 2, 3, 4) != SENDER_V1_OK) {
        close(socket_fd);
        return false;
    }
    const uint64_t first_capture_seen = health_sender.health.capture_seen;
    const uint64_t first_encode_reject = health_sender.health.encode_reject;
    csi_capture_v1_record_encode_reject(&capture);
    const bool health_ok = sender_v1_send_health(&health_sender, &capture, 101, 2, 3, 4)
            == SENDER_V1_OK
        && health_sender.health.capture_seen >= first_capture_seen
        && health_sender.health.encode_reject == first_encode_reject + 1;
    const struct sockaddr_in6 collector_v6 = {
        .sin6_family = AF_INET6,
        .sin6_port = htons(9),
        .sin6_addr = IN6ADDR_LOOPBACK_INIT,
    };
    const int socket_v6 = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    static sender_v1_t sender_v6;
    memset(&sender_v6, 0xa5, sizeof(sender_v6));
    sender_v1_t unchanged = sender_v6;
    const bool malformed_rejected = !sender_v1_init(&sender_v6, socket_v6,
            (const struct sockaddr *)&collector_v6, sizeof(collector_v6) - 1, &envelope, KEY)
        && memcmp(&sender_v6, &unchanged, sizeof(sender_v6)) == 0;
    const bool ipv6_ok = socket_v6 >= 0 && malformed_rejected
        && sender_v1_init(&sender_v6, socket_v6, (const struct sockaddr *)&collector_v6,
            sizeof(collector_v6), &envelope, KEY)
        && sender_v1_send_capabilities(&sender_v6, &descriptor) == SENDER_V1_OK
        && sender_v6.collector.ss_family == AF_INET6
        && sender_v6.collector_length == sizeof(collector_v6);
    if (socket_v6 >= 0) {
        close(socket_v6);
    }
    close(socket_fd);
    return health_ok && ipv6_ok;
}

void app_main(void)
{
    if (!check_provisioning()) {
        printf("NATIVE_FRAME_V1_PROVISIONING_FAIL\n");
    } else {
        printf("NATIVE_FRAME_V1_PROVISIONING_PASS\n");
    }
    if (!check_all()) {
        printf("NATIVE_FRAME_V1_PARITY_FAIL\n");
    } else {
        printf("NATIVE_FRAME_V1_PARITY_PASS\n");
    }
    if (!check_csi_radio_combinations() || !check_csi_capture()) {
        printf("NATIVE_FRAME_V1_CSI_CAPTURE_FAIL\n");
    } else {
        printf("NATIVE_FRAME_V1_CSI_CAPTURE_PASS\n");
    }
    if (!check_sender()) {
        printf("NATIVE_FRAME_V1_SENDER_FAIL\n");
    } else {
        printf("NATIVE_FRAME_V1_SENDER_PASS\n");
    }
    fflush(stdout);
    while (true) {
        vTaskDelay(portMAX_DELAY);
    }
}
