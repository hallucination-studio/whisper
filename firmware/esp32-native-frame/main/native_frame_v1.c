#include "native_frame_v1.h"

#include <stdbool.h>
#include <string.h>

#include "mbedtls/gcm.h"
#include "mbedtls/sha256.h"

#define NF_V1_CSI_FIXED_BODY_BYTES 75U
#define NF_V1_LTF_BLOCK_BYTES 6U

static void put_u16_le(uint8_t *output, uint16_t value)
{
    output[0] = (uint8_t)value;
    output[1] = (uint8_t)(value >> 8);
}

static void put_u32_le(uint8_t *output, uint32_t value)
{
    for (size_t index = 0; index < 4; ++index) {
        output[index] = (uint8_t)(value >> (index * 8));
    }
}

static void put_u64_le(uint8_t *output, uint64_t value)
{
    for (size_t index = 0; index < 8; ++index) {
        output[index] = (uint8_t)(value >> (index * 8));
    }
}

static uint16_t get_u16_le(const uint8_t *input)
{
    return (uint16_t)input[0] | ((uint16_t)input[1] << 8);
}

static uint64_t get_u64_le(const uint8_t *input)
{
    uint64_t value = 0;
    for (size_t index = 0; index < 8; ++index) {
        value |= (uint64_t)input[index] << (index * 8);
    }
    return value;
}

static bool digest_is_equal(const uint8_t left[32], const uint8_t right[32])
{
    uint8_t difference = 0;
    for (size_t index = 0; index < 32; ++index) {
        difference |= left[index] ^ right[index];
    }
    return difference == 0;
}

static nf_v1_result_t sha256(const uint8_t *input, size_t length, uint8_t output[32])
{
    return mbedtls_sha256(input, length, output, 0) == 0 ? NF_V1_OK : NF_V1_CRYPTO_FAILED;
}

static bool radio_is_valid(const nf_v1_radio_rx_s3_t *radio)
{
    if (radio->channel < 1 || radio->channel > 14 || radio->rx_antenna > 1 || radio->stbc > 1) {
        return false;
    }
    if (radio->phy == NF_V1_PHY_NON_HT) {
        return radio->bandwidth == NF_V1_BANDWIDTH_20_MHZ
            && radio->secondary == NF_V1_SECONDARY_NONE && radio->stbc == 0 && radio->mcs == 0;
    }
    if (radio->phy != NF_V1_PHY_HT || radio->rate != 0) {
        return false;
    }
    if (radio->bandwidth == NF_V1_BANDWIDTH_20_MHZ) {
        return radio->secondary == NF_V1_SECONDARY_NONE;
    }
    return radio->bandwidth == NF_V1_BANDWIDTH_40_MHZ
        && (radio->secondary == NF_V1_SECONDARY_ABOVE
            || radio->secondary == NF_V1_SECONDARY_BELOW);
}

static nf_v1_result_t validate_csi(const nf_v1_csi_data_t *csi, uint16_t *sample_count)
{
    if (csi == NULL || sample_count == NULL || csi->blocks == NULL || csi->raw_csi == NULL
        || csi->capture_sequence == 0 || csi->raw_csi_bytes > NF_V1_MAX_RAW_CSI_BYTES
        || csi->block_count < 1 || csi->block_count > 3 || !radio_is_valid(&csi->radio)) {
        return NF_V1_INVALID_BODY;
    }
    bool source_mac_is_zero = true;
    for (size_t index = 0; index < sizeof(csi->source_mac); ++index) {
        source_mac_is_zero &= csi->source_mac[index] == 0;
    }
    if (source_mac_is_zero || (csi->first_invalid_bytes != 0 && csi->first_invalid_bytes != 4)
        || (csi->trailing_invalid_bytes != 0 && csi->trailing_invalid_bytes != 2)
        || csi->raw_csi_bytes < csi->trailing_invalid_bytes) {
        return NF_V1_INVALID_BODY;
    }
    const size_t logical_bytes = csi->raw_csi_bytes - csi->trailing_invalid_bytes;
    if (csi->first_invalid_bytes > logical_bytes || logical_bytes == 0 || logical_bytes % 2 != 0) {
        return NF_V1_INVALID_BODY;
    }
    const uint16_t pairs = (uint16_t)(logical_bytes / 2);
    const uint8_t expected_blocks = csi->radio.phy == NF_V1_PHY_NON_HT
        ? 1
        : (uint8_t)(csi->radio.stbc != 0 ? 3 : 2);
    if (csi->block_count != expected_blocks) {
        return NF_V1_INVALID_BODY;
    }
    uint32_t pair_sum = 0;
    for (size_t index = 0; index < csi->block_count; ++index) {
        const nf_v1_ltf_block_t *block = &csi->blocks[index];
        if (block->kind != index + 1 || block->sample_count == 0
            || block->raw_offset_bytes != pair_sum * 2U) {
            return NF_V1_INVALID_BODY;
        }
        pair_sum += block->sample_count;
        if (pair_sum > pairs) {
            return NF_V1_INVALID_BODY;
        }
    }
    const size_t body_bytes = NF_V1_CSI_FIXED_BODY_BYTES
        + (size_t)csi->block_count * NF_V1_LTF_BLOCK_BYTES + csi->raw_csi_bytes;
    if (pair_sum != pairs || body_bytes > NF_V1_MAX_PLAINTEXT_BYTES) {
        return NF_V1_INVALID_BODY;
    }
    *sample_count = pairs;
    return NF_V1_OK;
}

static nf_v1_result_t validate_capabilities_body(const uint8_t *body, size_t length)
{
    if (length != NF_V1_CAPABILITIES_BODY_BYTES || get_u16_le(&body[32]) != NF_V1_DESCRIPTOR_BYTES) {
        return NF_V1_INVALID_BODY;
    }
    const uint8_t fixed[] = {1, 1, 1, 1, 1, 1, 1, 32, 0x07};
    if (memcmp(&body[34], fixed, sizeof(fixed)) != 0
        || get_u16_le(&body[43]) != NF_V1_MAX_RAW_CSI_BYTES
        || get_u16_le(&body[45]) != NF_V1_MAX_PLAINTEXT_BYTES
        || get_u16_le(&body[47]) < NF_V1_MIN_DATAGRAM_BUDGET_BYTES) {
        return NF_V1_INVALID_BODY;
    }
    uint8_t digest[32];
    nf_v1_result_t result = sha256(&body[34], NF_V1_DESCRIPTOR_BYTES, digest);
    return result == NF_V1_OK && digest_is_equal(body, digest) ? NF_V1_OK : NF_V1_INVALID_BODY;
}

static nf_v1_result_t validate_csi_body(const uint8_t *body, size_t length)
{
    if (length < NF_V1_CSI_FIXED_BODY_BYTES || get_u64_le(&body[32]) == 0) {
        return NF_V1_INVALID_BODY;
    }
    bool source_mac_is_zero = true;
    for (size_t index = 52; index < 58; ++index) {
        source_mac_is_zero &= body[index] == 0;
    }
    nf_v1_radio_rx_s3_t radio = {
        .channel = body[58], .secondary = body[59], .phy = body[60], .bandwidth = body[61],
        .stbc = body[62], .rssi_dbm = (int8_t)body[63], .noise_floor_dbm = (int8_t)body[64],
        .rate = body[65], .mcs = body[66], .rx_antenna = body[67],
    };
    const uint8_t block_count = body[70];
    const uint16_t raw_bytes = get_u16_le(&body[71]);
    const uint16_t pairs = get_u16_le(&body[73]);
    const size_t expected = NF_V1_CSI_FIXED_BODY_BYTES
        + (size_t)block_count * NF_V1_LTF_BLOCK_BYTES + raw_bytes;
    if (source_mac_is_zero || !radio_is_valid(&radio) || block_count < 1 || block_count > 3
        || expected != length
        || raw_bytes > NF_V1_MAX_RAW_CSI_BYTES || (body[68] != 0 && body[68] != 4)
        || (body[69] != 0 && body[69] != 2) || raw_bytes < body[69]) {
        return NF_V1_INVALID_BODY;
    }
    const size_t logical_bytes = raw_bytes - body[69];
    if (logical_bytes == 0 || logical_bytes % 2 != 0 || body[68] > logical_bytes
        || pairs != logical_bytes / 2) {
        return NF_V1_INVALID_BODY;
    }
    const uint8_t expected_blocks = radio.phy == NF_V1_PHY_NON_HT ? 1 : (radio.stbc != 0 ? 3 : 2);
    if (block_count != expected_blocks) {
        return NF_V1_INVALID_BODY;
    }
    uint32_t pair_sum = 0;
    for (size_t index = 0; index < block_count; ++index) {
        const size_t offset = NF_V1_CSI_FIXED_BODY_BYTES + index * NF_V1_LTF_BLOCK_BYTES;
        const uint16_t block_pairs = get_u16_le(&body[offset + 2]);
        if (body[offset] != index + 1 || body[offset + 1] != 0 || block_pairs == 0
            || get_u16_le(&body[offset + 4]) != pair_sum * 2U) {
            return NF_V1_INVALID_BODY;
        }
        pair_sum += block_pairs;
    }
    return pair_sum == pairs ? NF_V1_OK : NF_V1_INVALID_BODY;
}

static nf_v1_result_t validate_body(nf_v1_message_kind_t kind, const uint8_t *body, size_t length)
{
    if (body == NULL || length > NF_V1_MAX_PLAINTEXT_BYTES) {
        return NF_V1_INVALID_BODY;
    }
    switch (kind) {
    case NF_V1_CAPABILITIES:
        return validate_capabilities_body(body, length);
    case NF_V1_CSI_DATA:
        return validate_csi_body(body, length);
    case NF_V1_HEALTH:
        return length == NF_V1_HEALTH_BODY_BYTES ? NF_V1_OK : NF_V1_INVALID_BODY;
    default:
        return NF_V1_INVALID_ARGUMENT;
    }
}

nf_v1_result_t nf_v1_encode_capabilities(
    const nf_v1_capability_descriptor_t *descriptor,
    uint8_t *body,
    size_t body_capacity,
    size_t *body_length,
    uint8_t capability_digest[32])
{
    if (descriptor == NULL || body == NULL || body_length == NULL || capability_digest == NULL) {
        return NF_V1_INVALID_ARGUMENT;
    }
    if (descriptor->datagram_budget_bytes < NF_V1_MIN_DATAGRAM_BUDGET_BYTES) {
        return NF_V1_BUDGET_EXCEEDED;
    }
    if (body_capacity < NF_V1_CAPABILITIES_BODY_BYTES) {
        return NF_V1_BUFFER_TOO_SMALL;
    }
    uint8_t *descriptor_bytes = &body[34];
    const uint8_t fixed[] = {1, 1, 1, 1, 1, 1, 1, 32, 0x07};
    memcpy(descriptor_bytes, fixed, sizeof(fixed));
    put_u16_le(&descriptor_bytes[9], NF_V1_MAX_RAW_CSI_BYTES);
    put_u16_le(&descriptor_bytes[11], NF_V1_MAX_PLAINTEXT_BYTES);
    put_u16_le(&descriptor_bytes[13], descriptor->datagram_budget_bytes);
    memcpy(&descriptor_bytes[15], descriptor->firmware_build_digest, 32);
    memcpy(&descriptor_bytes[47], descriptor->idf_wifi_abi_digest, 32);
    nf_v1_result_t result = sha256(descriptor_bytes, NF_V1_DESCRIPTOR_BYTES, capability_digest);
    if (result != NF_V1_OK) {
        return result;
    }
    memcpy(body, capability_digest, 32);
    put_u16_le(&body[32], NF_V1_DESCRIPTOR_BYTES);
    *body_length = NF_V1_CAPABILITIES_BODY_BYTES;
    return NF_V1_OK;
}

nf_v1_result_t nf_v1_encode_csi_data(
    const nf_v1_csi_data_t *csi,
    uint8_t *body,
    size_t body_capacity,
    size_t *body_length)
{
    if (body == NULL || body_length == NULL) {
        return NF_V1_INVALID_ARGUMENT;
    }
    uint16_t pairs;
    nf_v1_result_t result = validate_csi(csi, &pairs);
    if (result != NF_V1_OK) {
        return result;
    }
    const size_t length = NF_V1_CSI_FIXED_BODY_BYTES
        + (size_t)csi->block_count * NF_V1_LTF_BLOCK_BYTES + csi->raw_csi_bytes;
    if (body_capacity < length) {
        return NF_V1_BUFFER_TOO_SMALL;
    }
    memcpy(body, csi->capability_digest, 32);
    put_u64_le(&body[32], csi->capture_sequence);
    put_u32_le(&body[40], csi->driver_rx_timestamp_us);
    put_u64_le(&body[44], csi->callback_tick_us);
    memcpy(&body[52], csi->source_mac, 6);
    body[58] = csi->radio.channel;
    body[59] = csi->radio.secondary;
    body[60] = csi->radio.phy;
    body[61] = csi->radio.bandwidth;
    body[62] = csi->radio.stbc;
    body[63] = (uint8_t)csi->radio.rssi_dbm;
    body[64] = (uint8_t)csi->radio.noise_floor_dbm;
    body[65] = csi->radio.rate;
    body[66] = csi->radio.mcs;
    body[67] = csi->radio.rx_antenna;
    body[68] = csi->first_invalid_bytes;
    body[69] = csi->trailing_invalid_bytes;
    body[70] = csi->block_count;
    put_u16_le(&body[71], csi->raw_csi_bytes);
    put_u16_le(&body[73], pairs);
    size_t cursor = NF_V1_CSI_FIXED_BODY_BYTES;
    for (size_t index = 0; index < csi->block_count; ++index) {
        body[cursor] = csi->blocks[index].kind;
        body[cursor + 1] = 0;
        put_u16_le(&body[cursor + 2], csi->blocks[index].sample_count);
        put_u16_le(&body[cursor + 4], csi->blocks[index].raw_offset_bytes);
        cursor += NF_V1_LTF_BLOCK_BYTES;
    }
    memcpy(&body[cursor], csi->raw_csi, csi->raw_csi_bytes);
    *body_length = length;
    return NF_V1_OK;
}

nf_v1_result_t nf_v1_encode_health(
    const nf_v1_health_t *health,
    uint8_t *body,
    size_t body_capacity,
    size_t *body_length)
{
    if (health == NULL || body == NULL || body_length == NULL) {
        return NF_V1_INVALID_ARGUMENT;
    }
    if (body_capacity < NF_V1_HEALTH_BODY_BYTES) {
        return NF_V1_BUFFER_TOO_SMALL;
    }
    memcpy(body, health->capability_digest, 32);
    size_t cursor = 32;
    const uint64_t counters[] = {
        health->callback_tick_us, health->capture_seen, health->queue_drop_no_slot,
        health->queue_drop_full, health->oversize_reject, health->encode_reject,
        health->send_failure,
    };
    for (size_t index = 0; index < sizeof(counters) / sizeof(counters[0]); ++index) {
        put_u64_le(&body[cursor], counters[index]);
        cursor += 8;
    }
    put_u16_le(&body[cursor], health->pool_high_water_slots);
    cursor += 2;
    put_u32_le(&body[cursor], health->callback_max_us);
    cursor += 4;
    put_u32_le(&body[cursor], health->encoder_max_us);
    *body_length = NF_V1_HEALTH_BODY_BYTES;
    return NF_V1_OK;
}

nf_v1_result_t nf_v1_seal(
    const nf_v1_envelope_t *envelope,
    nf_v1_message_kind_t kind,
    const uint8_t key[32],
    const uint8_t *body,
    size_t body_length,
    uint8_t *datagram,
    size_t datagram_capacity,
    size_t *datagram_length)
{
    if (envelope == NULL || key == NULL || datagram == NULL || datagram_length == NULL) {
        return NF_V1_INVALID_ARGUMENT;
    }
    if (envelope->key_epoch == 0 || envelope->boot_generation == 0
        || envelope->message_sequence == 0) {
        return NF_V1_INVALID_SEQUENCE;
    }
    nf_v1_result_t result = validate_body(kind, body, body_length);
    if (result != NF_V1_OK) {
        return result;
    }
    const size_t total_bytes = NF_V1_HEADER_BYTES + body_length + NF_V1_TAG_BYTES;
    if (envelope->datagram_budget_bytes < total_bytes) {
        return NF_V1_BUDGET_EXCEEDED;
    }
    if (datagram_capacity < total_bytes) {
        return NF_V1_BUFFER_TOO_SMALL;
    }
    memset(datagram, 0, NF_V1_HEADER_BYTES);
    datagram[0] = 1;
    datagram[1] = (uint8_t)kind;
    put_u16_le(&datagram[2], NF_V1_HEADER_BYTES);
    put_u64_le(&datagram[4], envelope->device_id);
    put_u16_le(&datagram[12], envelope->key_epoch);
    put_u32_le(&datagram[16], envelope->boot_generation);
    put_u64_le(&datagram[20], envelope->message_sequence);
    put_u16_le(&datagram[28], (uint16_t)body_length);
    uint8_t nonce[12];
    put_u32_le(nonce, envelope->boot_generation);
    put_u64_le(&nonce[4], envelope->message_sequence);
    mbedtls_gcm_context context;
    mbedtls_gcm_init(&context);
    int crypto_result = mbedtls_gcm_setkey(&context, MBEDTLS_CIPHER_ID_AES, key, 256);
    if (crypto_result == 0) {
        crypto_result = mbedtls_gcm_crypt_and_tag(
            &context,
            MBEDTLS_GCM_ENCRYPT,
            body_length,
            nonce,
            sizeof(nonce),
            datagram,
            NF_V1_HEADER_BYTES,
            body,
            &datagram[NF_V1_HEADER_BYTES],
            NF_V1_TAG_BYTES,
            &datagram[NF_V1_HEADER_BYTES + body_length]);
    }
    mbedtls_gcm_free(&context);
    if (crypto_result != 0) {
        return NF_V1_CRYPTO_FAILED;
    }
    *datagram_length = total_bytes;
    return NF_V1_OK;
}
