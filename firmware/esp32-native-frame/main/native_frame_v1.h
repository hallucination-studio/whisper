#ifndef NATIVE_FRAME_V1_H
#define NATIVE_FRAME_V1_H

#include <stddef.h>
#include <stdint.h>

#define NF_V1_HEADER_BYTES 32U
#define NF_V1_TAG_BYTES 16U
#define NF_V1_DESCRIPTOR_BYTES 79U
#define NF_V1_CAPABILITIES_BODY_BYTES 113U
#define NF_V1_HEALTH_BODY_BYTES 98U
#define NF_V1_MAX_RAW_CSI_BYTES 612U
#define NF_V1_MAX_PLAINTEXT_BYTES 705U
#define NF_V1_MIN_DATAGRAM_BUDGET_BYTES 753U

typedef enum {
    NF_V1_OK = 0,
    NF_V1_INVALID_ARGUMENT,
    NF_V1_INVALID_SEQUENCE,
    NF_V1_INVALID_BODY,
    NF_V1_BUFFER_TOO_SMALL,
    NF_V1_BUDGET_EXCEEDED,
    NF_V1_CRYPTO_FAILED,
} nf_v1_result_t;

typedef enum {
    NF_V1_CAPABILITIES = 1,
    NF_V1_CSI_DATA = 2,
    NF_V1_HEALTH = 3,
} nf_v1_message_kind_t;

typedef enum {
    NF_V1_SECONDARY_NONE = 0,
    NF_V1_SECONDARY_ABOVE = 1,
    NF_V1_SECONDARY_BELOW = 2,
} nf_v1_secondary_t;

typedef enum {
    NF_V1_PHY_NON_HT = 1,
    NF_V1_PHY_HT = 2,
} nf_v1_phy_t;

typedef enum {
    NF_V1_BANDWIDTH_20_MHZ = 1,
    NF_V1_BANDWIDTH_40_MHZ = 2,
} nf_v1_bandwidth_t;

typedef enum {
    NF_V1_LTF_LLTF = 1,
    NF_V1_LTF_HTLTF = 2,
    NF_V1_LTF_STBC_HTLTF = 3,
} nf_v1_ltf_kind_t;

typedef struct {
    uint8_t firmware_build_digest[32];
    uint8_t idf_wifi_abi_digest[32];
    uint16_t datagram_budget_bytes;
} nf_v1_capability_descriptor_t;

typedef struct {
    uint8_t kind;
    uint16_t sample_count;
    uint16_t raw_offset_bytes;
} nf_v1_ltf_block_t;

typedef struct {
    uint8_t channel;
    uint8_t secondary;
    uint8_t phy;
    uint8_t bandwidth;
    uint8_t stbc;
    int8_t rssi_dbm;
    int8_t noise_floor_dbm;
    uint8_t rate;
    uint8_t mcs;
    uint8_t rx_antenna;
} nf_v1_radio_rx_s3_t;

typedef struct {
    uint8_t capability_digest[32];
    uint64_t capture_sequence;
    uint32_t driver_rx_timestamp_us;
    uint64_t callback_tick_us;
    uint8_t source_mac[6];
    nf_v1_radio_rx_s3_t radio;
    uint8_t first_invalid_bytes;
    uint8_t trailing_invalid_bytes;
    const nf_v1_ltf_block_t *blocks;
    uint8_t block_count;
    const uint8_t *raw_csi;
    uint16_t raw_csi_bytes;
} nf_v1_csi_data_t;

typedef struct {
    uint8_t capability_digest[32];
    uint64_t callback_tick_us;
    uint64_t capture_seen;
    uint64_t queue_drop_no_slot;
    uint64_t queue_drop_full;
    uint64_t oversize_reject;
    uint64_t encode_reject;
    uint64_t send_failure;
    uint16_t pool_high_water_slots;
    uint32_t callback_max_us;
    uint32_t encoder_max_us;
} nf_v1_health_t;

typedef struct {
    uint64_t device_id;
    uint16_t key_epoch;
    uint32_t boot_generation;
    uint64_t message_sequence;
    uint16_t datagram_budget_bytes;
} nf_v1_envelope_t;

nf_v1_result_t nf_v1_encode_capabilities(
    const nf_v1_capability_descriptor_t *descriptor,
    uint8_t *body,
    size_t body_capacity,
    size_t *body_length,
    uint8_t capability_digest[32]);

nf_v1_result_t nf_v1_encode_csi_data(
    const nf_v1_csi_data_t *csi,
    uint8_t *body,
    size_t body_capacity,
    size_t *body_length);

nf_v1_result_t nf_v1_encode_health(
    const nf_v1_health_t *health,
    uint8_t *body,
    size_t body_capacity,
    size_t *body_length);

nf_v1_result_t nf_v1_seal(
    const nf_v1_envelope_t *envelope,
    nf_v1_message_kind_t kind,
    const uint8_t key[32],
    const uint8_t *body,
    size_t body_length,
    uint8_t *datagram,
    size_t datagram_capacity,
    size_t *datagram_length);

#endif
