#ifndef CSI_CAPTURE_V1_H
#define CSI_CAPTURE_V1_H

#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>

#include "esp_wifi_types.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "native_frame_v1.h"

/* Bootstrap: one encoding plus one queued slot; increase only after hardware budget/soak. */
#define CSI_CAPTURE_V1_SLOT_COUNT 2
#define CSI_CAPTURE_V1_READY_COUNT 1

typedef struct {
    uint64_t capture_sequence;
    uint64_t callback_tick_us;
    uint32_t driver_rx_timestamp_us;
    uint8_t source_mac[6];
    nf_v1_radio_rx_s3_t radio;
    uint8_t first_invalid_bytes;
    uint16_t raw_csi_bytes;
    uint8_t raw_csi[NF_V1_MAX_RAW_CSI_BYTES];
} csi_capture_v1_slot_t;

typedef struct {
    atomic_uint_least32_t capture_seen;
    atomic_uint_least32_t queue_drop_no_slot;
    atomic_uint_least32_t queue_drop_full;
    atomic_uint_least32_t oversize_reject;
    atomic_uint_least32_t encode_reject;
    atomic_uint_least16_t pool_high_water_slots;
} csi_capture_v1_counters_t;

typedef struct {
    uint32_t capture_seen;
    uint32_t queue_drop_no_slot;
    uint32_t queue_drop_full;
    uint32_t oversize_reject;
    uint32_t encode_reject;
} csi_capture_v1_counter_delta_t;

typedef struct {
    uint8_t station_bssid[6];
    uint8_t station_mac[6];
    uint8_t channel;
} csi_capture_v1_config_t;

typedef struct {
    csi_capture_v1_config_t config;
    csi_capture_v1_counters_t counters;
    uint64_t next_capture_sequence;
    csi_capture_v1_slot_t slots[CSI_CAPTURE_V1_SLOT_COUNT];
    uint8_t slot_states[CSI_CAPTURE_V1_SLOT_COUNT];
    QueueHandle_t free_queue;
    QueueHandle_t ready_queue;
    StaticQueue_t free_queue_state;
    StaticQueue_t ready_queue_state;
    uint8_t free_queue_storage[CSI_CAPTURE_V1_SLOT_COUNT];
    uint8_t ready_queue_storage[CSI_CAPTURE_V1_READY_COUNT];
} csi_capture_v1_t;

bool csi_capture_v1_init(csi_capture_v1_t *capture, const csi_capture_v1_config_t *config);
void csi_capture_v1_callback(void *context, wifi_csi_info_t *info);
const csi_capture_v1_slot_t *csi_capture_v1_take_ready(
    csi_capture_v1_t *capture, uint8_t *slot_index);
bool csi_capture_v1_release(csi_capture_v1_t *capture, uint8_t slot_index);
void csi_capture_v1_record_encode_reject(csi_capture_v1_t *capture);
void csi_capture_v1_drain_counters(
    csi_capture_v1_t *capture, csi_capture_v1_counter_delta_t *delta);
uint16_t csi_capture_v1_pool_high_water_slots(const csi_capture_v1_t *capture);

#endif
