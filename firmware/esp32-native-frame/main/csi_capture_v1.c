#include "csi_capture_v1.h"

#include <string.h>

#include "esp_timer.h"

#ifdef CSI_CAPTURE_V1_TEST
#include <assert.h>
#define CHECK_STATE(condition) assert(condition)
#else
#define CHECK_STATE(condition) ((void)0)
#endif

enum {
    SLOT_FREE,
    SLOT_CAPTURING,
    SLOT_READY,
    SLOT_ENCODING,
};

static void increment(atomic_uint_least32_t *counter)
{
    uint_least32_t value = atomic_load_explicit(counter, memory_order_relaxed);
    while (value != UINT32_MAX
        && !atomic_compare_exchange_weak_explicit(counter, &value, value + 1,
            memory_order_relaxed, memory_order_relaxed)) {
    }
}

static void record_pool_high_water(csi_capture_v1_t *capture)
{
    uint_least16_t occupied = CSI_CAPTURE_V1_SLOT_COUNT
        - uxQueueMessagesWaiting(capture->free_queue);
    uint_least16_t current = atomic_load_explicit(
        &capture->counters.pool_high_water_slots, memory_order_relaxed);
    while (current < occupied
        && !atomic_compare_exchange_weak_explicit(&capture->counters.pool_high_water_slots,
            &current, occupied, memory_order_relaxed, memory_order_relaxed)) {
    }
}

static bool radio_is_supported(const csi_capture_v1_t *capture, const wifi_csi_info_t *info)
{
    if (info->rx_ctrl.channel != capture->config.channel
        || info->rx_ctrl.channel < 1 || info->rx_ctrl.channel > 14
        || info->rx_ctrl.sig_mode > 1 || info->rx_ctrl.secondary_channel > 2
        || info->rx_ctrl.stbc > 1 || info->rx_ctrl.rx_state != 0) {
        return false;
    }
    if (info->rx_ctrl.sig_mode == 0) {
        return info->rx_ctrl.cwb == 0
            && info->rx_ctrl.secondary_channel == 0 && info->rx_ctrl.stbc == 0;
    }
    return info->rx_ctrl.cwb == 0
        ? info->rx_ctrl.secondary_channel == 0
        : info->rx_ctrl.secondary_channel == 1 || info->rx_ctrl.secondary_channel == 2;
}

bool csi_capture_v1_init(csi_capture_v1_t *capture, const csi_capture_v1_config_t *config)
{
    if (capture == NULL || config == NULL || config->channel < 1 || config->channel > 14) {
        return false;
    }
    memset(capture, 0, sizeof(*capture));
    capture->config = *config;
    capture->next_capture_sequence = 1;
    capture->free_queue = xQueueCreateStatic(CSI_CAPTURE_V1_SLOT_COUNT, sizeof(uint8_t),
        capture->free_queue_storage, &capture->free_queue_state);
    capture->ready_queue = xQueueCreateStatic(CSI_CAPTURE_V1_READY_COUNT, sizeof(uint8_t),
        capture->ready_queue_storage, &capture->ready_queue_state);
    if (capture->free_queue == NULL || capture->ready_queue == NULL) {
        return false;
    }
    for (uint8_t index = 0; index < CSI_CAPTURE_V1_SLOT_COUNT; ++index) {
        if (xQueueSend(capture->free_queue, &index, 0) != pdTRUE) {
            return false;
        }
    }
    return true;
}

void csi_capture_v1_callback(void *context, wifi_csi_info_t *info)
{
    csi_capture_v1_t *capture = context;
    if (capture == NULL || info == NULL || info->buf == NULL) {
        return;
    }
    if (info->len == 0 || info->len > NF_V1_MAX_RAW_CSI_BYTES) {
        increment(&capture->counters.oversize_reject);
        return;
    }
    if (memcmp(info->mac, capture->config.station_bssid, sizeof(info->mac)) != 0
        || memcmp(info->dmac, capture->config.station_mac, sizeof(info->dmac)) != 0) {
        increment(&capture->counters.encode_reject);
        return;
    }
    if (!radio_is_supported(capture, info) || capture->next_capture_sequence == 0) {
        increment(&capture->counters.encode_reject);
        return;
    }

    const uint64_t capture_sequence = capture->next_capture_sequence;
    capture->next_capture_sequence = capture_sequence == UINT64_MAX ? 0 : capture_sequence + 1;
    const uint64_t callback_tick_us = (uint64_t)esp_timer_get_time();
    increment(&capture->counters.capture_seen);

    uint8_t slot_index;
    if (xQueueReceive(capture->free_queue, &slot_index, 0) != pdTRUE) {
        increment(&capture->counters.queue_drop_no_slot);
        return;
    }
    record_pool_high_water(capture);
    CHECK_STATE(capture->slot_states[slot_index] == SLOT_FREE);
    if (capture->slot_states[slot_index] != SLOT_FREE) {
        return;
    }
    capture->slot_states[slot_index] = SLOT_CAPTURING;
    csi_capture_v1_slot_t *slot = &capture->slots[slot_index];
    slot->capture_sequence = capture_sequence;
    slot->callback_tick_us = callback_tick_us;
    slot->driver_rx_timestamp_us = info->rx_ctrl.timestamp;
    memcpy(slot->source_mac, info->mac, sizeof(slot->source_mac));
    slot->radio = (nf_v1_radio_rx_s3_t) {
        .channel = info->rx_ctrl.channel,
        .secondary = info->rx_ctrl.secondary_channel,
        .phy = info->rx_ctrl.sig_mode == 0 ? NF_V1_PHY_NON_HT : NF_V1_PHY_HT,
        .bandwidth = info->rx_ctrl.cwb == 0
            ? NF_V1_BANDWIDTH_20_MHZ : NF_V1_BANDWIDTH_40_MHZ,
        .stbc = info->rx_ctrl.stbc,
        .rssi_dbm = info->rx_ctrl.rssi,
        .noise_floor_dbm = info->rx_ctrl.noise_floor,
        .rate = info->rx_ctrl.sig_mode == 0 ? info->rx_ctrl.rate : 0,
        .mcs = info->rx_ctrl.sig_mode == 0 ? 0 : info->rx_ctrl.mcs,
        .rx_antenna = info->rx_ctrl.ant,
    };
    slot->first_invalid_bytes = info->first_word_invalid ? 4 : 0;
    slot->raw_csi_bytes = info->len;
    memcpy(slot->raw_csi, info->buf, info->len);
    capture->slot_states[slot_index] = SLOT_READY;
    if (xQueueSend(capture->ready_queue, &slot_index, 0) != pdTRUE) {
        increment(&capture->counters.queue_drop_full);
        capture->slot_states[slot_index] = SLOT_FREE;
        BaseType_t returned = xQueueSend(capture->free_queue, &slot_index, 0);
        CHECK_STATE(returned == pdTRUE);
        (void)returned;
    }
}

const csi_capture_v1_slot_t *csi_capture_v1_take_ready(
    csi_capture_v1_t *capture, uint8_t *slot_index)
{
    if (capture == NULL || slot_index == NULL
        || xQueueReceive(capture->ready_queue, slot_index, 0) != pdTRUE) {
        return NULL;
    }
    CHECK_STATE(*slot_index < CSI_CAPTURE_V1_SLOT_COUNT
        && capture->slot_states[*slot_index] == SLOT_READY);
    if (*slot_index >= CSI_CAPTURE_V1_SLOT_COUNT
        || capture->slot_states[*slot_index] != SLOT_READY) {
        return NULL;
    }
    capture->slot_states[*slot_index] = SLOT_ENCODING;
    return &capture->slots[*slot_index];
}

bool csi_capture_v1_release(csi_capture_v1_t *capture, uint8_t slot_index)
{
    if (capture == NULL || slot_index >= CSI_CAPTURE_V1_SLOT_COUNT
        || capture->slot_states[slot_index] != SLOT_ENCODING) {
        return false;
    }
    capture->slot_states[slot_index] = SLOT_FREE;
    if (xQueueSend(capture->free_queue, &slot_index, 0) == pdTRUE) {
        return true;
    }
    capture->slot_states[slot_index] = SLOT_ENCODING;
    return false;
}

void csi_capture_v1_record_encode_reject(csi_capture_v1_t *capture)
{
    if (capture != NULL) {
        increment(&capture->counters.encode_reject);
    }
}

void csi_capture_v1_drain_counters(
    csi_capture_v1_t *capture, csi_capture_v1_counter_delta_t *delta)
{
    if (capture == NULL || delta == NULL) {
        return;
    }
    delta->capture_seen = atomic_exchange_explicit(
        &capture->counters.capture_seen, 0, memory_order_relaxed);
    delta->queue_drop_no_slot = atomic_exchange_explicit(
        &capture->counters.queue_drop_no_slot, 0, memory_order_relaxed);
    delta->queue_drop_full = atomic_exchange_explicit(
        &capture->counters.queue_drop_full, 0, memory_order_relaxed);
    delta->oversize_reject = atomic_exchange_explicit(
        &capture->counters.oversize_reject, 0, memory_order_relaxed);
    delta->encode_reject = atomic_exchange_explicit(
        &capture->counters.encode_reject, 0, memory_order_relaxed);
}

uint16_t csi_capture_v1_pool_high_water_slots(const csi_capture_v1_t *capture)
{
    return capture == NULL ? 0 : atomic_load_explicit(
        &capture->counters.pool_high_water_slots, memory_order_relaxed);
}
