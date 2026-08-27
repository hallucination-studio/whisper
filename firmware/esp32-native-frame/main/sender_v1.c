#include "sender_v1.h"

#include <limits.h>
#include <string.h>

static uint64_t add_saturating(uint64_t total, uint64_t delta)
{
    return UINT64_MAX - total < delta ? UINT64_MAX : total + delta;
}

static sender_v1_result_t seal_and_send(sender_v1_t *sender, nf_v1_message_kind_t kind,
    const uint8_t *body, size_t body_length)
{
    if (sender->next_message_sequence == 0) {
        return SENDER_V1_SEQUENCE_EXHAUSTED;
    }
    sender->envelope.message_sequence = sender->next_message_sequence;
    sender->next_message_sequence = sender->next_message_sequence == UINT64_MAX
        ? 0 : sender->next_message_sequence + 1;
    if (nf_v1_seal(&sender->envelope, kind, sender->key, body, body_length,
            sender->datagram, sizeof(sender->datagram), &sender->datagram_length) != NF_V1_OK) {
        return SENDER_V1_SEAL_FAILED;
    }
    const ssize_t sent = sendto(sender->socket_fd, sender->datagram, sender->datagram_length, 0,
        (const struct sockaddr *)&sender->collector, sender->collector_length);
    if (sent < 0 || (size_t)sent != sender->datagram_length) {
        sender->health.send_failure = add_saturating(sender->health.send_failure, 1);
        return SENDER_V1_SEND_FAILED;
    }
    return SENDER_V1_OK;
}

static bool csi_layout(const csi_capture_v1_slot_t *slot, nf_v1_ltf_block_t blocks[3],
    uint8_t *block_count)
{
    const uint16_t *samples = NULL;
    static const uint16_t NON_HT_20[] = {64};
    static const uint16_t HT_20[] = {64, 64};
    static const uint16_t HT_20_STBC[] = {64, 64, 64};
    static const uint16_t HT_40[] = {64, 128};
    static const uint16_t HT_40_STBC[] = {64, 121, 121};

    if (slot->radio.phy == NF_V1_PHY_NON_HT && slot->radio.bandwidth == NF_V1_BANDWIDTH_20_MHZ
        && slot->radio.secondary == NF_V1_SECONDARY_NONE && slot->radio.stbc == 0
        && slot->raw_csi_bytes == 128) {
        samples = NON_HT_20;
        *block_count = 1;
    } else if (slot->radio.phy == NF_V1_PHY_HT
        && slot->radio.bandwidth == NF_V1_BANDWIDTH_20_MHZ
        && slot->radio.secondary == NF_V1_SECONDARY_NONE && slot->radio.stbc == 0
        && slot->raw_csi_bytes == 256) {
        samples = HT_20;
        *block_count = 2;
    } else if (slot->radio.phy == NF_V1_PHY_HT
        && slot->radio.bandwidth == NF_V1_BANDWIDTH_20_MHZ
        && slot->radio.secondary == NF_V1_SECONDARY_NONE && slot->radio.stbc == 1
        && slot->raw_csi_bytes == 384) {
        samples = HT_20_STBC;
        *block_count = 3;
    } else if (slot->radio.phy == NF_V1_PHY_HT
        && slot->radio.bandwidth == NF_V1_BANDWIDTH_40_MHZ
        && (slot->radio.secondary == NF_V1_SECONDARY_ABOVE
            || slot->radio.secondary == NF_V1_SECONDARY_BELOW)
        && slot->radio.stbc == 0 && slot->raw_csi_bytes == 384) {
        samples = HT_40;
        *block_count = 2;
    } else if (slot->radio.phy == NF_V1_PHY_HT
        && slot->radio.bandwidth == NF_V1_BANDWIDTH_40_MHZ
        && (slot->radio.secondary == NF_V1_SECONDARY_ABOVE
            || slot->radio.secondary == NF_V1_SECONDARY_BELOW)
        && slot->radio.stbc == 1 && slot->raw_csi_bytes == 612) {
        samples = HT_40_STBC;
        *block_count = 3;
    } else {
        return false;
    }

    uint16_t offset = 0;
    for (uint8_t index = 0; index < *block_count; ++index) {
        blocks[index] = (nf_v1_ltf_block_t) {
            .kind = (uint8_t)(NF_V1_LTF_LLTF + index),
            .sample_count = samples[index],
            .raw_offset_bytes = offset,
        };
        offset = (uint16_t)(offset + samples[index] * 2U);
    }
    return true;
}

bool sender_v1_init(sender_v1_t *sender, int socket_fd, const struct sockaddr *collector,
    socklen_t collector_length, const nf_v1_envelope_t *envelope, const uint8_t key[32])
{
    if (sender == NULL || collector == NULL || envelope == NULL || key == NULL
        || envelope->key_epoch == 0 || envelope->boot_generation == 0
        || envelope->message_sequence == 0 || collector_length < sizeof(sa_family_t)
        || (collector->sa_family == AF_INET && collector_length != sizeof(struct sockaddr_in))
        || (collector->sa_family == AF_INET6 && collector_length != sizeof(struct sockaddr_in6))
        || (collector->sa_family != AF_INET && collector->sa_family != AF_INET6)) {
        return false;
    }
    memset(sender, 0, sizeof(*sender));
    sender->socket_fd = socket_fd;
    memcpy(&sender->collector, collector, collector_length);
    sender->collector_length = collector_length;
    sender->envelope = *envelope;
    sender->next_message_sequence = envelope->message_sequence;
    memcpy(sender->key, key, sizeof(sender->key));
    return true;
}

sender_v1_result_t sender_v1_send_capabilities(
    sender_v1_t *sender, const nf_v1_capability_descriptor_t *descriptor)
{
    if (sender == NULL) {
        return SENDER_V1_REJECTED;
    }
    size_t body_length = 0;
    if (nf_v1_encode_capabilities(descriptor, sender->body, sizeof(sender->body), &body_length,
            sender->capability_digest) != NF_V1_OK) {
        return SENDER_V1_REJECTED;
    }
    memcpy(sender->health.capability_digest, sender->capability_digest, 32);
    return seal_and_send(sender, NF_V1_CAPABILITIES, sender->body, body_length);
}

sender_v1_result_t sender_v1_send_next_csi(sender_v1_t *sender, csi_capture_v1_t *capture)
{
    if (sender == NULL || capture == NULL) {
        return SENDER_V1_REJECTED;
    }
    uint8_t slot_index;
    const csi_capture_v1_slot_t *slot = csi_capture_v1_take_ready(capture, &slot_index);
    if (slot == NULL) {
        return SENDER_V1_NO_CSI;
    }
    nf_v1_ltf_block_t blocks[3];
    uint8_t block_count = 0;
    sender_v1_result_t result = SENDER_V1_CSI_DROPPED;
    if (!csi_layout(slot, blocks, &block_count)) {
        csi_capture_v1_record_encode_reject(capture);
    } else {
        nf_v1_csi_data_t csi = {
            .capture_sequence = slot->capture_sequence,
            .driver_rx_timestamp_us = slot->driver_rx_timestamp_us,
            .callback_tick_us = slot->callback_tick_us,
            .radio = slot->radio,
            .first_invalid_bytes = slot->first_invalid_bytes,
            .blocks = blocks,
            .block_count = block_count,
            .raw_csi = slot->raw_csi,
            .raw_csi_bytes = slot->raw_csi_bytes,
        };
        memcpy(csi.capability_digest, sender->capability_digest, 32);
        memcpy(csi.source_mac, slot->source_mac, sizeof(csi.source_mac));
        size_t body_length = 0;
        if (nf_v1_encode_csi_data(&csi, sender->body, sizeof(sender->body), &body_length)
            != NF_V1_OK) {
            csi_capture_v1_record_encode_reject(capture);
        } else {
            result = seal_and_send(sender, NF_V1_CSI_DATA, sender->body, body_length);
        }
    }
    if (!csi_capture_v1_release(capture, slot_index)) {
        return SENDER_V1_REJECTED;
    }
    return result;
}

sender_v1_result_t sender_v1_send_health(sender_v1_t *sender, csi_capture_v1_t *capture,
    uint64_t callback_tick_us, uint16_t pool_high_water_slots, uint32_t callback_max_us,
    uint32_t encoder_max_us)
{
    if (sender == NULL || capture == NULL) {
        return SENDER_V1_REJECTED;
    }
    csi_capture_v1_counter_delta_t delta;
    csi_capture_v1_drain_counters(capture, &delta);
    sender->health.callback_tick_us = callback_tick_us;
    sender->health.capture_seen = add_saturating(sender->health.capture_seen, delta.capture_seen);
    sender->health.queue_drop_no_slot = add_saturating(
        sender->health.queue_drop_no_slot, delta.queue_drop_no_slot);
    sender->health.queue_drop_full = add_saturating(
        sender->health.queue_drop_full, delta.queue_drop_full);
    sender->health.oversize_reject = add_saturating(
        sender->health.oversize_reject, delta.oversize_reject);
    sender->health.encode_reject = add_saturating(
        sender->health.encode_reject, delta.encode_reject);
    sender->health.pool_high_water_slots = pool_high_water_slots;
    sender->health.callback_max_us = callback_max_us;
    sender->health.encoder_max_us = encoder_max_us;
    size_t body_length = 0;
    if (nf_v1_encode_health(&sender->health, sender->body, sizeof(sender->body), &body_length)
        != NF_V1_OK) {
        return SENDER_V1_REJECTED;
    }
    return seal_and_send(sender, NF_V1_HEALTH, sender->body, body_length);
}
