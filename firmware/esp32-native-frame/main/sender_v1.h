#ifndef SENDER_V1_H
#define SENDER_V1_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "csi_capture_v1.h"
#include "lwip/sockets.h"
#include "native_frame_v1.h"

typedef enum {
    SENDER_V1_OK = 0,
    SENDER_V1_NO_CSI,
    SENDER_V1_CSI_DROPPED,
    SENDER_V1_REJECTED,
    SENDER_V1_SEQUENCE_EXHAUSTED,
    SENDER_V1_SEAL_FAILED,
    SENDER_V1_SEND_FAILED,
} sender_v1_result_t;

typedef struct {
    int socket_fd;
    struct sockaddr_storage collector;
    socklen_t collector_length;
    nf_v1_envelope_t envelope;
    uint8_t key[32];
    uint8_t capability_digest[32];
    uint64_t next_message_sequence;
    nf_v1_health_t health;
    uint8_t body[NF_V1_MAX_PLAINTEXT_BYTES];
    uint8_t datagram[NF_V1_HEADER_BYTES + NF_V1_MAX_PLAINTEXT_BYTES + NF_V1_TAG_BYTES];
    size_t datagram_length;
} sender_v1_t;

bool sender_v1_init(sender_v1_t *sender, int socket_fd, const struct sockaddr *collector,
    socklen_t collector_length, const nf_v1_envelope_t *envelope, const uint8_t key[32]);
sender_v1_result_t sender_v1_send_capabilities(
    sender_v1_t *sender, const nf_v1_capability_descriptor_t *descriptor);
sender_v1_result_t sender_v1_send_next_csi(sender_v1_t *sender, csi_capture_v1_t *capture);
sender_v1_result_t sender_v1_send_health(sender_v1_t *sender, csi_capture_v1_t *capture,
    uint64_t callback_tick_us, uint16_t pool_high_water_slots, uint32_t callback_max_us,
    uint32_t encoder_max_us);

#endif
