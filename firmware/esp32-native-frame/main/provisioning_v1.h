#ifndef PROVISIONING_V1_H
#define PROVISIONING_V1_H

#include <stdint.h>

#include "esp_err.h"

#define PROVISIONING_V1_SCHEMA UINT16_C(1)
#define PROVISIONING_V1_AES_KEY_BYTES 32
#define PROVISIONING_V1_CAPABILITY_DIGEST_BYTES 32
#define PROVISIONING_V1_BSSID_BYTES 6
#define PROVISIONING_V1_SSID_BYTES 33
#define PROVISIONING_V1_PASSWORD_BYTES 65
#define PROVISIONING_V1_COLLECTOR_ENDPOINT_BYTES 46

typedef struct {
    uint64_t device_id;
    uint16_t key_epoch;
    uint8_t aes_key[PROVISIONING_V1_AES_KEY_BYTES];
    char station_ssid[PROVISIONING_V1_SSID_BYTES];
    char station_password[PROVISIONING_V1_PASSWORD_BYTES];
    uint8_t station_bssid[PROVISIONING_V1_BSSID_BYTES];
    uint8_t station_channel;
    uint16_t probe_port;
    char collector_endpoint[PROVISIONING_V1_COLLECTOR_ENDPOINT_BYTES];
    uint16_t collector_port;
    uint8_t capability_digest[PROVISIONING_V1_CAPABILITY_DIGEST_BYTES];
} provisioning_v1_t;

esp_err_t provisioning_v1_load(provisioning_v1_t *provisioning);
esp_err_t boot_generation_v1_advance(uint32_t *boot_generation);

#endif
