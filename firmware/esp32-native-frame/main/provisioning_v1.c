#include "provisioning_v1.h"

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "arpa/inet.h"
#include "lwip/sockets.h"
#include "nvs.h"
#include "nvs_flash.h"

static esp_err_t get_exact_blob(nvs_handle_t handle, const char *key, void *value, size_t expected)
{
    size_t length = expected;
    esp_err_t result = nvs_get_blob(handle, key, value, &length);
    return result == ESP_OK && length == expected ? ESP_OK : ESP_ERR_INVALID_SIZE;
}

static esp_err_t get_bounded_string(
    nvs_handle_t handle, const char *key, char *value, size_t capacity, bool allow_empty)
{
    size_t length = 0;
    esp_err_t result = nvs_get_str(handle, key, NULL, &length);
    if (result != ESP_OK) {
        return result;
    }
    if (length > capacity || (!allow_empty && length <= 1)) {
        return ESP_ERR_INVALID_SIZE;
    }
    return nvs_get_str(handle, key, value, &length);
}

esp_err_t provisioning_v1_load(provisioning_v1_t *provisioning)
{
    if (provisioning == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    nvs_handle_t handle;
    esp_err_t result = nvs_open("provision", NVS_READONLY, &handle);
    if (result != ESP_OK) {
        return result;
    }

    uint16_t schema = 0;
    memset(provisioning, 0, sizeof(*provisioning));
#define GET(call) do { result = (call); if (result != ESP_OK) goto done; } while (0)
    GET(nvs_get_u16(handle, "schema", &schema));
    GET(nvs_get_u64(handle, "device_id", &provisioning->device_id));
    GET(nvs_get_u16(handle, "key_epoch", &provisioning->key_epoch));
    GET(get_exact_blob(handle, "aes_key", provisioning->aes_key, sizeof(provisioning->aes_key)));
    GET(get_bounded_string(handle, "ssid", provisioning->station_ssid,
        sizeof(provisioning->station_ssid), false));
    GET(get_bounded_string(handle, "wifi_pass", provisioning->station_password,
        sizeof(provisioning->station_password), true));
    GET(get_exact_blob(handle, "bssid", provisioning->station_bssid,
        sizeof(provisioning->station_bssid)));
    GET(nvs_get_u8(handle, "channel", &provisioning->station_channel));
    GET(nvs_get_u16(handle, "probe_port", &provisioning->probe_port));
    GET(get_bounded_string(handle, "collector_ip", provisioning->collector_endpoint,
        sizeof(provisioning->collector_endpoint), false));
    GET(nvs_get_u16(handle, "collect_port", &provisioning->collector_port));
    GET(get_exact_blob(handle, "cap_digest", provisioning->capability_digest,
        sizeof(provisioning->capability_digest)));
#undef GET

    struct in6_addr address;
    size_t password_bytes = strlen(provisioning->station_password);
    bool bssid_nonzero = false;
    for (size_t index = 0; index < sizeof(provisioning->station_bssid); ++index) {
        bssid_nonzero |= provisioning->station_bssid[index] != 0;
    }
    if (schema != PROVISIONING_V1_SCHEMA || provisioning->key_epoch == 0
        || (!bssid_nonzero || (provisioning->station_bssid[0] & 1) != 0)
        || (password_bytes != 0 && (password_bytes < 8 || password_bytes > 63))
        || provisioning->station_channel < 1
        || provisioning->station_channel > 14 || provisioning->probe_port == 0
        || provisioning->collector_port == 0
        || (inet_pton(AF_INET, provisioning->collector_endpoint, &address) != 1
            && inet_pton(AF_INET6, provisioning->collector_endpoint, &address) != 1)) {
        result = ESP_ERR_INVALID_ARG;
    }

done:
    nvs_close(handle);
    if (result != ESP_OK) {
        memset(provisioning, 0, sizeof(*provisioning));
    }
    return result;
}

esp_err_t boot_generation_v1_advance(uint32_t *boot_generation)
{
    if (boot_generation == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    nvs_handle_t handle;
    esp_err_t result = nvs_open("runtime", NVS_READWRITE, &handle);
    if (result != ESP_OK) {
        return result;
    }
    uint32_t previous = 0;
    result = nvs_get_u32(handle, "boot_generation", &previous);
    if (result == ESP_OK && previous == UINT32_MAX) {
        result = ESP_ERR_INVALID_STATE;
    }
    if (result == ESP_OK) {
        result = nvs_set_u32(handle, "boot_generation", previous + 1);
    }
    if (result == ESP_OK) {
        result = nvs_commit(handle);
    }
    nvs_close(handle);
    if (result != ESP_OK) {
        return result;
    }

    result = nvs_open("runtime", NVS_READONLY, &handle);
    if (result != ESP_OK) {
        return result;
    }
    uint32_t stored = 0;
    result = nvs_get_u32(handle, "boot_generation", &stored);
    nvs_close(handle);
    if (result != ESP_OK || stored == 0 || stored != previous + 1) {
        return result == ESP_OK ? ESP_ERR_INVALID_STATE : result;
    }
    *boot_generation = stored;
    return ESP_OK;
}
