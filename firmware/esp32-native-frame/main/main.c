#include <inttypes.h>
#include <stdatomic.h>
#include <string.h>

#include "arpa/inet.h"
#include "capability_build_facts.h"
#include "csi_capture_v1.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_ota_ops.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/task.h"
#include "lwip/sockets.h"
#include "mbedtls/constant_time.h"
#include "mbedtls/platform_util.h"
#include "native_frame_v1.h"
#include "nvs_flash.h"
#include "provisioning_v1.h"
#include "sender_v1.h"

static const char *TAG = "native_frame";

/* User-authorized v1 bootstrap values; changes affect startup, admission, and observability. */
#define ASSOCIATION_TIMEOUT_MS UINT32_C(30000)
#define CAPABILITIES_PERIOD_US UINT64_C(30000000)
#define HEALTH_PERIOD_US UINT64_C(10000000)
#define WIFI_READY_BIT BIT0
#define WIFI_FAILED_BIT BIT1
#define SENDER_READY_BIT BIT2
#define SENDER_FAILED_BIT BIT3

_Static_assert(configTICK_RATE_HZ == 100, "v1 sender idle bound requires pinned 100 Hz tick");

typedef struct {
    EventGroupHandle_t events;
    bool wifi_initialized;
    esp_netif_t *station_netif;
    int collector_family;
    esp_ip6_addr_type_t collector_ipv6_type;
    atomic_int socket_fd;
    struct sockaddr_storage collector;
    socklen_t collector_length;
    nf_v1_envelope_t envelope;
    nf_v1_capability_descriptor_t descriptor;
    uint8_t key[PROVISIONING_V1_AES_KEY_BYTES];
    csi_capture_v1_t capture;
} runtime_v1_t;

static runtime_v1_t runtime;

static void fail_runtime(runtime_v1_t *state)
{
    if (state->events != NULL) {
        xEventGroupSetBits(state->events, WIFI_FAILED_BIT | SENDER_FAILED_BIT);
    }
    if (state->wifi_initialized) {
        esp_wifi_set_csi(false);
    }
    int socket_fd = atomic_exchange_explicit(&state->socket_fd, -1, memory_order_acq_rel);
    if (socket_fd >= 0) {
        shutdown(socket_fd, SHUT_RDWR);
        close(socket_fd);
    }
}

static void csi_callback(void *context, wifi_csi_info_t *info)
{
    runtime_v1_t *state = context;
    csi_capture_v1_callback(&state->capture, info);
}

static void wifi_event(void *argument, esp_event_base_t base, int32_t id, void *data)
{
    runtime_v1_t *state = argument;
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_CONNECTED
        && state->collector_family == AF_INET6) {
        if (esp_netif_create_ip6_linklocal(state->station_netif) != ESP_OK) {
            fail_runtime(state);
        }
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP
        && state->collector_family == AF_INET
        && ((ip_event_got_ip_t *)data)->esp_netif == state->station_netif) {
        xEventGroupSetBits(state->events, WIFI_READY_BIT);
    } else if (base == IP_EVENT && id == IP_EVENT_GOT_IP6
        && state->collector_family == AF_INET6) {
        ip_event_got_ip6_t *event = data;
        if (event->esp_netif == state->station_netif
            && esp_netif_ip6_get_addr_type(&event->ip6_info.ip) == state->collector_ipv6_type) {
            xEventGroupSetBits(state->events, WIFI_READY_BIT);
        }
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        fail_runtime(state);
    }
}

static esp_err_t configure_collector(const provisioning_v1_t *provisioning)
{
    struct sockaddr_in *v4 = (struct sockaddr_in *)&runtime.collector;
    struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&runtime.collector;
    if (inet_pton(AF_INET, provisioning->collector_endpoint, &v4->sin_addr) == 1) {
        runtime.collector_family = AF_INET;
        runtime.collector_length = sizeof(*v4);
        v4->sin_family = AF_INET;
        v4->sin_port = htons(provisioning->collector_port);
        return ESP_OK;
    }
    if (inet_pton(AF_INET6, provisioning->collector_endpoint, &v6->sin6_addr) != 1
        || IN6_IS_ADDR_UNSPECIFIED(&v6->sin6_addr) || IN6_IS_ADDR_LOOPBACK(&v6->sin6_addr)
        || IN6_IS_ADDR_MULTICAST(&v6->sin6_addr) || IN6_IS_ADDR_LINKLOCAL(&v6->sin6_addr)
        || IN6_IS_ADDR_V4MAPPED(&v6->sin6_addr)) {
        return ESP_ERR_INVALID_ARG;
    }
    runtime.collector_family = AF_INET6;
    runtime.collector_length = sizeof(*v6);
    v6->sin6_family = AF_INET6;
    v6->sin6_port = htons(provisioning->collector_port);
    if ((v6->sin6_addr.s6_addr[0] & 0xfe) == 0xfc) {
        runtime.collector_ipv6_type = ESP_IP6_ADDR_IS_UNIQUE_LOCAL;
    } else if (v6->sin6_addr.s6_addr[0] == 0xfe
        && (v6->sin6_addr.s6_addr[1] & 0xc0) == 0xc0) {
        runtime.collector_ipv6_type = ESP_IP6_ADDR_IS_SITE_LOCAL;
    } else {
        runtime.collector_ipv6_type = ESP_IP6_ADDR_IS_GLOBAL;
    }
    return ESP_OK;
}

static esp_err_t start_station(const provisioning_v1_t *provisioning)
{
    esp_err_t result = esp_netif_init();
    if (result == ESP_OK) result = esp_event_loop_create_default();
    if (result == ESP_OK) {
        runtime.station_netif = esp_netif_create_default_wifi_sta();
        if (runtime.station_netif == NULL) result = ESP_ERR_NO_MEM;
    }
    wifi_init_config_t init = WIFI_INIT_CONFIG_DEFAULT();
    if (result == ESP_OK) result = esp_wifi_init(&init);
    if (result == ESP_OK) runtime.wifi_initialized = true;
    if (result == ESP_OK) result = esp_event_handler_register(WIFI_EVENT,
        ESP_EVENT_ANY_ID, wifi_event, &runtime);
    if (result == ESP_OK) result = esp_event_handler_register(IP_EVENT,
        runtime.collector_family == AF_INET ? IP_EVENT_STA_GOT_IP : IP_EVENT_GOT_IP6,
        wifi_event, &runtime);
    if (result == ESP_OK) result = esp_wifi_set_mode(WIFI_MODE_STA);

    wifi_config_t config = {0};
    memcpy(config.sta.ssid, provisioning->station_ssid,
        strnlen(provisioning->station_ssid, sizeof(config.sta.ssid)));
    memcpy(config.sta.password, provisioning->station_password,
        strnlen(provisioning->station_password, sizeof(config.sta.password)));
    if (result == ESP_OK) result = esp_wifi_set_config(WIFI_IF_STA, &config);
    mbedtls_platform_zeroize(&config, sizeof(config));
    if (result == ESP_OK) result = esp_wifi_start();
    if (result == ESP_OK) result = esp_wifi_set_promiscuous(false);
    if (result == ESP_OK) result = esp_wifi_set_ps(WIFI_PS_NONE);
    if (result == ESP_OK) result = esp_wifi_connect();
    if (result != ESP_OK) return result;
    EventBits_t bits = xEventGroupWaitBits(runtime.events, WIFI_READY_BIT | WIFI_FAILED_BIT,
        pdFALSE, pdFALSE, pdMS_TO_TICKS(ASSOCIATION_TIMEOUT_MS));
    return (bits & WIFI_READY_BIT) != 0 ? ESP_OK : ESP_ERR_TIMEOUT;
}

static esp_err_t resolve_capture_binding(csi_capture_v1_config_t *capture_config)
{
    if (capture_config == NULL) return ESP_ERR_INVALID_ARG;
    wifi_ap_record_t access_point = {0};
    esp_err_t result = esp_wifi_sta_get_ap_info(&access_point);
    bool bssid_nonzero = false;
    for (size_t index = 0; index < sizeof(access_point.bssid); ++index) {
        bssid_nonzero |= access_point.bssid[index] != 0;
    }
    if (result == ESP_OK && (!bssid_nonzero || (access_point.bssid[0] & 1) != 0
        || access_point.primary < 1 || access_point.primary > 14)) {
        result = ESP_ERR_INVALID_RESPONSE;
    }
    if (result == ESP_OK) {
        memcpy(capture_config->station_bssid, access_point.bssid,
            sizeof(capture_config->station_bssid));
        capture_config->channel = access_point.primary;
        result = esp_wifi_get_mac(WIFI_IF_STA, capture_config->station_mac);
    }
    mbedtls_platform_zeroize(&access_point, sizeof(access_point));
    return result;
}

static esp_err_t open_probe_socket(const provisioning_v1_t *provisioning)
{
    int socket_fd = socket(runtime.collector_family, SOCK_DGRAM, IPPROTO_UDP);
    if (socket_fd < 0) return ESP_FAIL;
    int bound;
    if (runtime.collector_family == AF_INET) {
        struct sockaddr_in local = {.sin_family = AF_INET,
            .sin_port = htons(provisioning->probe_port), .sin_addr.s_addr = htonl(INADDR_ANY)};
        bound = bind(socket_fd, (const struct sockaddr *)&local, sizeof(local));
    } else {
        struct sockaddr_in6 local = {.sin6_family = AF_INET6,
            .sin6_port = htons(provisioning->probe_port), .sin6_addr = IN6ADDR_ANY_INIT};
        bound = bind(socket_fd, (const struct sockaddr *)&local, sizeof(local));
    }
    if (bound != 0) {
        close(socket_fd);
        return ESP_FAIL;
    }
    atomic_store_explicit(&runtime.socket_fd, socket_fd, memory_order_release);
    return ESP_OK;
}

static void probe_task(void *argument)
{
    runtime_v1_t *state = argument;
    uint8_t discard[64];
    int socket_fd = atomic_load_explicit(&state->socket_fd, memory_order_acquire);
    while (socket_fd >= 0 && recv(socket_fd, discard, sizeof(discard), 0) >= 0) {
    }
    vTaskDelete(NULL);
}

static bool sender_result_is_fatal(sender_v1_result_t result)
{
    return result != SENDER_V1_OK && result != SENDER_V1_NO_CSI
        && result != SENDER_V1_CSI_DROPPED && result != SENDER_V1_SEND_FAILED;
}

static void sender_task(void *argument)
{
    runtime_v1_t *state = argument;
    sender_v1_t sender;
    int socket_fd = atomic_load_explicit(&state->socket_fd, memory_order_acquire);
    bool initialized = sender_v1_init(&sender, socket_fd,
        (const struct sockaddr *)&state->collector, state->collector_length,
        &state->envelope, state->key);
    mbedtls_platform_zeroize(state->key, sizeof(state->key));
    if (!initialized || sender_v1_send_capabilities(&sender, &state->descriptor) != SENDER_V1_OK) {
        fail_runtime(state);
        mbedtls_platform_zeroize(&sender, sizeof(sender));
        vTaskDelete(NULL);
        return;
    }
    xEventGroupSetBits(state->events, SENDER_READY_BIT);
    uint64_t now_us = (uint64_t)esp_timer_get_time();
    uint64_t next_capabilities_us = now_us + CAPABILITIES_PERIOD_US;
    uint64_t next_health_us = now_us + HEALTH_PERIOD_US;
    for (;;) {
        if ((xEventGroupGetBits(state->events) & WIFI_FAILED_BIT) != 0) break;
        sender_v1_result_t result = sender_v1_send_next_csi(&sender, &state->capture);
        if (sender_result_is_fatal(result)) break;
        now_us = (uint64_t)esp_timer_get_time();
        if (now_us >= next_capabilities_us) {
            result = sender_v1_send_capabilities(&sender, &state->descriptor);
            next_capabilities_us = now_us + CAPABILITIES_PERIOD_US;
        }
        if (!sender_result_is_fatal(result) && now_us >= next_health_us) {
            result = sender_v1_send_health(&sender, &state->capture, now_us,
                csi_capture_v1_pool_high_water_slots(&state->capture), 0, 0);
            next_health_us = now_us + HEALTH_PERIOD_US;
        }
        if (sender_result_is_fatal(result)) break;
        /* Pinned 100 Hz FreeRTOS tick: 10 ms idle ceiling; use queue notification if measured too slow. */
        vTaskDelay(1);
    }
    fail_runtime(state);
    mbedtls_platform_zeroize(&sender, sizeof(sender));
    vTaskDelete(NULL);
}

void app_main(void)
{
    provisioning_v1_t provisioning;
    uint32_t boot_generation = 0;
    memset(&runtime, 0, sizeof(runtime));
    atomic_init(&runtime.socket_fd, -1);
    runtime.events = xEventGroupCreate();
    esp_err_t result = runtime.events == NULL ? ESP_ERR_NO_MEM : nvs_flash_init();
    if (result == ESP_OK) result = provisioning_v1_load(&provisioning);

    uint8_t capability_body[NF_V1_CAPABILITIES_BODY_BYTES];
    uint8_t capability_digest[32];
    size_t capability_body_bytes = 0;
    runtime.descriptor.datagram_budget_bytes = 1200;
    if (result == ESP_OK) result = esp_partition_get_sha256(esp_ota_get_running_partition(),
        runtime.descriptor.firmware_build_digest);
    memcpy(runtime.descriptor.idf_wifi_abi_digest, IDF_WIFI_ABI_DIGEST, sizeof(IDF_WIFI_ABI_DIGEST));
    if (result == ESP_OK && nf_v1_encode_capabilities(&runtime.descriptor, capability_body,
        sizeof(capability_body), &capability_body_bytes, capability_digest) != NF_V1_OK) {
        result = ESP_FAIL;
    }
    if (result == ESP_OK && mbedtls_ct_memcmp(capability_digest,
        provisioning.capability_digest, sizeof(capability_digest)) != 0) result = ESP_ERR_INVALID_CRC;
    if (result == ESP_OK) result = configure_collector(&provisioning);
    if (result == ESP_OK) result = boot_generation_v1_advance(&boot_generation);
    if (result == ESP_OK) ESP_LOGI(TAG, "provisioning accepted; boot generation %" PRIu32
        "; awaiting network prerequisites", boot_generation);
    if (result == ESP_OK) result = start_station(&provisioning);
    if (result == ESP_OK) result = open_probe_socket(&provisioning);
    if (result == ESP_OK && (xEventGroupGetBits(runtime.events) & WIFI_FAILED_BIT) != 0) {
        result = ESP_ERR_INVALID_STATE;
        fail_runtime(&runtime);
    }

    csi_capture_v1_config_t capture_config = {0};
    if (result == ESP_OK) result = resolve_capture_binding(&capture_config);
    if (result == ESP_OK && !csi_capture_v1_init(&runtime.capture, &capture_config)) result = ESP_FAIL;
    if (result == ESP_OK) {
        runtime.envelope = (nf_v1_envelope_t) {.device_id = provisioning.device_id,
            .key_epoch = provisioning.key_epoch, .boot_generation = boot_generation,
            .message_sequence = 1, .datagram_budget_bytes = runtime.descriptor.datagram_budget_bytes};
        memcpy(runtime.key, provisioning.aes_key, sizeof(runtime.key));
    }
    mbedtls_platform_zeroize(&provisioning, sizeof(provisioning));
    mbedtls_platform_zeroize(capability_body, sizeof(capability_body));
    mbedtls_platform_zeroize(capability_digest, sizeof(capability_digest));
    mbedtls_platform_zeroize(&capture_config, sizeof(capture_config));

    wifi_csi_config_t csi_config = {.lltf_en = true, .htltf_en = true,
        .stbc_htltf2_en = true, .ltf_merge_en = false, .channel_filter_en = false,
        .manu_scale = false, .shift = 0, .dump_ack_en = false};
    if (result == ESP_OK) result = esp_wifi_set_csi_config(&csi_config);
    if (result == ESP_OK) result = esp_wifi_set_csi_rx_cb(csi_callback, &runtime);
    if (result == ESP_OK && xTaskCreate(probe_task, "probe_rx", 3072, &runtime, 1, NULL) != pdPASS)
        result = ESP_ERR_NO_MEM;
    bool sender_started = false;
    if (result == ESP_OK) {
        sender_started = xTaskCreate(sender_task, "native_sender", 4096,
            &runtime, 2, NULL) == pdPASS;
        if (!sender_started) result = ESP_ERR_NO_MEM;
    }
    if (result == ESP_OK) {
        EventBits_t bits = xEventGroupWaitBits(runtime.events,
            SENDER_READY_BIT | SENDER_FAILED_BIT | WIFI_FAILED_BIT,
            pdFALSE, pdFALSE, pdMS_TO_TICKS(ASSOCIATION_TIMEOUT_MS));
        result = (bits & SENDER_READY_BIT) != 0
                && (bits & (SENDER_FAILED_BIT | WIFI_FAILED_BIT)) == 0
            ? ESP_OK : ESP_FAIL;
    }
    if (result == ESP_OK) result = esp_wifi_set_csi(true);
    if (result == ESP_OK && (xEventGroupGetBits(runtime.events) & WIFI_FAILED_BIT) != 0) {
        result = ESP_ERR_INVALID_STATE;
    }
    if (result != ESP_OK) {
        fail_runtime(&runtime);
        if (!sender_started) mbedtls_platform_zeroize(runtime.key, sizeof(runtime.key));
        ESP_LOGE(TAG, "runtime startup failed: %s; capture disabled", esp_err_to_name(result));
        return;
    }
    ESP_LOGI(TAG, "runtime active; boot generation %" PRIu32, boot_generation);
}
