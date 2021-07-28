/*!
 * @file
 * @brief ubirch API
 *
 * ...
 *
 * @author Matthias L. Jugel
 * @date   2018-11-30
 *
 * @copyright &copy; 2018 ubirch GmbH (https://ubirch.com)
 *
 * ```
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ```
 */
#include <stddef.h>
#include <assert.h>
#include <esp_http_client.h>
#include <esp_log.h>
#include <msgpack.h>
#include <ubirch_protocol.h>
#include "ubirch_api.h"
#include "mbedtls/base64.h"

static const char *TAG = "UBIRCH API";
//#define LOG_LOCAL_LEVEL ESP_LOG_DEBUG

/*!
 * Used locally to pass verifier with unpacker to the http-event-handler.
 */
typedef struct {
    msgpack_unpacker* unpacker;
    ubirch_protocol_check verifier;
    bool verified;
} http_event_user_data_context_t;

/*!
 * Event handler for the ubirch response. Feeds response data into a msgpack unpacker to be parsed.
 * 
 * @param evt, which calls this handler
 * @return error state if any or ESP_OK
 */
static esp_err_t _ubirch_http_event_handler(esp_http_client_event_t *evt) {
    if (evt->event_id == HTTP_EVENT_ON_DATA) {
        ESP_LOGD(TAG, "HTTP received %d byte", evt->data_len);
        ESP_LOG_BUFFER_HEXDUMP(TAG, evt->data, (uint16_t) evt->data_len, ESP_LOG_DEBUG);
        http_event_user_data_context_t* ctx = evt->user_data;

        // verify if there's a verifier and proceed only if received data is verifiable
        if (ctx->verifier != NULL) {
            if (ubirch_protocol_verify(evt->data, evt->data_len, ctx->verifier) == 0) {
                ctx->verified = true;
            } else {
                ESP_LOGD(TAG, "verification of received data failed");
                return ESP_FAIL;
            }
        }

        // only feed data if the unpacker is available
        if (ctx->unpacker != NULL) {
            msgpack_unpacker *unpacker = ctx->unpacker;

            if (!esp_http_client_is_chunked_response(evt->client)) {
                ESP_LOG_BUFFER_HEXDUMP(TAG, evt->data, (uint16_t) evt->data_len, ESP_LOG_DEBUG);
                if (msgpack_unpacker_buffer_capacity(unpacker) < evt->data_len) {
                    msgpack_unpacker_reserve_buffer(unpacker, (uint16_t) evt->data_len);
                }
                memcpy(msgpack_unpacker_buffer(unpacker), evt->data, (uint16_t) evt->data_len);
                msgpack_unpacker_buffer_consumed(unpacker, (uint16_t) evt->data_len);
            }
        }
    }
    return ESP_OK;
}

void uuid_to_string(const unsigned char *uuid, char *buffer, size_t len) {
    assert(len >= 37);
    const char *format = "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x";
    sprintf(buffer, format,
            uuid[0], uuid[1], uuid[2], uuid[3], uuid[4], uuid[5], uuid[6], uuid[7],
            uuid[8], uuid[9], uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]
    );
}

static char *auth_to_base64(const char *auth) {
    unsigned char *auth64 = NULL;
    size_t auth64_len;
    mbedtls_base64_encode(auth64, 0, &auth64_len,
                          (const unsigned char *) auth, strlen(auth));
    auth64 = malloc(auth64_len);
    mbedtls_base64_encode(auth64, auth64_len, &auth64_len,
                          (const unsigned char *) auth, strlen(auth));
    return (char *) auth64;
}

ubirch_send_err_t ubirch_send(const char *url, const unsigned char *uuid, const char *data, const size_t length,
        int* http_status, msgpack_unpacker *unpacker, ubirch_protocol_check verifier) {
    ESP_LOGD(TAG, "ubirch_send(%s, len=%d)", url, length);
    http_event_user_data_context_t event_context = {
            .unpacker = unpacker,
            .verifier = verifier,
            .verified = false
    };
    esp_http_client_config_t config = {
            .url = url,
            .event_handler = _ubirch_http_event_handler,
            .user_data = &event_context
    };
    esp_http_client_handle_t client = esp_http_client_init(&config);

    // POST
    esp_http_client_set_url(client, url);
    esp_http_client_set_method(client, HTTP_METHOD_POST);
#ifdef CONFIG_UBIRCH_AUTH
    char uuid_string[37];
    uuid_to_string(uuid, uuid_string, sizeof(uuid_string));
    char *auth_string = auth_to_base64(CONFIG_UBIRCH_AUTH);

    esp_http_client_set_header(client, "Content-Type", "application/octet-stream");
    esp_http_client_set_header(client, "X-Ubirch-Hardware-Id", uuid_string);
    esp_http_client_set_header(client, "X-Ubirch-Credential", auth_string);
    esp_http_client_set_header(client, "X-Ubirch-Auth-Type", "ubirch");
#endif
    esp_http_client_set_post_field(client, data, (int) (length));
    esp_err_t err = esp_http_client_perform(client);
    ubirch_send_err_t return_code = UBIRCH_SEND_OK;
    if (err == ESP_OK) {
        *http_status = esp_http_client_get_status_code(client);
        const int content_length = esp_http_client_get_content_length(client);
        ESP_LOGD(TAG, "HTTP POST status = %d, content_length = %d", *http_status, content_length);
        if (event_context.verifier != NULL && !event_context.verified) {
            return_code = UBIRCH_SEND_VERIFICATION_FAILED;
        }
    } else {
        ESP_LOGD(TAG, "HTTP POST request failed: %s", esp_err_to_name(err));
        return_code = UBIRCH_SEND_ERROR;
    }
    esp_http_client_cleanup(client);
#ifdef CONFIG_UBIRCH_AUTH
    free(auth_string);
#endif
    return return_code;
}
