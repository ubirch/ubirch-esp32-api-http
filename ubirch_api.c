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
#include <esp_http_client.h>
#include <esp_log.h>
#include <msgpack.h>
#include <ubirch_protocol.h>
#include "ubirch_api.h"

static const char *TAG = "UBIRCH API";

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

        // only feed data if the unpacker is available
        if (evt->user_data != NULL) {
            msgpack_unpacker *unpacker = evt->user_data;

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


esp_err_t ubirch_send(const char *url, const char *data, const size_t length, msgpack_unpacker *unpacker) {
    ESP_LOGD(TAG, "ubirch_send(%s, len=%d)", url, length);

    esp_http_client_config_t config = {
            .url = url,
            .event_handler = _ubirch_http_event_handler,
            .user_data = unpacker
    };
    esp_http_client_handle_t client = esp_http_client_init(&config);

    // POST
    esp_http_client_set_url(client, url);
    esp_http_client_set_method(client, HTTP_METHOD_POST);
#ifdef UBIRCH_AUTH
    esp_http_client_set_header(client, "Content-Type", "application/octet-stream");
    esp_http_client_set_header(client, "Authorization", UBIRCH_AUTH);
#endif
    esp_http_client_set_post_field(client, data, (int) (length));
    esp_err_t err = esp_http_client_perform(client);
    if (err == ESP_OK) {
        const int http_status = esp_http_client_get_status_code(client);
        const int content_length = esp_http_client_get_content_length(client);
        ESP_LOGI(TAG, "HTTP POST status = %d, content_length = %d", http_status, content_length);
        err = (http_status >= 200 && http_status <= 299) ? ESP_OK : ESP_FAIL;
    } else {
        ESP_LOGE(TAG, "HTTP POST request failed: %s", esp_err_to_name(err));
    }

    esp_http_client_cleanup(client);
    return err;
}