/*!
 * @file
 * @brief ubirch register things
 *
 * ...
 *
 * @author Sven Herrmann
 * @date   2023-03-14
 *
 * @copyright &copy; 2023 ubirch GmbH (https://ubirch.com)
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
//#define LOG_LOCAL_LEVEL ESP_LOG_DEBUG

#include <string.h>
#include <esp_http_client.h>
#include <esp_log.h>
#include <cJSON.h>
#include <id_handling.h>
#include <token_handling.h>
#include <esp_err.h>
#include "register_thing.h"
#include "api-http-helper.h"

#ifndef CONFIG_UBIRCH_REGISTER_THING
#warning "UBIRCH_REGISTER_THING not enabled"
#else

static const char *TAG = "UBIRCH REGISTER THING";

/*!
 * TODO: fix documentation
 * @example JSON
 * - response when registering device
 *  [
 *    {
 *      "FFEEDDCC-BBAA-9988-7766-554433221100":{
 *        "state":"ok",
 *        "apiConfig":{
 *          "password":"00112233-4455-6677-8899-AABBCCDDEEFF",
 *          "keyService":"https://key.prod.ubirch.com/api/keyService/v1/pubkey/mpack",
 *          "niomon":"https://niomon.prod.ubirch.com/",
 *          "data":"https://data.prod.ubirch.com/v1/msgPack"
 *        }
 *      }
 *    }
 *  ]
 *
 * - response when requesting device info only
 *  [
 *    {
 *      "FFEEDDCC-BBAA-9988-7766-554433221100":{
 *        "password":"00112233-4455-6677-8899-AABBCCDDEEFF",
 *        "keyService": "https://key.prod.ubirch.com/api/keyService/v1/pubkey/mpack",
 *        "niomon": "https://niomon.prod.ubirch.com/",
 *        "data": "https://data.prod.ubirch.com/v1/msgPack"
 *      }
 *    }
 *  ]
 *
 * Parse json and check if it matches configuration. If everything is fine,
 * write password into password_buffer.
 *
 * @param expected_uuid[in]         the uuid, that we expect in the json
 * @param json[in]                  json character buffer, that is parsed
 * @param json_size[in]             size of the json character buffer
 * @param password_buffer[out]      password buffer for the received password
 * @param password_buffer_len[in]   size of password buffer
 *
 * @return ESP_OK
 *         ESP_FAIL
 */
static esp_err_t parse_api_info(const unsigned char* expected_uuid, const char* json,
        size_t json_size, char* password_buffer, size_t password_buffer_len) {
    ESP_LOGI(TAG, "parsing api info");
    ESP_LOG_BUFFER_HEXDUMP(TAG, json, (uint16_t) json_size, ESP_LOG_DEBUG);
    char expected_uuid_string[37];
    if (uuid_to_string(expected_uuid, expected_uuid_string, 37) < 0) {
        return ESP_FAIL;
    }

    cJSON* api_info = cJSON_Parse(json);
    if (api_info == NULL) {
        ESP_LOGE(TAG, "failed to parse json string");
        goto PARSE_API_INFO_ERROR;
    }
    if (cJSON_GetArraySize(api_info) != 1) {
        ESP_LOGE(TAG, "unexpected array size");
        goto PARSE_API_INFO_ERROR;
    }
    cJSON* device_info = cJSON_GetObjectItemCaseSensitive(
            cJSON_GetArrayItem(api_info, 0),
            expected_uuid_string);
    if (!cJSON_IsObject(device_info)) {
        ESP_LOGE(TAG, "could not get device info object");
        goto PARSE_API_INFO_ERROR;
    }

    const cJSON* state = cJSON_GetObjectItemCaseSensitive(device_info, "state");
    cJSON* config = NULL;
    if (state != NULL) {
        // we have a state value (so it's the response of the registration)
        if (!cJSON_IsString(state) || (state->valuestring == NULL)
                || (strcmp("ok", state->valuestring) != 0)) {
            ESP_LOGE(TAG, "state is not ok");
            goto PARSE_API_INFO_ERROR;
        }
        config = cJSON_GetObjectItemCaseSensitive(device_info, "apiConfig");
        if (!cJSON_IsObject(config)) {
            ESP_LOGE(TAG, "no api config found in json");
            goto PARSE_API_INFO_ERROR;
        }
    } else {
        // we have no state value (so it's the response of the configuration request)
        // in this case the device info object contains the configuration directly
        config = device_info;
    }
    // check api configuration
    cJSON* niomon_url = cJSON_GetObjectItemCaseSensitive(config, "niomon");
    if (!cJSON_IsString(niomon_url) || (niomon_url->valuestring == NULL)
                    || (strcmp(CONFIG_UBIRCH_BACKEND_DATA_URL, niomon_url->valuestring) != 0)) {
        ESP_LOGE(TAG, "unexpected or no niomon url");
        goto PARSE_API_INFO_ERROR;
    }
    // so everything is fine
    // copy password from api config into password_buffer
    cJSON* password = cJSON_GetObjectItemCaseSensitive(config, "password");
    if (!cJSON_IsString(password) || (password->valuestring == NULL)) {
        ESP_LOGE(TAG, "failed to read password");
        goto PARSE_API_INFO_ERROR;
    }
    if (snprintf(password_buffer, password_buffer_len, password->valuestring)
            > password_buffer_len) {
        ESP_LOGE(TAG, "password buffer too small");
        goto PARSE_API_INFO_ERROR;
    }

    cJSON_Delete(api_info);
    return ESP_OK;

PARSE_API_INFO_ERROR:
    cJSON_Delete(api_info);
    return ESP_FAIL;
}

// strlen("{\"hwDeviceId\":\"") + strlen("<UUID>") + strlen("\",\"description\":\"\"}\0")
#define UBIRCH_REGISTER_THING_JSON_OBJECT_SIZE (14 + 36 + 21)
static int build_post_json_object(const unsigned char* uuid, const char* device_description,
        char* string_buffer, size_t max_len) {
    size_t offset = 0;
    int ret = snprintf(string_buffer, max_len, "{\"hwDeviceId\":\"");
    if (ret < 0) {
        return UBIRCH_ESP32_REGISTER_THING_ERROR;
    }
    offset = ret;
    ret = uuid_to_string(uuid, string_buffer + offset, max_len - offset);
    if (ret < 0) {
        return UBIRCH_ESP32_REGISTER_THING_ERROR;
    }
    offset = offset + ret;
    ret = snprintf(string_buffer + offset, max_len - offset, "\",\"description\":\"%s\"}", device_description);
    if (ret < 0) {
        return UBIRCH_ESP32_REGISTER_THING_ERROR;
    }
    return offset + ret;
}

typedef struct {
    bool ok;
} register_current_id_event_handler_user_data_context_t;

static esp_err_t _register_current_id_event_handler(esp_http_client_event_t* evt) {
    if (evt->event_id == HTTP_EVENT_ON_DATA) {
        ESP_LOGD(TAG, "HTTP received %d bytes", evt->data_len);
        ESP_LOG_BUFFER_HEXDUMP(TAG, evt->data, (uint16_t) evt->data_len, ESP_LOG_DEBUG);

        register_current_id_event_handler_user_data_context_t* ctx = evt->user_data;

        // get uuid from current context
        unsigned char* uuid;
        size_t uuid_len;
        if (ubirch_uuid_get(&uuid, &uuid_len) != ESP_OK) {
            return ESP_FAIL;
        }

        // try to parse json response
        char password_buffer[37];
        if (parse_api_info(uuid, evt->data, evt->data_len, password_buffer,
                    sizeof(password_buffer)) != ESP_OK) {
            ESP_LOGE(TAG, "Failed to parse received json");
            return ESP_FAIL;
        }
        // set password of current context
        if (ubirch_password_set(password_buffer, strlen(password_buffer)) != ESP_OK) {
            ESP_LOGE(TAG, "Failed to set current password");
            return ESP_FAIL;
        }
        ubirch_id_state_set(UBIRCH_ID_STATE_PASSWORD_SET, true);

        ctx->ok = true;
    }
    return ESP_OK;
}

int ubirch_register_current_id(const char* device_description) {
    register_current_id_event_handler_user_data_context_t event_context = {
        .ok = false
    };

    // get current uuid
    unsigned char* uuid;
    size_t uuid_len;
    if (ubirch_uuid_get(&uuid, &uuid_len) != ESP_OK) {
        return UBIRCH_ESP32_REGISTER_THING_ERROR;
    }

    char get_info_url[sizeof(CONFIG_UBIRCH_GET_INFO_OF_THING_URL) + 37] = CONFIG_UBIRCH_GET_INFO_OF_THING_URL;
    if (uuid_to_string(uuid, get_info_url + sizeof(CONFIG_UBIRCH_GET_INFO_OF_THING_URL) - 1, 37) < 0) {
        return -1;
    }
    ESP_LOGD(TAG, "get-info-url: \"%s\"", get_info_url);

    // get authorization token
    const char* token = NULL;
    ubirch_token_get(&token);
    char auth_header[1024];
    sprintf(auth_header, "Bearer %s", token);
    ESP_LOGD(TAG, "auth-header: \"%s\"", auth_header);

    // FIXME: adjust buffer size, what do we need at maximum?
    esp_http_client_config_t config = {
            .url = get_info_url,
            .event_handler = _register_current_id_event_handler,
            .user_data = &event_context,
            .buffer_size = 2048,
            .buffer_size_tx = 2048
    };
    esp_http_client_handle_t client = esp_http_client_init(&config);

    ESP_LOGI(TAG, "check if device is already registered");
    esp_http_client_set_method(client, HTTP_METHOD_POST);
    esp_http_client_set_header(client, "Authorization", auth_header);
    esp_http_client_set_header(client, "accept", "application/json");
    esp_err_t err = esp_http_client_perform(client);

    int return_code = UBIRCH_ESP32_REGISTER_THING_REQUEST_FAILED;
    if (err == ESP_OK) {
        int http_status = esp_http_client_get_status_code(client);
        const int content_length = esp_http_client_get_content_length(client);
        ESP_LOGD(TAG, "HTTP POST status = %d, content_length = %d", http_status, content_length);
        if (event_context.ok) {
            return_code = UBIRCH_ESP32_REGISTER_THING_ALREADY_REGISTERED;
        } else {
            return_code = UBIRCH_ESP32_REGISTER_THING_ERROR;
        }
    } else {
        ESP_LOGD(TAG, "HTTP POST request failed: %s", esp_err_to_name(err));
        return_code = UBIRCH_ESP32_REGISTER_THING_REQUEST_FAILED;
    }

    // build up request and send
    if (device_description != NULL && return_code == UBIRCH_ESP32_REGISTER_THING_ERROR) {
        ESP_LOGI(TAG, "register device");
        // build request data json
        const size_t json_data_len = UBIRCH_REGISTER_THING_JSON_OBJECT_SIZE + strlen(device_description);
        char* json_data = malloc(json_data_len);
        unsigned char* uuid;
        size_t uuid_len;
        if (ubirch_uuid_get(&uuid, &uuid_len) != ESP_OK) {
            return UBIRCH_ESP32_REGISTER_THING_ERROR;
        }
        if (build_post_json_object(uuid, device_description, json_data, json_data_len) < 0) {
            return UBIRCH_ESP32_REGISTER_THING_ERROR;
        }
        ESP_LOGD(TAG, "request: %s", json_data);

        // re-use request from above
        esp_http_client_set_url(client, CONFIG_UBIRCH_REGISTER_THING_URL);
        esp_http_client_set_header(client, "Content-Type", "application/json");
        esp_http_client_set_post_field(client, json_data, (int)json_data_len);
        err = esp_http_client_perform(client);

        if (err == ESP_OK) {
            int http_status = esp_http_client_get_status_code(client);
            const int content_length = esp_http_client_get_content_length(client);
            ESP_LOGD(TAG, "HTTP POST status = %d, content_length = %d", http_status, content_length);
            if (event_context.ok) {
                return_code = UBIRCH_ESP32_REGISTER_THING_SUCCESS;
            } else {
                return_code = UBIRCH_ESP32_REGISTER_THING_ERROR;
            }
        } else {
            ESP_LOGD(TAG, "HTTP POST request failed: %s", esp_err_to_name(err));
            return_code = UBIRCH_ESP32_REGISTER_THING_ERROR;
        }
        free(json_data);
    }

    esp_http_client_cleanup(client);
    return return_code;
}

#endif // UBIRCH_REGISTER_THING