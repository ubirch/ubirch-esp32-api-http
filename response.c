/*!
 * @file
 * @brief ubirch response parser
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
#include <msgpack.h>
#include <esp_log.h>
#include <ubirch_protocol.h>
#include <armnacl.h>
#include "ubirch_api.h"
#include "response.h"
#include "message.h"

static const char *TAG = "UBIRCH API";

bool match(const msgpack_object_kv *kv, const char *key, const int type) {
    const size_t keyLength = strlen(key);
    return kv->key.type == MSGPACK_OBJECT_RAW &&
           kv->key.via.raw.size == keyLength &&
           (type == -1 || kv->val.type == type) &&
           !memcmp(key, kv->key.via.raw.ptr, keyLength);
}

static void parse_measurement_reply(msgpack_object *envelope, ubirch_response_handler handler) {
    if (envelope->type == MSGPACK_OBJECT_MAP) {
        msgpack_object_kv *entry = envelope->via.map.ptr;
        for (uint32_t entries = 0; entries < envelope->via.map.size; entry++, entries++) {
            handler(entry);
        }
    } else {
        ESP_LOGI(TAG, "unknown MSGPACK object");
    }
}


void ubirch_parse_response(msgpack_unpacker *unpacker, ubirch_response_handler handler) {
    ESP_LOGI(TAG, "parsing payload");
    // new unpacked result buffer
    msgpack_unpacked result;
    msgpack_unpacked_init(&result);
    // unpack into result buffer and look for ARRAY
    if (msgpack_unpacker_next(unpacker, &result) && result.data.type == MSGPACK_OBJECT_ARRAY) {
        // redirect the result to the envelope
        msgpack_object *envelope = result.data.via.array.ptr;
        unsigned int p_version = 0;
        // get the envelope version
        if (envelope->type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
            p_version = (int) envelope->via.u64;
            ESP_LOGI(TAG, "VERSION: %d (variant %d)\r\n", p_version >> 4U, p_version & 0xfU);
        }
        // get the backend UUID
        if ((++envelope)->type == MSGPACK_OBJECT_RAW) {
            ESP_LOG_BUFFER_HEX_LEVEL("UUID", envelope->via.raw.ptr, (uint16_t) envelope->via.raw.size, ESP_LOG_DEBUG);
        }
        // only continue if the envelope version and variant match
        if (p_version == proto_chained) {
            // previous message signature (from our request message)
            unsigned char *last_signature = NULL;
            size_t last_signature_len;
            if (ubirch_load_signature(&last_signature, &last_signature_len) != ESP_OK) {
                ESP_LOGW(TAG, "error loading last signature");
            }
            // compare the previous signature to the received one
            bool last_signature_matches = false;
            if ((++envelope)->type == MSGPACK_OBJECT_RAW) {
                ESP_LOG_BUFFER_HEXDUMP(TAG, envelope->via.raw.ptr, (uint16_t) envelope->via.raw.size, ESP_LOG_DEBUG);
                if (envelope->via.raw.size == crypto_sign_BYTES) {
                    // if we have no last signature, accept this message, otherwise compare
                    last_signature_matches =
                            last_signature == NULL ||
                            !memcmp(last_signature, envelope->via.raw.ptr, UBIRCH_PROTOCOL_SIGN_SIZE);
                }
            }
            // only continue, if the signatures match
            if (last_signature_matches && (++envelope)->type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
                ESP_LOGI(TAG, "TYPE: %d\r\n", (unsigned int) envelope->via.u64);
                switch ((unsigned int) envelope->via.u64) {
                    case MSGPACK_MSG_REPLY:
                        parse_measurement_reply(++envelope, handler);
                        break;
                    case UBIRCH_PROTOCOL_TYPE_HSK:
                        //TODO handshake reply evaluation
                        break;
                    default:
                        ESP_LOGI(TAG, "unknown packet data type");
                        break;
                }
            } else {
                ESP_LOGW(TAG, "prev signature mismatch or message type wrong!");
            }
        } else {
            ESP_LOGW(TAG, "protocol version mismatch: %d != %d", p_version, proto_chained);
        }
    } else {
        ESP_LOGW(TAG, "empty message not accepted");
    }
    ESP_LOGI(TAG, "destroy result");
    msgpack_unpacked_destroy(&result);
}

