/*!
 * @file    message.c
 * @brief   ubirch message parser
 *
 * ...
 *
 * @author Matthias L. Jugel
 * @date   2018-12-01
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
#include <ubirch_ed25519.h>
#include <sys/time.h>
#include <storage.h>
#include <esp_log.h>
#include "message.h"

static const char *TAG = "MESSAGE";

esp_err_t ubirch_load_signature(unsigned char **signature, size_t *len) {
    esp_err_t err;

    err = kv_load("sign_storage", "signature", (void **) signature, len);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "error loading the last signature");
    }

    return err;
}

esp_err_t ubirch_store_signature(unsigned char *signature, size_t len) {
    esp_err_t err;

    err = kv_store("sign_storage", "signature", signature, len);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "error storing the signature");
    }

    return err;
}

esp_err_t *ubirch_message(ubirch_protocol *upp, int32_t *values, uint16_t num) {
    // load the signature of the previously sent message and copy it to the protocol context
    unsigned char *last_signature = NULL;
    size_t last_signature_len = 0;
    ubirch_load_signature(&last_signature, &last_signature_len);
    if (last_signature != NULL && last_signature_len == UBIRCH_PROTOCOL_SIGN_SIZE) {
        memcpy(upp->signature, last_signature, UBIRCH_PROTOCOL_SIGN_SIZE);
    }
    free(last_signature);

    // create and initialize buffer and packer for msgpack type payload
    msgpack_sbuffer sbuf; /* buffer */
    msgpack_packer pk;    /* packer */
    msgpack_sbuffer_init(&sbuf); /* initialize buffer */
    msgpack_packer_init(&pk, &sbuf, msgpack_sbuffer_write); /* initialize packer */

    // create array[ timestamp, value1, value2 ])
    msgpack_pack_array(&pk, num + 1);
    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint64_t ts = (uint64_t) tv.tv_sec * (uint64_t) 1000000 + tv.tv_usec;

    msgpack_pack_uint64(&pk, ts);
    for (int i = 0; i < num; ++i) {
        msgpack_pack_int32(&pk, values[i]);
    }

    // create ubirch protocol message
    ubirch_protocol_message(upp, proto_chained, UBIRCH_PROTOCOL_TYPE_MSGPACK, upp->data, upp->size);

    // store signature of the new message
    ubirch_store_signature(upp->signature, UBIRCH_PROTOCOL_SIGN_SIZE);

    ESP_LOG_BUFFER_HEXDUMP(TAG, upp->data, (uint16_t) upp->size, ESP_LOG_DEBUG);

    return ESP_OK;
}
