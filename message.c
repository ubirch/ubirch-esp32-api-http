/*!
 * @file
 * @brief TODO: ${FILE}
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
#include <ubirch_protocol.h>
#include <ubirch_ed25519.h>
#include <storage.h>
#include <esp_log.h>
#include "message.h"
#include "ubirch_api.h"

static const char *TAG = "MESSAGE";

#define TIME_RES_SEC 1000


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


static uint64_t get_time_us() {
    time_t now = time(NULL);
    int64_t timer = esp_timer_get_time();
    return ((uint64_t) (now) * TIME_RES_SEC) + (((uint64_t) (timer) * TIME_RES_SEC / 1000000) % TIME_RES_SEC);
}

esp_err_t *ubirch_message(msgpack_sbuffer *sbuf, const unsigned char *uuid, int32_t *values, uint16_t num) {
    // create buffer, writer, ubirch protocol context and packer
    ubirch_protocol *proto = ubirch_protocol_new(proto_chained, MSGPACK_MSG_UBIRCH,
                                                 sbuf, msgpack_sbuffer_write, ed25519_sign, uuid);
    msgpack_packer *pk = msgpack_packer_new(proto, ubirch_protocol_write);

    // load the signature of the previously sent message and copy it to the protocol
    unsigned char *last_signature = NULL;
    size_t last_signature_len = 0;
    ubirch_load_signature(&last_signature, &last_signature_len);
    if(last_signature != NULL && last_signature_len == UBIRCH_PROTOCOL_SIGN_SIZE) {
        memcpy(proto->signature, last_signature, UBIRCH_PROTOCOL_SIGN_SIZE);
    }
    free(last_signature);

    // start the protocol
    ubirch_protocol_start(proto, pk);

    // create array[ timestamp, value1, value2 ])
    msgpack_pack_array(pk, num + 1);
    uint64_t ts = get_time_us();
    msgpack_pack_uint64(pk, ts);
    for (int i = 0; i < num; ++i) {
        msgpack_pack_int32(pk, values[i]);
    }

    // finish the protocol and then store the signature of this message
    ubirch_protocol_finish(proto, pk);

    // store signature
    ubirch_store_signature(proto->signature, UBIRCH_PROTOCOL_SIGN_SIZE);

    // free allocated ressources
    msgpack_packer_free(pk);
    ubirch_protocol_free(proto);

    ESP_LOG_BUFFER_HEXDUMP(TAG, sbuf->data, (uint16_t) sbuf->size, ESP_LOG_DEBUG);

    return ESP_OK;
}
