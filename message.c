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
#include <ubirch_protocol.h>
#include <ubirch_ed25519.h>
#include <sys/time.h>
#include <storage.h>
#include <esp_log.h>
#include "message.h"
#include "api-http-helper.h"
#include "id_handling.h"

//#define LOG_LOCAL_LEVEL ESP_LOG_DEBUG

static const char *TAG = "MESSAGE";

esp_err_t *ubirch_message(ubirch_protocol *upp, int32_t *values, uint16_t num) {
    // load the signature of the previously sent message and copy it to the protocol context
    unsigned char *last_signature = NULL;
    size_t last_signature_len = 0;
    ubirch_previous_signature_get(&last_signature, &last_signature_len);
    if (last_signature != NULL && last_signature_len == UBIRCH_PROTOCOL_SIGN_SIZE) {
        memcpy(upp->signature, last_signature, UBIRCH_PROTOCOL_SIGN_SIZE);
    }

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

	// make a hash of the payload
	unsigned char sha512sum[UBIRCH_PROTOCOL_SIGN_SIZE];
	mbedtls_sha512((const unsigned char *) sbuf.data, sbuf.size, sha512sum, 0);

	char *base64_hash = str_to_base64((const char *) sha512sum, UBIRCH_PROTOCOL_SIGN_SIZE);
	ESP_LOGI("HASH","%s",base64_hash);
	free(base64_hash);

	// create ubirch protocol message
    ubirch_protocol_message(upp, proto_chained, UBIRCH_PROTOCOL_TYPE_BIN, (const char *)sha512sum, UBIRCH_PROTOCOL_SIGN_SIZE);

    // destroy the buffers
	msgpack_sbuffer_destroy(&sbuf);

    // store signature of the new message
    ubirch_previous_signature_set(upp->signature, UBIRCH_PROTOCOL_SIGN_SIZE);
    ubirch_id_context_store();

    ESP_LOG_BUFFER_HEXDUMP(TAG, upp->data, (uint16_t) upp->size, ESP_LOG_DEBUG);

    return ESP_OK;
}
