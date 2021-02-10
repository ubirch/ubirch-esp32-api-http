/*!
 * @file    response.h
 * @brief   ubirch response parser
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
#ifndef API_RESPONSE_H
#define API_RESPONSE_H

#include <ubirch_protocol.h>

/*!
 * ubirch response handler function, which receives msgpack key/value entries to evaluate.
 */
typedef void (*ubirch_response_handler)(const msgpack_object_kv *entry);

/*!
 * Parse a msgpack response that contains a ubirch-protocol message. The function parses all relevant
 * values and verifies the signature of the message. If the verification is successful, the response
 * handler will be called with all elements received.
 *
 * @param unpacker the unpacker holding unparsed data
 * @param handler a handler for individual response values
 */
void ubirch_parse_response(msgpack_unpacker *unpacker, ubirch_response_handler handler);

/*
 * TODO: probably name it differently
 */
typedef enum {
    UBIRCH_ESP32_API_HTTP_RESPONSE_SUCCESS = 0,
    UBIRCH_ESP32_API_HTTP_RESPONSE_ERROR,
} ubirch_esp32_api_http_response_t;

/*!
 * TODO: fix name!
 */
typedef void (*ubirch_response_bin_data_handler)(const void* data, const size_t len);

/*
 * Parse a msgpack response that contains a ubirch-protocol message.
 * The function expects
 *      1. proto_chained type
 *      2. matching previous signature
 *      3. payload of binary type UBIRCH_PROTOCOL_TYPE_BIN
 * otherwise it will not call the handler on this binary data.
 *
 * @param unpacker the unpacker holding unparsed data
 * @param handler a handler for the received payload
 * @return ..._SUCCESS if the above is matched, else ..._ERROR
 */
int ubirch_parse_backend_response(msgpack_unpacker *unpacker, ubirch_response_bin_data_handler handler);

/*!
 * Helper function, checking a specific key in a msgpack key/value object.
 * @param kv the map
 * @param key the key we look for
 * @param type the type of the value we look for
 * @return true if the key and type match
 */
bool match(const msgpack_object_kv *kv, const char *key, int type);

#endif //API_RESPONSE_H
