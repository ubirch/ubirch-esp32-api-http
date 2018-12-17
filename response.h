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

/*!
 * Helper function, checking a specific key in a msgpack key/value object.
 * @param kv the map
 * @param key the key we look for
 * @param type the type of the value we look for
 * @return true if the key and type match
 */
bool match(const msgpack_object_kv *kv, const char *key, int type);

#endif //API_RESPONSE_H
