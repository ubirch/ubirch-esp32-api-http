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
#ifndef UBIRCH_API_H
#define UBIRCH_API_H

#include <esp_err.h>
#include <msgpack.h>

#define MSGPACK_MSG_REPLY 85
#define MSGPACK_MSG_UBIRCH 50

/*!
 * Send data to the ubirch backend.
 * @param url The backend url.
 * @param data the msgpack encoded data to send
 * @param length the length of the data packet
 * @param unpacker a msgpack unpacker to feed the response to
 * @return ESP_OK or an error code
 */
esp_err_t ubirch_send(const char *url, const char *data, const size_t length, msgpack_unpacker *unpacker);

#endif //UBIRCH_API_H
