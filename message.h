/*!
 * @file    message.h
 * @brief   ubirch message parser.
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
#ifndef UBIRCH_API_MESSAGE_H
#define UBIRCH_API_MESSAGE_H

#include <esp_err.h>
#include <msgpack.h>
#include <ubirch_protocol.h>

/*!
 * Create a new ubirch API message from the UUID and an array of sensor values.
 * This function will implicitely load the signature of the previous message and store
 * the signature of this created protocol message.
 *
 * @param upp a buffer structure to hold the packages data, needs to be freed after use
 * @param uuid the device UUID
 * @param values an array of values to send
 * @param num the number of values in the array
 * @return ESP_OK or an error code if the packaging failed
 */
esp_err_t *ubirch_message(ubirch_protocol *upp, int32_t *values, uint16_t num);

#endif //UBIRCH_API_MESSAGE_H
