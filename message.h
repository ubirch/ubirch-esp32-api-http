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

#include <msgpack.h>

/*!
 * Store the signature in non-volatile memory to save it for the next message.
 *
 * @param signature the signature byte array
 * @param len the length of the signature
 * @return ESP_OK or an error code
 */
esp_err_t ubirch_store_signature(unsigned char *signature, size_t len);

/*!
 * Load the last stored signature from non-volatile memory.
 * This function internally allocates the memory required for the signature. Needs to be freed
 * after use.
 *
 * @param signature a pointer to the target signature pointer
 * @param len a pointer to a length variable where the loaded length is stored in
 * @return ESP_OK or an error code
 */
esp_err_t ubirch_load_signature(unsigned char **signature, size_t *len);

/*!
 * Create a new ubirch API message from the UUID and an array of sensor values.
 * This function will implicitely load the signature of the previous message and store
 * the signature of this created protocol message.
 *
 * @param sbuf a buffer structure to hold the packages data, needs to be freed after use
 * @param uuid the device UUID
 * @param values an array of values to send
 * @param num the number of values in the array
 * @return ESP_OK or an error code if the packaging failed
 */
esp_err_t *ubirch_message(msgpack_sbuffer *sbuf, const unsigned char *uuid, int32_t *values, uint16_t num);

/*!
 * TODO
 * @param sbuf
 * @param uuid
 * @param data
 * @return
 */
esp_err_t *ubirch_message_niomon(msgpack_sbuffer *sbuf, const unsigned char *uuid, const unsigned char *data);


#endif //UBIRCH_API_MESSAGE_H
