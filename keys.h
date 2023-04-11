/*!
 * @file    keys.h
 * @brief   key helping functions
 *
 * @author Waldemar Gruenwald
 * @date   2018-10-10
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



#ifndef KEYS_H
#define KEYS_H

#include <string.h>
#include "ubirch_ed25519.h"

#ifdef __cplusplus
extern "C" {
#endif

// length of base64 string is ceil(number_of_bytes / 3) * 4
// to get ceil for value / 3 (value >= 0) we use (value + 2) / 3
#define PUBLICKEY_BASE64_STRING_LENGTH (((crypto_sign_PUBLICKEYBYTES + 2) / 3) * 4)

extern unsigned char server_pub_key[crypto_sign_PUBLICKEYBYTES];

/*!
 * @brief Create a new signature Key pair for the current ID context.
 *
 * After creating the key pair, it is packad into msgpack together with aditional
 * information, according to the structure `ubirch_key_info()`, from `ubirch_protocol_kex.h`,
 * which is part of the `ubirch-protocol` module.
 */
void create_keys(void);

/*!
 * @brief Register the Keys of the current ID context in the backend.
 *
 * @note This function can only be executed, if a network connection is available.
 * @return ESP_OK, or ESP_FAIL if error occurs.
 */
esp_err_t register_keys(void);

/*!
 * @brief Update the Keys of the current ID context in the backend.
 *
 * @note This function can only be executed, if a network connection is available.
 * @return ESP_OK, or ESP_FAIL if error occurs.
 */
esp_err_t update_keys(void);

#ifdef __cplusplus
}
#endif

#endif /* KEYS_H */
