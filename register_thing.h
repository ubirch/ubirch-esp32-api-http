/*!
 * @file    register_thing.h
 * @brief   ubirch thing registration
 *
 * ...
 *
 * @author Sven Herrmann
 * @date   2023-02-13
 *
 * @copyright &copy; 2023 ubirch GmbH (https://ubirch.com)
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
#ifndef REGISTER_THING_H
#define REGISTER_THING_H

#ifndef CONFIG_UBIRCH_REGISTER_THING
#error "UBIRCH_REGISTER_THING not enabled"
#else

typedef enum {
    UBIRCH_ESP32_REGISTER_THING_SUCCESS = 0,
    UBIRCH_ESP32_REGISTER_THING_ALREADY_REGISTERED,
    UBIRCH_ESP32_REGISTER_THING_ERROR,
} ubirch_esp32_register_thing_t;

/*!
 * Send registration request to ubirch backend.
 * If successfull, password of the id will be saved into current context.
 */
int ubirch_register_current_id(const char* device_description);

#endif // UBIRCH_REGISTER_THING
#endif // REGISTER_THING_H
