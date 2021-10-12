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

#include <msgpack.h>
#include <ubirch_protocol.h>

#define MSGPACK_MSG_REPLY 85
#define MSGPACK_MSG_UBIRCH 50

/*!
 * Return type for the ubirch_send function.
 */
typedef enum {
    UBIRCH_SEND_OK,
    UBIRCH_SEND_VERIFICATION_FAILED,
    UBIRCH_SEND_ERROR
} ubirch_send_err_t;

/*!
 * Send data to the ubirch backend.
 * @param url The backend url.
 * @param uuid The client uuid.
 * @param data The msgpack encoded data to send.
 * @param length The length of the data packet.
 * @param http_status The http status of the backend response.
 * @param unpacker The msgpack unpacker to feed the response to
 *        if a verifier is not given or it can verify the received data.
 * @param verifier a ubirch_protocol_check verification function or NULL
 * @return UBIRCH_SEND_OK
 *         UBIRCH_SEND_VERIFICATION_FAILED if verifier is given and verification failed
 *         UBIRCH_SEND_ERROR if any error occured
 */
ubirch_send_err_t ubirch_send(const char *url, const unsigned char *uuid, const char *data, const size_t length,
        int* http_status, msgpack_unpacker *unpacker, ubirch_protocol_check verifier);

ubirch_send_err_t ubirch_send_json(const char *url, const unsigned char *uuid, const char *data, const size_t length,
        int* http_status, msgpack_unpacker *unpacker, ubirch_protocol_check verifier);

#endif //UBIRCH_API_H
