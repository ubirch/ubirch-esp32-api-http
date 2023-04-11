/*!
 * @file    keys.c
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


#include <stdio.h>
#include <string.h>
#include <esp_err.h>
#include <time.h>
#include <esp_log.h>
#include <ubirch_api.h>

#include "ubirch_ed25519.h"
#include "ubirch_protocol_kex.h"
#include "ubirch_protocol.h"

#include "id_handling.h"
#include "keys.h"

#include <mbedtls/base64.h>

//#define LOG_LOCAL_LEVEL ESP_LOG_DEBUG

#define KEY_LIFETIME_IN_SECONDS (60 * 60 * 24 * 365 * CONFIG_UBIRCH_KEY_LIFETIME_YEARS)
#define KEY_UPDATE_BEFORE_EXPIRE_IN_SECONDS (60 * 60 * 24 * 7) // one week

#define STR(x) #x
#define VALUE_STRING(x) STR(x)
#pragma message ("Key lifetime at creation and update is set to " \
        VALUE_STRING(CONFIG_UBIRCH_KEY_LIFETIME_YEARS) " year(s)")

#define BYTES_LENGTH_TO_BASE64_STRING_LENGTH(__len) (((__len + 2) / 3) * 4)

static const char *TAG = "KEY_HANDLING";

/*!
 * Create a new signature Key pair for the current ID context
 */
void create_keys(void) {
    ESP_LOGI(TAG, "create keys");
    // create the key pair
    unsigned char secret_key[crypto_sign_SECRETKEYBYTES];
    unsigned char public_key[crypto_sign_PUBLICKEYBYTES];
    crypto_sign_keypair(public_key, secret_key);
    ESP_LOGD(TAG, "publicKey");
    ESP_LOG_BUFFER_HEX_LEVEL(TAG, (const char *) (public_key), crypto_sign_PUBLICKEYBYTES, ESP_LOG_DEBUG);

    ubirch_public_key_set(public_key, sizeof(public_key));
    ubirch_secret_key_set(secret_key, sizeof(secret_key));

    unsigned char* uuid = NULL;
    size_t uuid_len = 0;
    ubirch_uuid_get(&uuid, &uuid_len);

    // create key registration info
    ubirch_key_info info = {};
    info.algorithm = (char *) (UBIRCH_KEX_ALG_ECC_ED25519);
    info.created = (unsigned int) time(NULL);                           // current time of the system
    memcpy(info.hwDeviceId, uuid, uuid_len);                        // 16 Byte unique hardware device ID
    memcpy(info.pubKey, public_key, sizeof(public_key));// the public key
    info.validNotAfter = (unsigned int) (time(NULL) +
                                         KEY_LIFETIME_IN_SECONDS);      // time until the key will be valid (now + 1 year)
    info.validNotBefore = (unsigned int) time(NULL);                    // time from when the key will be valid (now)

    // create protocol context
    ubirch_protocol *upp = ubirch_protocol_new(uuid, ed25519_sign);

    // create the certificate for the key pair
    ubirch_protocol_message(upp, proto_signed, UBIRCH_PROTOCOL_TYPE_REG, (const char *) &info, sizeof(info));

    // store certificate in flash
    if (ubirch_certificate_store(upp->data, upp->size) != ESP_OK) {
        ESP_LOGW(TAG, "key certificate could not be stored in flash");
    }

    // free allocated resources
    ubirch_protocol_free(upp);

    ubirch_id_state_set(UBIRCH_ID_STATE_KEYS_CREATED, true);
    ubirch_id_state_set(UBIRCH_ID_STATE_KEYS_REGISTERED, false);
    ubirch_next_key_update_set(info.validNotAfter - KEY_UPDATE_BEFORE_EXPIRE_IN_SECONDS);
}


/*!
 * Register the Keys of the current ID context in the backend.
 */
esp_err_t register_keys(void) {
    ESP_LOGI(TAG, "register identity");

    msgpack_sbuffer *sbuf = msgpack_sbuffer_new();

    ESP_LOGD(TAG, "sbuf size: %d", (int)sbuf->size);

    if (ubirch_certificate_load(&sbuf->data, &sbuf->size) != ESP_OK) {
        ESP_LOGE(TAG, "error loaded certificate");
        msgpack_sbuffer_free(sbuf);
        return ESP_FAIL;
    }
    ESP_LOGD(TAG, "sbuf size: %d", (int)sbuf->size);
    ESP_LOG_BUFFER_HEX_LEVEL(TAG, (const char *) (sbuf->data), sbuf->size, ESP_LOG_DEBUG);

    unsigned char* uuid = NULL;
    size_t uuid_len = 0;
    ubirch_uuid_get(&uuid, &uuid_len);

    // send the data
    // TODO: verify response
    int http_status;
    esp_err_t ret = ESP_FAIL;
    if (ubirch_send(CONFIG_UBIRCH_BACKEND_KEY_SERVER_URL, uuid, sbuf->data, sbuf->size, &http_status, NULL, NULL)
            == UBIRCH_SEND_OK) {
        if (http_status == 200) {
            ESP_LOGI(TAG, "successfull sent registration");
            ubirch_id_state_set(UBIRCH_ID_STATE_KEYS_REGISTERED, true);
            if (ubirch_certificate_remove()) {
                ESP_LOGW(TAG, "unable to delete certificate");
            }
            ret = ESP_OK;
        } else {
            ESP_LOGE(TAG, "unable to send registration (%d)", http_status);
        }
    } else {
        ESP_LOGE(TAG, "error while sending registration");
    }
    msgpack_sbuffer_free(sbuf);
    return ret;
}


/*!
 * Update the Keys of the current ID context in the backend.
 */
esp_err_t update_keys(void) {
    // get time information
    time_t now = time(NULL);

    // create new keys
    unsigned char new_ed25519_secret_key[crypto_sign_SECRETKEYBYTES] = {};
    unsigned char new_ed25519_public_key[crypto_sign_PUBLICKEYBYTES] = {};
    crypto_sign_keypair(new_ed25519_public_key, new_ed25519_secret_key);

    // convert keys into base64 format
    unsigned char* ed25519_public_key_old = NULL;
    size_t len = 0;
    if (ubirch_public_key_get(&ed25519_public_key_old, &len)) {
        ESP_LOGW(TAG, "failed to load old pub");
        return ESP_FAIL;
    }
    char old_pubKey[BYTES_LENGTH_TO_BASE64_STRING_LENGTH(crypto_sign_PUBLICKEYBYTES) + 1];
    unsigned int outputlen = 0;
    if (mbedtls_base64_encode((unsigned char*)old_pubKey, sizeof(old_pubKey),
                &outputlen, ed25519_public_key_old, len) != 0) {
        ESP_LOGW(TAG, "failed to convert old pub key to base64");
        return ESP_FAIL;
    }
    char new_pubKey[BYTES_LENGTH_TO_BASE64_STRING_LENGTH(crypto_sign_PUBLICKEYBYTES) + 1];
    outputlen = 0;
    if (mbedtls_base64_encode((unsigned char*)new_pubKey, sizeof(new_pubKey),
                &outputlen, new_ed25519_public_key, crypto_sign_PUBLICKEYBYTES) != 0) {
        ESP_LOGW(TAG, "failed to convert new pub key to base64");
        return ESP_FAIL;
    }

    unsigned char* uuid = NULL;
    size_t uuid_len = 0;
    ubirch_uuid_get(&uuid, &uuid_len);

    // build update json string
    ubirch_update_key_info update_info = {
        .algorithm = UBIRCH_KEX_ALG_ECC_ED25519,
        .created = now,
        .hwDeviceId = uuid,
        .pubKey = new_pubKey,
        .prevPubKeyId = old_pubKey,
        .validNotAfter = now + KEY_LIFETIME_IN_SECONDS,
        .validNotBefore = now
    };

    ESP_LOGD(TAG, "validNotBefore: %ld", update_info.validNotBefore);
    ESP_LOGD(TAG, "validNotAfter: %ld", update_info.validNotAfter);

    // init with outer brace
    char json_string[610] = "{\"pubKeyInfo\":";
    char *inner_json_string = json_string + strlen(json_string);
    size_t inner_json_string_size = json_pack_key_update(&update_info, inner_json_string,
            sizeof(json_string) - strlen(json_string));
    ESP_LOGD(TAG, "inner json string size: %d", inner_json_string_size);
    ESP_LOGD(TAG, "inner json string: %s", inner_json_string);

    // sign json with old key
    unsigned char signature_old[crypto_sign_BYTES];
    if (ed25519_sign((unsigned char*)inner_json_string, inner_json_string_size, signature_old) != 0) {
        ESP_LOGW(TAG, "failed to sign with old key");
        return ESP_FAIL;
    }
    char signature_old_base64[BYTES_LENGTH_TO_BASE64_STRING_LENGTH(crypto_sign_BYTES) + 1];
    outputlen = 0;
    if (mbedtls_base64_encode((unsigned char*)signature_old_base64, sizeof(signature_old_base64),
                &outputlen, signature_old, crypto_sign_BYTES) != 0) {
        ESP_LOGW(TAG, "failed to convert signature to base64");
        return ESP_FAIL;
    }
    // sign json with new key
    unsigned char signature_new[crypto_sign_BYTES];
    if (ed25519_sign_key((unsigned char*)inner_json_string, inner_json_string_size, signature_new,
                new_ed25519_secret_key) != 0) {
        ESP_LOGW(TAG, "failed to sign with new key");
        return ESP_FAIL;
    }
    char signature_new_base64[BYTES_LENGTH_TO_BASE64_STRING_LENGTH(crypto_sign_BYTES) + 1];
    outputlen = 0;
    if (mbedtls_base64_encode((unsigned char*)signature_new_base64, sizeof(signature_new_base64),
                &outputlen, signature_new, crypto_sign_BYTES) != 0) {
        ESP_LOGW(TAG, "failed to convert signature to base64");
        return ESP_FAIL;
    }
    // add signatures to json string
    char *string_index = inner_json_string + inner_json_string_size;
    string_index += sprintf(string_index, ",\"signature\":\"%s\",\"prevSignature\":\"%s\"}",
            signature_new_base64, signature_old_base64);
    size_t json_string_size = string_index - json_string;
    ESP_LOGD(TAG, "update key json length: %d", json_string_size);
    ESP_LOGD(TAG, "update key json: %s", json_string);

    // send data
    int http_status;
    if (ubirch_send_json(CONFIG_UBIRCH_BACKEND_UPDATE_KEY_SERVER_URL, uuid,
                json_string, json_string_size, &http_status, NULL, NULL)
            == UBIRCH_SEND_OK) {
        if (http_status == 200) {
            ESP_LOGI(TAG, "successfull sent key update");
            if (ubirch_public_key_set(new_ed25519_public_key, crypto_sign_PUBLICKEYBYTES) != ESP_OK
                    || ubirch_secret_key_set(new_ed25519_secret_key, crypto_sign_SECRETKEYBYTES) != ESP_OK) {
                ESP_LOGW(TAG, "failed to set new key pair after registration");
                return ESP_FAIL;
            }
        } else {
            ESP_LOGW(TAG, "unable to send key update, http response is: %d", http_status);
            return ESP_FAIL;
        }
    } else {
        ESP_LOGW(TAG, "error while sending key update");
        return ESP_FAIL;
    }

    ubirch_id_state_set(UBIRCH_ID_STATE_KEYS_CREATED, true);
    ubirch_id_state_set(UBIRCH_ID_STATE_KEYS_REGISTERED, true);
    ubirch_next_key_update_set(update_info.validNotAfter - KEY_UPDATE_BEFORE_EXPIRE_IN_SECONDS);

    return ESP_OK;
}
