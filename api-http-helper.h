/*!
 * @file api-http-helper.h 
 * @brief Helper function for HTTP API
 * 
 * @author Waldemar Gruenwald
 * @date 2020-09-03
 * @copyright Ubirch GmbH 2020
 * 
 * @note the uuid functionmality is based on https://tools.ietf.org/html/rfc4122
 */

#ifndef EXAMPLE_ESP32_API_HTTP_HELPER_H
#define EXAMPLE_ESP32_API_HTTP_HELPER_H

#include "copyrt.h"

#define UUID_SIZ 16
#define UUID_STR_SIZ 37

typedef unsigned char uuid_t[UUID_SIZ];


/*!
 * @brief Encode char string to base64.
 *
 * @param char_string pointer to char array
 * @return pointer to base64 encoded string
 *
 * @note Make sure to free the memory of the return value
 */
char *str_to_base64(const char *char_string, size_t len);

/*!
 * Write 16 byte uuid into string (XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX).
 *
 * @param uuid uuid bytes
 * @param buffer buffer to write uuid in stringform
 * @param len len of buffer
 */
int uuid_to_string(const uuid_t uuid, char *buffer, size_t len);

/*!
 * @brief create UUID V5 from Namespace ('ns') and Name
 *
 * @param [out] p_uuid pointer to uuid, which will be filled with generated UUID
 * @param [in] ns Namespace String for the first step of UUID generation
 * @param [in] ns_len length of the Namespace String
 * @param [in] name Name String for the second step of UUID generation
 * @param [in] name_len length of the Name String 
 * 
 * @return ESP_OK, or ESP_FAIL if input paremeters NULL/0
 */
esp_err_t uuid_v5_create_from_name(uuid_t *p_uuid, char *ns, size_t ns_len, char *name, size_t name_len);

/*!
 * @brief create UUID V5 from Namespace ('ns'), derived Namespace (`der_ns`) and Name
 *
 * @param [out] p_uuid pointer to uuid, which will be filled with generated UUID
 * @param [in] ns Namespace String for the first step of UUID generation
 * @param [in] ns_len length of the Namespace String
 * @param [in] der_ns derived Namespace String for the second step of UUID generation
 * @param [in] der_ns_len length of the derived Namespace String
 * @param [in] name Name String for the third step of UUID generation
 * @param [in] name_len length of the Name String 
 * 
 * @return ESP_OK, or ESP_FAIL if input paremeters NULL/0
 */
esp_err_t uuid_v5_create_derived_from_name(uuid_t *p_uuid, char *ns, size_t ns_len, char *der_ns, size_t der_ns_len, char *name, size_t name_len);

#endif //EXAMPLE_ESP32_API_HTTP_HELPER_H
