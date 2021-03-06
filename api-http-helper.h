//
// Created by gruenwaldi on 03.09.20.
//

#ifndef EXAMPLE_ESP32_API_HTTP_HELPER_H
#define EXAMPLE_ESP32_API_HTTP_HELPER_H

/*!
 * Encode char string to base64.
 *
 * @param char_string pointer to char array
 * @return pointer to base64 encoded string
 *
 * @note Make sure to free the memory of the return value
 */
char *str_to_base64(const char *char_string, size_t len);

#endif //EXAMPLE_ESP32_API_HTTP_HELPER_H
