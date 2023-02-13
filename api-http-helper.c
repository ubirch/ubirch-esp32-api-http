//
// Created by gruenwaldi on 03.09.20.
//

#include <mbedtls/base64.h>
#include <stdlib.h>
#include <stdio.h>
#include "api-http-helper.h"

char *str_to_base64(const char *char_string, size_t len) {
	unsigned char *str64 = NULL;
	size_t str64_len;
	mbedtls_base64_encode(str64, 0, &str64_len,
	                      (const unsigned char *) char_string, len);
	str64 = malloc(str64_len);
	mbedtls_base64_encode(str64, str64_len, &str64_len,
	                      (const unsigned char *) char_string, len);
	return (char *) str64;
}

int uuid_to_string(const unsigned char *uuid, char *buffer, size_t len) {
    return snprintf(buffer, len,
			"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
            uuid[0], uuid[1], uuid[2], uuid[3], uuid[4], uuid[5], uuid[6], uuid[7],
            uuid[8], uuid[9], uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]
    );
}

