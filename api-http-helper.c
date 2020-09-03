//
// Created by gruenwaldi on 03.09.20.
//

#include <mbedtls/base64.h>
#include <stdlib.h>
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

