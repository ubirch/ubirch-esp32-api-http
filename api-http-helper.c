//
// Created by gruenwaldi on 03.09.20.
//
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <mbedtls/base64.h>
#include <mbedtls/sha1.h>

#include <esp_err.h>

#include "api-http-helper.h"

/*!
 * @brief format_uuid_v3or5 -- make a UUID from a (pseudo)random 128-bit
   number */
static void format_uuid_v3or5(uuid_t *p_uuid, unsigned char hash[16], int v)
{
	/* convert UUID to local byte order */
	memcpy(*p_uuid, hash, sizeof(*p_uuid));
	
	/* put in the variant and version bits */
	(*p_uuid)[6] &= 0x0F; 		/*< first clear the version field */
	(*p_uuid)[6] |= (v << 4); 	/*< set the verion field*/
	(*p_uuid)[8] &= 0x3F;	 	/*< clear the variant bits*/
	(*p_uuid)[8] |= 0x80;		/*< set the variant bit*/
}

/*!
 * @brief create a version 5 UUID based on SHA-1, `ns` and `name`
 * 
 * @param [out] p_uuid pointer to uuid, where the resulting UUID will be stored into
 * @param [in] nsid ns id, is the UUID of the ns
 * @param [in] name pointer to the name from which to generate a UUID
 * @param [in] name_len length of the name 
 */
static void uuid_create_sha1_from_name (uuid_t *p_uuid, uuid_t nsid, char *name, size_t name_len) {
	mbedtls_sha1_context c;
	unsigned char hash[20];

	mbedtls_sha1_init(&c);
	mbedtls_sha1_starts_ret(&c);
	mbedtls_sha1_update_ret(&c, (const unsigned char *) nsid, sizeof(uuid_t));
	mbedtls_sha1_update_ret(&c, (const unsigned char *) name, name_len);
	mbedtls_sha1_finish_ret(&c, hash);

	// /* the hash is in network byte order at this point */
	format_uuid_v3or5(p_uuid, hash, 5);
}

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

int uuid_to_string(const uuid_t uuid, char *buffer, size_t len) {
    return snprintf(buffer, len,
			"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
            uuid[0], uuid[1], uuid[2], uuid[3], uuid[4], uuid[5], uuid[6], uuid[7],
            uuid[8], uuid[9], uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]
    );
}

esp_err_t uuid_v5_create_from_name(uuid_t *p_uuid, char *ns, size_t ns_len, char *name, size_t name_len) {
	uuid_t nil_uuid = {0};
	uuid_t ns_uuid;
	uuid_t device_uuid;

	if (p_uuid == NULL || ns == NULL || name == NULL)
		return ESP_FAIL;
	if (name_len == 0 || ns_len == 0)
		return ESP_FAIL;

	uuid_create_sha1_from_name((uuid_t *)&ns_uuid, nil_uuid, ns, ns_len);
	uuid_create_sha1_from_name((uuid_t *)&device_uuid, ns_uuid, name, name_len);

	memcpy(*p_uuid, device_uuid, sizeof(*p_uuid));

	return ESP_OK;
}

esp_err_t uuid_v5_create_derived_from_name(uuid_t *p_uuid, char *ns, size_t ns_len, char *der_ns, size_t der_ns_len, char *name, size_t name_len) {
 	uuid_t nil_uuid = {0};
	uuid_t ns_uuid;
	uuid_t der_ns_uuid;
    uuid_t der_device_uuid;

	if (p_uuid == NULL || ns == NULL || der_ns == NULL || name == NULL)
		return ESP_FAIL;
	if (name_len == 0 || ns_len == 0 || der_ns_len == 0)
		return ESP_FAIL;

	uuid_create_sha1_from_name((uuid_t *)&ns_uuid, nil_uuid, ns, ns_len);
	uuid_create_sha1_from_name((uuid_t *)&der_ns_uuid, ns_uuid, der_ns, der_ns_len);
	uuid_create_sha1_from_name((uuid_t *)&der_device_uuid, der_ns_uuid, name, name_len);

	memcpy(*p_uuid, der_device_uuid, sizeof(*p_uuid));

	return ESP_OK;
}

