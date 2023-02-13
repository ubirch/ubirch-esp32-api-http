#include "unity.h"
#include "api-http-helper.h"

TEST_CASE("uuid_format", "[api-http-helper]") {
	unsigned char uuid[16] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
	};
	char buffer[37];
	TEST_ASSERT_EQUAL_INT(36, uuid_to_string(uuid, buffer, sizeof(buffer)));
	TEST_ASSERT_EQUAL_STRING("00010203-0405-0607-0809-0a0b0c0d0e0f", buffer);
}
