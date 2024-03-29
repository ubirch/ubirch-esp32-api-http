#include "unity.h"

// load from compilation unit to be able to check static functions
#include "register_thing.c"

TEST_CASE("request json object", "[register_thing]") {
    unsigned char uuid[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    char* description = "hello world";
    const size_t data_len = UBIRCH_REGISTER_THING_JSON_OBJECT_SIZE + strlen(description);
    char* string_buffer = malloc(data_len);
    // note: build_post_json_object returns number of characters written without terminatin zero
    TEST_ASSERT_EQUAL_INT(data_len - 1, build_post_json_object(uuid, description, string_buffer, data_len));
    TEST_ASSERT_EQUAL_STRING(
            "{\"hwDeviceId\":\"00010203-0405-0607-0809-0a0b0c0d0e0f\",\"description\":\"hello world\"}",
            string_buffer);
}

TEST_CASE("parse api info", "[register_thing]") {
    unsigned char uuid[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    char* json = "[{\"00010203-0405-0607-0809-0a0b0c0d0e0f\":{\"state\":\"ok\",\"apiConfig\":{\"password\":\"abcdef12-0011-4dce-9022-012345678901\",\"keyService\":\"https://key.prod.ubirch.com/api/keyService/v1/pubkey/mpack\",\"niomon\":\"https://niomon.prod.ubirch.com/\",\"data\":\"https://data.prod.ubirch.com/v1/msgPack\"}}}]";
    char password_buffer[37];
    TEST_ASSERT_EQUAL_INT(ESP_OK, parse_api_info(uuid, json, strlen(json),
                password_buffer, sizeof(password_buffer)));
    TEST_ASSERT_EQUAL_STRING("abcdef12-0011-4dce-9022-012345678901", password_buffer);

    // try with slightly modified json string (some newlines and spaces)
    json = "[\n{\n\"00010203-0405-0607-0809-0a0b0c0d0e0f\":  {\n\"state\": \"ok\",\n\"apiConfig\":{\"password\":  \"abcdef12-0011-4dce-9022-012345678901\",\"keyService\":\"https://key.prod.ubirch.com/api/keyService/v1/pubkey/mpack\",\"niomon\":\"https://niomon.prod.ubirch.com/\",\"data\":\"https://data.prod.ubirch.com/v1/msgPack\"}}}]";
    TEST_ASSERT_EQUAL_INT(ESP_OK, parse_api_info(uuid, json, strlen(json),
                password_buffer, sizeof(password_buffer)));
    TEST_ASSERT_EQUAL_STRING("abcdef12-0011-4dce-9022-012345678901", password_buffer);

    json = "[{\"00010203-0405-0607-0809-0a0b0c0d0e0f\":{\"password\":\"abcdef12-0011-4dce-9022-012345678901\",\"keyService\":\"https://key.prod.ubirch.com/api/keyService/v1/pubkey/mpack\",\"niomon\":\"https://niomon.prod.ubirch.com/\",\"data\":\"https://data.prod.ubirch.com/v1/msgPack\"}}]";
    TEST_ASSERT_EQUAL_INT(ESP_OK, parse_api_info(uuid, json, strlen(json),
                password_buffer, sizeof(password_buffer)));
    TEST_ASSERT_EQUAL_STRING("abcdef12-0011-4dce-9022-012345678901", password_buffer);

    // some failing requests
    // broken json: last closing "]" missing
    json = "[{\"00010203-0405-0607-0809-0a0b0c0d0e0f\":{\"password\":\"abcdef12-0011-4dce-9022-012345678901\",\"keyService\":\"https://key.prod.ubirch.com/api/keyService/v1/pubkey/mpack\",\"niomon\":\"https://niomon.prod.ubirch.com/\",\"data\":\"https://data.prod.ubirch.com/v1/msgPack\"}}";
    // buffer too small
    TEST_ASSERT_EQUAL_INT(ESP_FAIL, parse_api_info(uuid, json, strlen(json),
                password_buffer, sizeof(password_buffer) - 1));
    // json parsing fails
    TEST_ASSERT_EQUAL_INT(ESP_FAIL, parse_api_info(uuid, json, strlen(json),
                password_buffer, sizeof(password_buffer)));
    // unexpected json: includes more than one element in array
    json = "[{\"00010203-0405-0607-0809-0a0b0c0d0e0f\":{\"password\":\"abcdef12-0011-4dce-9022-012345678901\",\"keyService\":\"https://key.prod.ubirch.com/api/keyService/v1/pubkey/mpack\",\"niomon\":\"https://niomon.prod.ubirch.com/\",\"data\":\"https://data.prod.ubirch.com/v1/msgPack\"}}, {\"00010203-0405-0607-0809-0a0b0c0d0e0g\":{\"password\":\"abcdef12-0011-4dce-9022-012345678901\",\"keyService\":\"https://key.prod.ubirch.com/api/keyService/v1/pubkey/mpack\",\"niomon\":\"https://niomon.prod.ubirch.com/\",\"data\":\"https://data.prod.ubirch.com/v1/msgPack\"}}]";
    TEST_ASSERT_EQUAL_INT(ESP_FAIL, parse_api_info(uuid, json, strlen(json),
                password_buffer, sizeof(password_buffer)));
    // unexpected json: unexpected uuid
    json = "[{\"a0010203-0405-0607-0809-0a0b0c0d0e0f\":{\"password\":\"abcdef12-0011-4dce-9022-012345678901\",\"keyService\":\"https://key.prod.ubirch.com/api/keyService/v1/pubkey/mpack\",\"niomon\":\"https://niomon.prod.ubirch.com/\",\"data\":\"https://data.prod.ubirch.com/v1/msgPack\"}}]";
    TEST_ASSERT_EQUAL_INT(ESP_FAIL, parse_api_info(uuid, json, strlen(json),
                password_buffer, sizeof(password_buffer)));
    // unexpected json: state is not ok
    json = "[{\"00010203-0405-0607-0809-0a0b0c0d0e0f\":{\"state\":\"foo\",\"apiConfig\":{\"password\":\"abcdef12-0011-4dce-9022-012345678901\",\"keyService\":\"https://key.prod.ubirch.com/api/keyService/v1/pubkey/mpack\",\"niomon\":\"https://niomon.prod.ubirch.com/\",\"data\":\"https://data.prod.ubirch.com/v1/msgPack\"}}}]";
    TEST_ASSERT_EQUAL_INT(ESP_FAIL, parse_api_info(uuid, json, strlen(json),
                password_buffer, sizeof(password_buffer)));
    // unexpected json: no apiConfig
    json = "[{\"00010203-0405-0607-0809-0a0b0c0d0e0f\":{\"state\":\"ok\",\"fooConfig\":{\"password\":\"abcdef12-0011-4dce-9022-012345678901\",\"keyService\":\"https://key.prod.ubirch.com/api/keyService/v1/pubkey/mpack\",\"niomon\":\"https://niomon.prod.ubirch.com/\",\"data\":\"https://data.prod.ubirch.com/v1/msgPack\"}}}]";
    TEST_ASSERT_EQUAL_INT(ESP_FAIL, parse_api_info(uuid, json, strlen(json),
                password_buffer, sizeof(password_buffer)));
    // unexpected json: wrong niomon url
    json = "[{\"00010203-0405-0607-0809-0a0b0c0d0e0f\":{\"state\":\"ok\",\"apiConfig\":{\"password\":\"abcdef12-0011-4dce-9022-012345678901\",\"keyService\":\"https://key.prod.ubirch.com/api/keyService/v1/pubkey/mpack\",\"niomon\":\"https://niomon.foo.ubirch.com/\",\"data\":\"https://data.prod.ubirch.com/v1/msgPack\"}}}]";
    TEST_ASSERT_EQUAL_INT(ESP_FAIL, parse_api_info(uuid, json, strlen(json),
                password_buffer, sizeof(password_buffer)));
    // unexpected json: no password
    json = "[{\"00010203-0405-0607-0809-0a0b0c0d0e0f\":{\"state\":\"ok\",\"apiConfig\":{\"spamword\":\"abcdef12-0011-4dce-9022-012345678901\",\"keyService\":\"https://key.prod.ubirch.com/api/keyService/v1/pubkey/mpack\",\"niomon\":\"https://niomon.prod.ubirch.com/\",\"data\":\"https://data.prod.ubirch.com/v1/msgPack\"}}}]";
    TEST_ASSERT_EQUAL_INT(ESP_FAIL, parse_api_info(uuid, json, strlen(json),
                password_buffer, sizeof(password_buffer)));
    // unexpected json: password buffer too small
    json = "[{\"00010203-0405-0607-0809-0a0b0c0d0e0f\":{\"state\":\"ok\",\"apiConfig\":{\"password\":\"abcdef12-0011-4dce-9022-012345678901spamspamspam\",\"keyService\":\"https://key.prod.ubirch.com/api/keyService/v1/pubkey/mpack\",\"niomon\":\"https://niomon.prod.ubirch.com/\",\"data\":\"https://data.prod.ubirch.com/v1/msgPack\"}}}]";
    TEST_ASSERT_EQUAL_INT(ESP_FAIL, parse_api_info(uuid, json, strlen(json),
                password_buffer, sizeof(password_buffer)));
}
