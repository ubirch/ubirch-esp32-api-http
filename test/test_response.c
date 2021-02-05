#include "unity.h"
#include <msgpack.h>
//#define LOG_LOCAL_LEVEL ESP_LOG_DEBUG
#include <esp_log.h>
#include "response.h"
#include "message.h"
#include "storage.h"
#include "ubirch_protocol.h"
#include <ubirch_ed25519.h>

static const char *TAG = "UBIRCH API TEST RESPONSE";

//
#define PREVIOUS_SIGNATURE_START (4 + 16 + 2)

// test signing key
unsigned char test_ed25519_public_key[] = {
        0x2f, 0x17, 0xc2, 0x3a, 0x62, 0x6d, 0x4e, 0x78,
        0x04, 0xde, 0x1d, 0xb1, 0x96, 0x91, 0x93, 0x9c,
        0xe7, 0xe9, 0x7e, 0xe1, 0x5c, 0xcd, 0x94, 0x25,
        0x4a, 0xb3, 0xde, 0xea, 0xd9, 0x7c, 0xfe, 0x22
};

// "backend signing key"
unsigned char server_public_key[] = {
    0xef, 0x80, 0x48, 0xad, 0x06, 0xc0, 0x28, 0x5a,
    0xf0, 0x17, 0x70, 0x09, 0x38, 0x18, 0x30, 0xc4,
    0x6c, 0xec, 0x02, 0x5d, 0x01, 0xd8, 0x60, 0x85,
    0xe7, 0x5a, 0x4f, 0x00, 0x41, 0xc2, 0xe6, 0x90
};


void response_handler(const void* data, const size_t len) {
    ESP_LOGD(TAG, " response handler called");
    ESP_LOG_BUFFER_HEXDUMP("response handler data", data, len, ESP_LOG_DEBUG);
}

static int ed25519_verify_test0(const unsigned char *data, size_t len,
        const unsigned char signature[UBIRCH_PROTOCOL_SIGN_SIZE]) {
    return ed25519_verify_key(data, len, signature, test_ed25519_public_key);
}

static int ed25519_verify_test1(const unsigned char *data, size_t len,
        const unsigned char signature[UBIRCH_PROTOCOL_SIGN_SIZE]) {
    return ed25519_verify_key(data, len, signature, server_public_key);
}

int test_ubirch_parse_backend_response(char* data, size_t len, ubirch_protocol_check verify) {
    // verify signature
    // NOTE: this doesn't test any functionality implemented here...
    // TODO: mock esp_http_client so the verification inside ubirch_send can be tested
    TEST_ASSERT_EQUAL_INT(0, ubirch_protocol_verify(data, len, verify));

    // feed data to unpacker
    msgpack_unpacker* unpacker = msgpack_unpacker_new(1024);
    memcpy(msgpack_unpacker_buffer(unpacker), data, len);
    msgpack_unpacker_buffer_consumed(unpacker, len);

    // test message
    int ret = ubirch_parse_backend_response(unpacker, response_handler);

    msgpack_unpacker_free(unpacker);

    return ret;
}

TEST_CASE("simple", "[response]")
{
    // data0 signed with test_ed25519_public_key
    char data0[] = {
        0x96, 0x23,
        // bin uuid
        0xc4, 0x10, 0x52, 0x7d, 0x17, 0x68,
        0xd5, 0x11, 0x47, 0x3e, 0x93, 0x39, 0x29, 0x90,
        0x5c, 0x11, 0xf5, 0xe0,
        // bin prev sig
        0xc4, 0x40, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // bin data
        0xc4,
        0x40, 0x41, 0x5d, 0xfc, 0xa4, 0xdd, 0xec, 0x2f,
        0x77, 0x7d, 0xd4, 0xa1, 0xca, 0xd6, 0x5a, 0x77,
        0x0d, 0xf8, 0x84, 0x67, 0x78, 0x17, 0x61, 0xcd,
        0x60, 0x21, 0xd6, 0xc5, 0x66, 0x67, 0x0c, 0x50,
        0x23, 0x8c, 0x85, 0x94, 0xda, 0x88, 0x84, 0xe3,
        0xd7, 0x4b, 0xb1, 0x23, 0xbe, 0x6b, 0xb2, 0x74,
        0xd8, 0x85, 0x34, 0xf9, 0x85, 0x3d, 0xb7, 0xc2,
        0xa1, 0xc1, 0x2d, 0x53, 0xeb, 0xfa, 0x22, 0xf7,
        0xbe,
        // bin signature
        0xc4, 0x40, 0xda, 0x31, 0xfa, 0xc8, 0xd6,
        0x03, 0xee, 0x2b, 0x30, 0xec, 0x09, 0x71, 0x20,
        0x64, 0xca, 0x37, 0xa9, 0xfe, 0x5f, 0x43, 0x88,
        0x7f, 0x7b, 0x83, 0x9b, 0x64, 0x3e, 0x10, 0x52,
        0x93, 0x59, 0xca, 0xb4, 0xd8, 0xb7, 0x5d, 0x7c,
        0x88, 0x23, 0x3b, 0x6e, 0x29, 0xec, 0x05, 0xcf,
        0xb9, 0xa2, 0x2b, 0x39, 0x8f, 0xbf, 0x74, 0x49,
        0x0b, 0x77, 0x37, 0x18, 0x14, 0x26, 0x32, 0xe1,
        0x9b, 0xcc, 0x07
    };

    // data1 signed with server_public_key
    char data1[] = {
        0x96, 0x23,
        // bin uuid
        0xc4, 0x10, 0x10, 0xb2, 0xe1, 0xa4,
        0x56, 0xb3, 0x4f, 0xff, 0x9a, 0xda, 0xcc, 0x8c,
        0x20, 0xf9, 0x30, 0x16,
        // bin prev sig
        0xc4, 0x40, 0x54, 0x7f,
        0x8b, 0x7c, 0x78, 0x33, 0x76, 0x79, 0x5f, 0x93,
        0x4f, 0xcd, 0x29, 0xff, 0x24, 0xfd, 0xe8, 0x99,
        0x23, 0x83, 0x51, 0xaa, 0xe1, 0xf4, 0x5d, 0x62,
        0x17, 0x5c, 0xcc, 0x3f, 0xdf, 0xf8, 0xc0, 0xde,
        0x20, 0x6b, 0xa4, 0x81, 0xb9, 0x3f, 0xd2, 0x79,
        0x8c, 0x75, 0xcf, 0xe4, 0xc9, 0xca, 0xef, 0xdf,
        0x3c, 0x40, 0x11, 0x54, 0x5e, 0xe6, 0x8f, 0xc5,
        0x14, 0x60, 0x72, 0xae, 0xc6, 0x03, 0x00,
        // bin payload
        0xc4,
        0x10, 0xd4, 0x2c, 0x07, 0x33, 0x84, 0x2c, 0x49,
        0x7c, 0x96, 0x60, 0x81, 0xaf, 0xfa, 0x96, 0xdf,
        0x82,
        // bin signature
        0xc4, 0x40, 0x55, 0xe3, 0x21, 0x2b, 0xab,
        0xb8, 0xc4, 0xde, 0xba, 0xb4, 0x6d, 0x77, 0xb6,
        0x0f, 0x2e, 0x27, 0xb9, 0x1f, 0xa7, 0x4e, 0x46,
        0xf8, 0x6e, 0x7f, 0x43, 0x7a, 0xae, 0xe2, 0xf8,
        0x99, 0x46, 0xf5, 0x7c, 0x97, 0x64, 0x0b, 0x9f,
        0x42, 0x5a, 0x1c, 0x41, 0x43, 0xc1, 0xc4, 0x8e,
        0x8d, 0xd5, 0x71, 0xe5, 0x3f, 0x42, 0x93, 0x9b,
        0x61, 0x73, 0x9c, 0x7e, 0x7d, 0x96, 0x18, 0x52,
        0x6b, 0x2a, 0x03
    };

    init_nvs();
    // store previous signature
    unsigned char* prev_sig = (unsigned char*)data0 + PREVIOUS_SIGNATURE_START;
    ubirch_store_signature(prev_sig, UBIRCH_PROTOCOL_SIGN_SIZE);
    // test message
    TEST_ASSERT_EQUAL_INT(UBIRCH_ESP32_API_HTTP_RESPONSE_SUCCESS,
            test_ubirch_parse_backend_response(data0, sizeof(data0), ed25519_verify_test0));

    // store previous signature
    prev_sig = (unsigned char*)data1 + PREVIOUS_SIGNATURE_START;
    ubirch_store_signature(prev_sig, UBIRCH_PROTOCOL_SIGN_SIZE);
    // test message
    TEST_ASSERT_EQUAL_INT(UBIRCH_ESP32_API_HTTP_RESPONSE_SUCCESS,
            test_ubirch_parse_backend_response(data1, sizeof(data1), ed25519_verify_test1));
}

TEST_CASE("wrong data", "[response]")
{
    char data1[] = {
        0x96, 0x23,
        // bin uuid
        0xc4, 0x10, 0x10, 0xb2, 0xe1, 0xa4,
        0x56, 0xb3, 0x4f, 0xff, 0x9a, 0xda, 0xcc, 0x8c,
        0x20, 0xf9, 0x30, 0x16,
        // bin prev sig
        0xc4, 0x40, 0x54, 0x7f,
        0x8b, 0x7c, 0x78, 0x33, 0x76, 0x79, 0x5f, 0x93,
        0x4f, 0xcd, 0x29, 0xff, 0x24, 0xfd, 0xe8, 0x99,
        0x23, 0x83, 0x51, 0xaa, 0xe1, 0xf4, 0x5d, 0x62,
        0x17, 0x5c, 0xcc, 0x3f, 0xdf, 0xf8, 0xc0, 0xde,
        0x20, 0x6b, 0xa4, 0x81, 0xb9, 0x3f, 0xd2, 0x79,
        0x8c, 0x75, 0xcf, 0xe4, 0xc9, 0xca, 0xef, 0xdf,
        0x3c, 0x40, 0x11, 0x54, 0x5e, 0xe6, 0x8f, 0xc5,
        0x14, 0x60, 0x72, 0xae, 0xc6, 0x03, 0x00,
        // bin payload
        0xc4,
        0x10, 0xd4, 0x2c, 0x07, 0x33, 0x84, 0x2c, 0x49,
        0x7c, 0x96, 0x60, 0x81, 0xaf, 0xfa, 0x96, 0xdf,
        0x82,
        // bin signature
        0xc4, 0x40, 0x55, 0xe3, 0x21, 0x2b, 0xab,
        0xb8, 0xc4, 0xde, 0xba, 0xb4, 0x6d, 0x77, 0xb6,
        0x0f, 0x2e, 0x27, 0xb9, 0x1f, 0xa7, 0x4e, 0x46,
        0xf8, 0x6e, 0x7f, 0x43, 0x7a, 0xae, 0xe2, 0xf8,
        0x99, 0x46, 0xf5, 0x7c, 0x97, 0x64, 0x0b, 0x9f,
        0x42, 0x5a, 0x1c, 0x41, 0x43, 0xc1, 0xc4, 0x8e,
        0x8d, 0xd5, 0x71, 0xe5, 0x3f, 0x42, 0x93, 0x9b,
        0x61, 0x73, 0x9c, 0x7e, 0x7d, 0x96, 0x18, 0x52,
        0x6b, 0x2a, 0x03
    };

    // fake store previous signature
    init_nvs();
    unsigned char prev_sig[UBIRCH_PROTOCOL_SIGN_SIZE];
    memcpy(prev_sig, data1 + PREVIOUS_SIGNATURE_START, UBIRCH_PROTOCOL_SIGN_SIZE);
    // break previous signature in data
    prev_sig[7]++;
    ubirch_store_signature(prev_sig, UBIRCH_PROTOCOL_SIGN_SIZE);


    // test message
    TEST_ASSERT_EQUAL_INT(UBIRCH_ESP32_API_HTTP_RESPONSE_ERROR,
            test_ubirch_parse_backend_response(data1, sizeof(data1), ed25519_verify_test1));
}
