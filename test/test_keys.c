#include "unity.h"
#include <time.h>
#define LOG_LOCAL_LEVEL ESP_LOG_DEBUG
#include <esp_log.h>
#include "keys.h"
#include "id_handling.h"
#include "storage.h"
#include "ubirch_ed25519.h"

static const char *TAG = "UBIRCH API TEST KEYS";

TEST_CASE("create_keys", "[keys]")
{
    init_nvs();

    unsigned char uuid[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

    TEST_ASSERT_EQUAL_INT(ESP_OK, ubirch_id_context_add("test_id_3"));
    TEST_ASSERT_EQUAL_INT(ESP_OK, ubirch_uuid_set(uuid, sizeof(uuid)));
    TEST_ASSERT_EQUAL_INT(ESP_OK, ubirch_id_context_store());
    TEST_ASSERT(!ubirch_id_state_get(UBIRCH_ID_STATE_KEYS_CREATED));
    create_keys();
    TEST_ASSERT(ubirch_id_state_get(UBIRCH_ID_STATE_KEYS_CREATED));
    TEST_ASSERT_EQUAL_INT(ESP_OK, ubirch_id_context_store());
    TEST_ASSERT_EQUAL_INT(ESP_OK, ubirch_id_context_load("test_id_3"));

    time_t next_update;
    TEST_ASSERT_EQUAL_INT(ESP_OK, ubirch_next_key_update_get(&next_update));
    ESP_LOGD(TAG, "next update from mem: %ld", next_update);

    TEST_ASSERT(ubirch_id_state_get(UBIRCH_ID_STATE_KEYS_CREATED));
    TEST_ASSERT(!ubirch_id_state_get(UBIRCH_ID_STATE_KEYS_REGISTERED));
    TEST_ASSERT(!ubirch_id_state_get(UBIRCH_ID_STATE_PASSWORD_SET));
    TEST_ASSERT(!ubirch_id_state_get(UBIRCH_ID_STATE_PREVIOUS_SIGNATURE_SET));

    // check if key pair works
    unsigned char signature[crypto_sign_BYTES];
    unsigned char data[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
    TEST_ASSERT_EQUAL_INT(0, ed25519_sign(data, sizeof(data), signature));
    TEST_ASSERT_EQUAL_INT(0, ed25519_verify(data, sizeof(data), signature));
}
