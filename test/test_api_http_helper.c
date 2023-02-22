#include "unity.h"

// load from compilation unit to be able to check static functions
#include "api-http-helper.c"

TEST_CASE("uuid_format", "[api-http-helper]") {
	unsigned char uuid[16] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
	};
	char buffer[UUID_STR_SIZ];
	TEST_ASSERT_EQUAL_INT(36, uuid_to_string(uuid, buffer, sizeof(buffer)));
	TEST_ASSERT_EQUAL_STRING("00010203-0405-0607-0809-0a0b0c0d0e0f", buffer);
}

/* NILL UUID */
uuid_t nil_uuid = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
/* expected namespace */
char *namespace_name = "Namespace Test";
uuid_t exp_namespace_uuid = {
    0x73, 0x79, 0x9f, 0xba, 0x4f, 0x42, 0x57, 0x15, 0x86, 0x73, 0xe4, 0x28, 0xc4, 0x45, 0x48, 0xd1
};
char *exp_namespace_uuid_string = "73799fba-4f42-5715-8673-e428c44548d1";

/* expected device */
char *device_name = "12345678";
uuid_t exp_device_uuid = {
    0xe9, 0x7e, 0xf8, 0x29, 0x65, 0xa8, 0x5a, 0x3c, 0xa6, 0x2a, 0x1a, 0x44, 0x06, 0x81, 0x31, 0x69
};
char *exp_device_uuid_string = "e97ef829-65a8-5a3c-a62a-1a4406813169";

/* expected derive namespace */
char *der_namespace_name = "Namespace Derived";
uuid_t exp_der_namespace_uuid = {
    0xbc, 0x5b, 0x4e, 0x99, 0x1d, 0x5a, 0x52, 0x94, 0x97, 0xa9, 0x4e, 0xa0, 0xff, 0xb1, 0xde, 0x3b
};
char *exp_der_namespace_uuid_string = "bc5b4e99-1d5a-5294-97a9-4ea0ffb1de3b";

/* expected derived device UUID */
uuid_t exp_der_device_uuid = {
    0x10, 0x1b, 0xdb, 0x0b, 0x89, 0xdc, 0x52, 0xdb, 0x83, 0x5f, 0xa8, 0x66, 0xdd, 0x23, 0x21, 0x4a
};
char *exp_der_device_uuid_str = "101bdb0b-89dc-52db-835f-a866dd23214a";


TEST_CASE("format uuid v3 or v5", "[uuid handling]"){
	unsigned char hash[] = {
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	};
	uuid_t expected_formated_uuid = {
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x5f, 0xff, 0xbf, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	};
	uuid_t test_uuid;

	format_uuid_v3or5(&test_uuid, hash, 5);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(test_uuid, expected_formated_uuid, UUID_SIZ);
}

// nil_uuid: 00000000-0000-0000-0000-000000000000
// Namespace based on ["Namespace Test"] = 73799fba-4f42-5715-8673-e428c44548d1
TEST_CASE("create UUID v5 with sha1 from name", "[uuid handling]") {
    char charbuf[UUID_STR_SIZ]= { 0 };
    uuid_t namespace_uuid;
    
    uuid_create_sha1_from_name((uuid_t *)&namespace_uuid, nil_uuid, namespace_name, strlen(namespace_name));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(namespace_uuid, exp_namespace_uuid, UUID_SIZ);

    uuid_to_string(namespace_uuid, charbuf, UUID_STR_SIZ);
    printf("Namespace based on [\"%s\"] =  %s\n",namespace_name, charbuf);
    TEST_ASSERT_EQUAL_STRING(charbuf, exp_namespace_uuid_string);
}

// nil_uuid: 00000000-0000-0000-0000-000000000000
// Namespace based on ["Namespace Test"]: 73799fba-4f42-5715-8673-e428c44548d1
// device uuid, based on ["12345678"]: e97ef829-65a8-5a3c-a62a-1a4406813169
TEST_CASE("create UUID v5 based on namespace UUID", "[uuid handling]") {
    char charbuf[UUID_STR_SIZ]= { 0 };
    uuid_t device_uuid;
	esp_err_t ret_err;

    ret_err = uuid_v5_create_from_name(&device_uuid, namespace_name, strlen(namespace_name), device_name, strlen(device_name));
	TEST_ASSERT_EQUAL_INT(ESP_OK, ret_err);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(device_uuid, exp_device_uuid, UUID_SIZ);
    uuid_to_string(device_uuid, charbuf, UUID_STR_SIZ);
    printf("device uuid, based on [\"%s\"] = %s\n",device_name, charbuf);
    TEST_ASSERT_EQUAL_STRING(charbuf, exp_device_uuid_string);
}

// nil_uuid: 00000000-0000-0000-0000-000000000000
// Namespace based on ["Namespace Test"]: 73799fba-4f42-5715-8673-e428c44548d1
// Namespace based on ["Namespace Derived"]: bc5b4e99-1d5a-5294-97a9-4ea0ffb1de3b
// device uuid, based on ["12345678"]: 101bdb0b-89dc-52db-835f-a866dd23214a
TEST_CASE("create derived UUID v5 based on derived namespace UUID", "[uuid handling]") {
    char charbuf[UUID_STR_SIZ]= { 0 };
    uuid_t der_device_uuid;
	esp_err_t ret_err;
    
	ret_err = uuid_v5_create_derived_from_name(&der_device_uuid, namespace_name, strlen(namespace_name), der_namespace_name, strlen(der_namespace_name), device_name, strlen(device_name));
    TEST_ASSERT_EQUAL_INT(ESP_OK, ret_err);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(der_device_uuid, exp_der_device_uuid, UUID_SIZ);
    uuid_to_string(der_device_uuid, charbuf, UUID_STR_SIZ);
    printf("device uuid, based on [\"%s\"] = %s\n",device_name, charbuf);
    TEST_ASSERT_EQUAL_STRING(charbuf, exp_der_device_uuid_str);
}

TEST_CASE("create UUID with NULL / 0 inputs", "[uuid_handling]") {
	esp_err_t ret_err;
	uuid_t test_uuid;
	char *name = "name";
    
	ret_err = uuid_v5_create_from_name(NULL,name,strlen(name),name,strlen(name));
	TEST_ASSERT_EQUAL_INT(ESP_FAIL, ret_err);
	ret_err = uuid_v5_create_from_name((uuid_t *)&test_uuid,NULL,strlen(name),name,strlen(name));
	TEST_ASSERT_EQUAL_INT(ESP_FAIL, ret_err);
	ret_err = uuid_v5_create_from_name((uuid_t *)&test_uuid,name,0,name,strlen(name));
	TEST_ASSERT_EQUAL_INT(ESP_FAIL, ret_err);
	ret_err = uuid_v5_create_from_name((uuid_t *)&test_uuid,name,strlen(name),NULL,strlen(name));
	TEST_ASSERT_EQUAL_INT(ESP_FAIL, ret_err);
	ret_err = uuid_v5_create_from_name((uuid_t *)&test_uuid,name,strlen(name),name,0);
	TEST_ASSERT_EQUAL_INT(ESP_FAIL, ret_err);

	ret_err = uuid_v5_create_derived_from_name(NULL,name,strlen(name),name,strlen(name),name,strlen(name));
	TEST_ASSERT_EQUAL_INT(ESP_FAIL, ret_err);
	ret_err = uuid_v5_create_derived_from_name((uuid_t *)&test_uuid,NULL,strlen(name),name,strlen(name),name,strlen(name));
	TEST_ASSERT_EQUAL_INT(ESP_FAIL, ret_err);
	ret_err = uuid_v5_create_derived_from_name((uuid_t *)&test_uuid,name,0,name,strlen(name),name,strlen(name));
	TEST_ASSERT_EQUAL_INT(ESP_FAIL, ret_err);
	ret_err = uuid_v5_create_derived_from_name((uuid_t *)&test_uuid,name,strlen(name),NULL,strlen(name),name,strlen(name));
	TEST_ASSERT_EQUAL_INT(ESP_FAIL, ret_err);
	ret_err = uuid_v5_create_derived_from_name((uuid_t *)&test_uuid,name,strlen(name),name,0,name,strlen(name));
	TEST_ASSERT_EQUAL_INT(ESP_FAIL, ret_err);
	ret_err = uuid_v5_create_derived_from_name((uuid_t *)&test_uuid,name,strlen(name),name,strlen(name),NULL,strlen(name));
	TEST_ASSERT_EQUAL_INT(ESP_FAIL, ret_err);
	ret_err = uuid_v5_create_derived_from_name((uuid_t *)&test_uuid,name,strlen(name),name,strlen(name),name,0);
	TEST_ASSERT_EQUAL_INT(ESP_FAIL, ret_err);
}
