![ubirch logo](https://ubirch.de/wp-content/uploads/2018/10/cropped-uBirch_Logo.png)

# ESP32 ubirch api http functions

This component makes communication with the ubirch API simpler.

## Prerequisits

The following components are required for the functionality, see also
[CMakeLists.txt](https://github.com/ubirch/ubirch-esp32-api-http/blob/master/CMakeLists.txt)

- [ubirch-protocol](https://github.com/ubirch/ubirch-protocol.git)
- [ubirch-esp32-storage](https://github.com/ubirch/ubirch-esp32-storage)
- [esp_http_client](https://github.com/espressif/esp-idf/tree/master/components/esp_http_client)

## Example

This is an example code snippet to send a message in the ubirch format to the backend.

```c
// create buffer and allocate memory space
msgpack_sbuffer *sbuf = msgpack_sbuffer_new(); //!< send buffer
msgpack_unpacker *unpacker = msgpack_unpacker_new(128); //!< receive unpacker

// measurement values to send
int32_t values[2] = {(int32_t) (temperature * 100), (int32_t) (humidity * 100)};

// create a message
ubirch_message(sbuf, UUID, values, sizeof(values) / sizeof(values[0]));
// send the message
int http_status;
ubirch_send(CONFIG_UBIRCH_BACKEND_DATA_URL, sbuf->data, sbuf->size, &http_status, unpacker, NULL);
// parse the message response
ubirch_parse_response(unpacker, response_handler);

// free the allocated memory space
msgpack_unpacker_free(unpacker);
msgpack_sbuffer_free(sbuf);
```

If you want to verify and handle the backend response you additionally need a verifier and a response handler callback.
It is implemented in the [example application](https://github.com/ubirch/example-esp32/blob/master/main/sensor.c)

```c
static int ed25519_verify_backend_response(const unsigned char *data,
        size_t len, const unsigned char signature[UBIRCH_PROTOCOL_SIGN_SIZE]) {
    return ed25519_verify_key(data, len, signature, server_pub_key);
}

void bin_response_handler(const void* data, size_t len) {
    ESP_LOG_BUFFER_HEXDUMP("response UPP payload", data, len, ESP_LOG_INFO);
}
```

Those have to be passed to `ubirch_send` and `ubirch_parse_backend_response`.

```c
// [...]
// send the message
int http_status;
ubirch_send(CONFIG_UBIRCH_BACKEND_DATA_URL, sbuf->data, sbuf->size, &http_status, unpacker, ed25519_verify_backend_response);

// parse backend response
ubirch_parse_backend_response(unpacker, bin_response_handler);
// [...]
```
