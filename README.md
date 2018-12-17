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
It is implemented in the [example application](https://github.com/ubirch/example-esp32/blob/master/main/sensor.c#L61-L75)

```c
// create buffer and allocate memory space
msgpack_sbuffer *sbuf = msgpack_sbuffer_new(); //!< send buffer
msgpack_unpacker *unpacker = msgpack_unpacker_new(128); //!< receive unpacker

// measurement values to send
int32_t values[2] = {(int32_t) (temperature * 100), (int32_t) (humidity * 100)};

// create a message
ubirch_message(sbuf, UUID, values, sizeof(values) / sizeof(values[0]));
// send the message
ubirch_send(CONFIG_UBIRCH_BACKEND_DATA_URL, sbuf->data, sbuf->size, unpacker);
// parse the message response
ubirch_parse_response(unpacker, response_handler);

// free the allocated memory space
msgpack_unpacker_free(unpacker);
msgpack_sbuffer_free(sbuf);
```
