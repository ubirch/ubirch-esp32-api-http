set(COMPONENT_SRCS
        ubirch_api.c
        message.c
        response.c
        api-http-helper.c
        keys.c
        register_thing.c
        )
set(COMPONENT_ADD_INCLUDEDIRS ".")
set(COMPONENT_REQUIRES ubirch-protocol ubirch-esp32-key-storage)
set(COMPONENT_PRIV_REQUIRES esp_http_client mbedtls json)
register_component()
