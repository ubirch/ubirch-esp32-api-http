set(COMPONENT_SRCS
        ubirch_api.c
        message.c
        response.c
        )
set(COMPONENT_ADD_INCLUDEDIRS ".")
set(COMPONENT_REQUIRES ubirch-protocol ubirch-esp32-storage)
set(COMPONENT_PRIV_REQUIRES esp_http_client)
register_component()