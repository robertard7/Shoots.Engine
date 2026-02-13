add_library(shoots_engine
    src/engine.c
    src/provider_runtime.c
    src/session.c
    src/ledger.c
    src/execution_spine.c
    src/commands.c
    src/core_engine.c
)

target_include_directories(shoots_engine
    PUBLIC
        include
    PRIVATE
        src
)

set_target_properties(shoots_engine PROPERTIES
    C_STANDARD 17
    C_STANDARD_REQUIRED YES
    C_EXTENSIONS NO
)
