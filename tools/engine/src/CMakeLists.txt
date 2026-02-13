add_library(shoots_engine
    src/engine.c
    src/provider_runtime.c

    # Engine support modules.
    src/session.c
    src/ledger.c
    src/execution_spine.c
    src/tools.c
    src/planner.c
    src/exec_gate.c
    src/selfcheck.c
)

target_include_directories(shoots_engine
    PUBLIC
        include
    PRIVATE
        src
)

# Keep it plain C17.
set_target_properties(shoots_engine PROPERTIES
    C_STANDARD 17
    C_STANDARD_REQUIRED YES
    C_EXTENSIONS NO
)
