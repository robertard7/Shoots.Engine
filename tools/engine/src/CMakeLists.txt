add_library(shoots_engine
    src/core_engine.c
    src/session.c
    src/ledger.c
    src/commands.c
    src/execution_spine.c
    src/tools.c
    src/planner.c
    src/exec_gate.c
    src/selfcheck.c
)
target_include_directories(shoots_engine PUBLIC include/shoots PRIVATE src)
