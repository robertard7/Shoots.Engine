set(SHOOTS_ENGINE_SOURCES
  src/engine.c
  src/provider_runtime.c
  src/session.c
  src/ledger.c
  src/execution_spine.c
  src/commands.c
  src/core_engine.c
)

add_library(shoots_engine_static STATIC
  ${SHOOTS_ENGINE_SOURCES}
)

add_library(shoots_engine_shared SHARED
  ${SHOOTS_ENGINE_SOURCES}
)

set_target_properties(shoots_engine_static PROPERTIES
  C_STANDARD 17
  C_STANDARD_REQUIRED YES
  C_EXTENSIONS NO
  OUTPUT_NAME shoots_engine
)

set_target_properties(shoots_engine_shared PROPERTIES
  C_STANDARD 17
  C_STANDARD_REQUIRED YES
  C_EXTENSIONS NO
  OUTPUT_NAME shoots_engine
)

target_include_directories(shoots_engine_static PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_include_directories(shoots_engine_shared PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/include
)

get_target_property(_shoots_engine_shared_sources shoots_engine_shared SOURCES)
get_target_property(_shoots_engine_static_sources shoots_engine_static SOURCES)
list(SORT _shoots_engine_shared_sources)
list(SORT _shoots_engine_static_sources)
if(NOT _shoots_engine_shared_sources STREQUAL _shoots_engine_static_sources)
  string(JOIN "\n" _shared_lines ${_shoots_engine_shared_sources})
  string(JOIN "\n" _static_lines ${_shoots_engine_static_sources})
  message(FATAL_ERROR
    "shoots_engine source drift detected between shared and static targets.\n"
    "shared:\n${_shared_lines}\n"
    "static:\n${_static_lines}")
endif()

set(_shoots_engine_sources_lock_data "${CMAKE_CURRENT_BINARY_DIR}/engine_sources_lock_data.cmake")
file(WRITE "${_shoots_engine_sources_lock_data}"
  "set(STATIC_SOURCES \"${_shoots_engine_static_sources}\")\n"
  "set(SHARED_SOURCES \"${_shoots_engine_shared_sources}\")\n")

add_custom_target(engine_sources_lock
  COMMAND ${CMAKE_COMMAND}
    -DDATA_FILE=${_shoots_engine_sources_lock_data}
    -P ${CMAKE_CURRENT_LIST_DIR}/../cmake/check_sources_lock.cmake
  COMMENT "Checking shoots_engine source list drift"
  VERBATIM
)

add_custom_target(no_symbol_stubs
  COMMAND ${CMAKE_COMMAND}
    -DFILE=${CMAKE_CURRENT_SOURCE_DIR}/src/commands.c
    -P ${CMAKE_CURRENT_LIST_DIR}/../cmake/check_symbol_free_tu.cmake
  COMMAND ${CMAKE_COMMAND}
    -DFILE=${CMAKE_CURRENT_SOURCE_DIR}/src/core_engine.c
    -P ${CMAKE_CURRENT_LIST_DIR}/../cmake/check_symbol_free_tu.cmake
  COMMENT "Ensuring refactor placeholder TUs stay symbol-free"
  VERBATIM
)

add_dependencies(shoots_engine_static engine_sources_lock no_symbol_stubs)
add_dependencies(shoots_engine_shared engine_sources_lock no_symbol_stubs)
