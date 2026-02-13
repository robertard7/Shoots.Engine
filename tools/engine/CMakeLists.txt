cmake_minimum_required(VERSION 3.20)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  project(ShootsEngine C)
endif()

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
