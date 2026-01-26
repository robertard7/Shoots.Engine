cmake_minimum_required(VERSION 3.20)

add_library(shoots_engine_static STATIC
  src/empty.c
)

add_library(shoots_engine_shared SHARED
  src/empty.c
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
