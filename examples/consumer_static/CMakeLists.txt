cmake_minimum_required(VERSION 3.20)
project(shoots_engine_consumer_static C)

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../../tools/engine ${CMAKE_BINARY_DIR}/tools-engine)

add_executable(consumer_static
  main.c
)

target_include_directories(consumer_static PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../../tools/engine/include
  ${CMAKE_CURRENT_SOURCE_DIR}/../../tools/engine/src
)

target_link_libraries(consumer_static PRIVATE shoots_engine_static)

set_target_properties(consumer_static PROPERTIES
  C_STANDARD 17
  C_STANDARD_REQUIRED YES
  C_EXTENSIONS NO
)
