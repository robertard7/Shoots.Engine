cmake_minimum_required(VERSION 3.20)
project(shoots_engine_consumer_shared C)

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../../tools/engine ${CMAKE_BINARY_DIR}/tools-engine)

add_executable(consumer_shared
  main.c
)

target_include_directories(consumer_shared PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../../tools/engine/include
  ${CMAKE_CURRENT_SOURCE_DIR}/../../tools/engine/src
)

target_link_libraries(consumer_shared PRIVATE shoots_engine_shared)

set_target_properties(consumer_shared PROPERTIES
  C_STANDARD 17
  C_STANDARD_REQUIRED YES
  C_EXTENSIONS NO
)
