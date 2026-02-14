add_library(headers_smoke OBJECT
  header_smoke/header_smoke_public.c
  header_smoke/header_smoke_provider_runtime.c
  header_smoke/header_smoke_engine_internal.c
  header_smoke/header_smoke_execution_spine.c
)

target_include_directories(headers_smoke PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../include
  ${CMAKE_CURRENT_SOURCE_DIR}/../src
)

set_target_properties(headers_smoke PROPERTIES
  C_STANDARD 17
  C_STANDARD_REQUIRED YES
  C_EXTENSIONS NO
)

add_library(provider_exports_signature OBJECT
  header_smoke/provider_exports_signature.c
)

target_include_directories(provider_exports_signature PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../include
  ${CMAKE_CURRENT_SOURCE_DIR}/../src
)

set_target_properties(provider_exports_signature PROPERTIES
  C_STANDARD 17
  C_STANDARD_REQUIRED YES
  C_EXTENSIONS NO
)

add_executable(provider_roundtrip_static_test
  provider_roundtrip_test.c
)
target_include_directories(provider_roundtrip_static_test PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../include
  ${CMAKE_CURRENT_SOURCE_DIR}/../src
)
target_link_libraries(provider_roundtrip_static_test PRIVATE shoots_engine_static)

add_executable(provider_roundtrip_shared_test
  provider_roundtrip_test.c
)
target_include_directories(provider_roundtrip_shared_test PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../include
  ${CMAKE_CURRENT_SOURCE_DIR}/../src
)
target_link_libraries(provider_roundtrip_shared_test PRIVATE shoots_engine_shared)

add_executable(determinism_replay_static_test
  determinism_replay_test.c
)
target_include_directories(determinism_replay_static_test PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../include
  ${CMAKE_CURRENT_SOURCE_DIR}/../src
)
target_link_libraries(determinism_replay_static_test PRIVATE shoots_engine_static)

add_executable(guardrail_limits_static_test
  guardrail_limits_test.c
)
target_include_directories(guardrail_limits_static_test PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../include
  ${CMAKE_CURRENT_SOURCE_DIR}/../src
)
target_link_libraries(guardrail_limits_static_test PRIVATE shoots_engine_static)

foreach(_tgt
  provider_roundtrip_static_test
  provider_roundtrip_shared_test
  determinism_replay_static_test
  guardrail_limits_static_test)
  set_target_properties(${_tgt} PROPERTIES
    C_STANDARD 17
    C_STANDARD_REQUIRED YES
    C_EXTENSIONS NO
  )
endforeach()

add_test(NAME provider_roundtrip_static_test COMMAND provider_roundtrip_static_test)
add_test(NAME provider_roundtrip_shared_test COMMAND provider_roundtrip_shared_test)
add_test(NAME determinism_replay_static_test COMMAND determinism_replay_static_test)
add_test(NAME guardrail_limits_static_test COMMAND guardrail_limits_static_test)

add_dependencies(headers_smoke shoots_engine_static)
add_dependencies(provider_exports_signature shoots_engine_static)
