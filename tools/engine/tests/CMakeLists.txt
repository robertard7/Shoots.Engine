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

add_executable(malformed_receipt_static_test
  malformed_receipt_test.c
)
target_include_directories(malformed_receipt_static_test PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../include
  ${CMAKE_CURRENT_SOURCE_DIR}/../src
)
target_link_libraries(malformed_receipt_static_test PRIVATE shoots_engine_static)

add_executable(multi_request_ordering_static_test
  multi_request_ordering_test.c
)
target_include_directories(multi_request_ordering_static_test PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../include
  ${CMAKE_CURRENT_SOURCE_DIR}/../src
)
target_link_libraries(multi_request_ordering_static_test PRIVATE shoots_engine_static)

add_executable(multi_session_isolation_static_test
  multi_session_isolation_test.c
)
target_include_directories(multi_session_isolation_static_test PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../include
  ${CMAKE_CURRENT_SOURCE_DIR}/../src
)
target_link_libraries(multi_session_isolation_static_test PRIVATE shoots_engine_static)

add_executable(snapshot_contract_static_test
  snapshot_contract_test.c
)
target_include_directories(snapshot_contract_static_test PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../include
  ${CMAKE_CURRENT_SOURCE_DIR}/../src
)
target_link_libraries(snapshot_contract_static_test PRIVATE shoots_engine_static)

add_executable(oom_guardrails_static_test
  oom_guardrails_test.c
)
target_include_directories(oom_guardrails_static_test PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../include
  ${CMAKE_CURRENT_SOURCE_DIR}/../src
)
target_link_libraries(oom_guardrails_static_test PRIVATE shoots_engine_static)
target_include_directories(guardrail_limits_static_test PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../include
  ${CMAKE_CURRENT_SOURCE_DIR}/../src
)
target_link_libraries(guardrail_limits_static_test PRIVATE shoots_engine_static)

foreach(_tgt
  provider_roundtrip_static_test
  provider_roundtrip_shared_test
  determinism_replay_static_test
  guardrail_limits_static_test
  malformed_receipt_static_test
  multi_request_ordering_static_test
  multi_session_isolation_static_test
  snapshot_contract_static_test
  oom_guardrails_static_test)
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
add_test(NAME malformed_receipt_static_test COMMAND malformed_receipt_static_test)
add_test(NAME multi_request_ordering_static_test COMMAND multi_request_ordering_static_test)
add_test(NAME multi_session_isolation_static_test COMMAND multi_session_isolation_static_test)
add_test(NAME snapshot_contract_static_test COMMAND snapshot_contract_static_test)
add_test(NAME oom_guardrails_static_test COMMAND oom_guardrails_static_test)

add_dependencies(headers_smoke shoots_engine_static)
add_dependencies(provider_exports_signature shoots_engine_static)
