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
if(MSVC AND SHOOTS_ENGINE_STRICT_MSVC)
  target_compile_options(headers_smoke PRIVATE /W4 /WX)
endif()

add_library(public_headers_smoke OBJECT
  header_smoke/header_smoke_public_api.c
)

target_include_directories(public_headers_smoke PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../include
)

set_target_properties(public_headers_smoke PROPERTIES
  C_STANDARD 17
  C_STANDARD_REQUIRED YES
  C_EXTENSIONS NO
)
if(MSVC AND SHOOTS_ENGINE_STRICT_MSVC)
  target_compile_options(public_headers_smoke PRIVATE /W4 /WX)
endif()

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
if(MSVC AND SHOOTS_ENGINE_STRICT_MSVC)
  target_compile_options(provider_exports_signature PRIVATE /W4 /WX)
endif()

function(add_engine_test_pair base source)
  add_executable(${base}_static_test ${source})
  target_include_directories(${base}_static_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../src
  )
  target_link_libraries(${base}_static_test PRIVATE shoots_engine_static)

  add_executable(${base}_shared_test ${source})
  target_include_directories(${base}_shared_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../src
  )
  target_link_libraries(${base}_shared_test PRIVATE shoots_engine_shared)

  set_target_properties(${base}_static_test ${base}_shared_test PROPERTIES
    C_STANDARD 17
    C_STANDARD_REQUIRED YES
    C_EXTENSIONS NO
  )

  if(MSVC AND SHOOTS_ENGINE_STRICT_MSVC)
    target_compile_options(${base}_static_test PRIVATE /W4 /WX)
    target_compile_options(${base}_shared_test PRIVATE /W4 /WX)
  endif()

  add_test(NAME ${base}_static_test COMMAND ${base}_static_test)
  add_test(NAME ${base}_shared_test COMMAND ${base}_shared_test)
endfunction()

add_engine_test_pair(provider_roundtrip provider_roundtrip_test.c)
add_engine_test_pair(determinism_replay determinism_replay_test.c)
add_engine_test_pair(guardrail_limits guardrail_limits_test.c)
add_engine_test_pair(malformed_receipt malformed_receipt_test.c)
add_engine_test_pair(multi_request_ordering multi_request_ordering_test.c)
add_engine_test_pair(multi_session_isolation multi_session_isolation_test.c)
add_engine_test_pair(snapshot_contract snapshot_contract_test.c)
add_engine_test_pair(oom_guardrails oom_guardrails_test.c)

add_custom_target(engine_tests_all)
add_dependencies(engine_tests_all
  provider_roundtrip_static_test provider_roundtrip_shared_test
  determinism_replay_static_test determinism_replay_shared_test
  guardrail_limits_static_test guardrail_limits_shared_test
  malformed_receipt_static_test malformed_receipt_shared_test
  multi_request_ordering_static_test multi_request_ordering_shared_test
  multi_session_isolation_static_test multi_session_isolation_shared_test
  snapshot_contract_static_test snapshot_contract_shared_test
  oom_guardrails_static_test oom_guardrails_shared_test
)

add_dependencies(headers_smoke shoots_engine_static)
add_dependencies(public_headers_smoke shoots_engine_static)
add_dependencies(provider_exports_signature shoots_engine_static)
