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

add_dependencies(headers_smoke shoots_engine_static)
add_dependencies(provider_exports_signature shoots_engine_static)
