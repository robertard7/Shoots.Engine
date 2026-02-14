cmake_minimum_required(VERSION 3.20)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  project(ShootsEngine C)
endif()

option(SHOOTS_ENGINE_STRICT_MSVC "Enable strict MSVC warnings for engine and tests" ON)
option(SHOOTS_ENGINE_BUILD_HEADER_SMOKE "Build header smoke and signature guard targets" ON)
option(SHOOTS_ENGINE_BUILD_SELFCHECK "Build selfcheck executable" OFF)

include(${CMAKE_CURRENT_SOURCE_DIR}/src/CMakeLists.txt)

if(MSVC AND SHOOTS_ENGINE_STRICT_MSVC)
  target_compile_options(shoots_engine_static PRIVATE /W4 /WX)
  target_compile_options(shoots_engine_shared PRIVATE /W4 /WX)
endif()

if(SHOOTS_ENGINE_BUILD_HEADER_SMOKE)
  enable_testing()
  add_subdirectory(tests)
endif()

if(TARGET engine_tests_all)
  add_dependencies(engine_tests_all shoots_engine_static shoots_engine_shared)
endif()
