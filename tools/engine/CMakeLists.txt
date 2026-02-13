cmake_minimum_required(VERSION 3.20)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  project(ShootsEngine C)
endif()

include(${CMAKE_CURRENT_SOURCE_DIR}/src/CMakeLists.txt)

option(SHOOTS_ENGINE_BUILD_HEADER_SMOKE "Build header smoke and signature guard targets" ON)
option(SHOOTS_ENGINE_BUILD_SELFCHECK "Build selfcheck executable" OFF)

if(SHOOTS_ENGINE_BUILD_HEADER_SMOKE)
  enable_testing()
  add_subdirectory(tests)
endif()
