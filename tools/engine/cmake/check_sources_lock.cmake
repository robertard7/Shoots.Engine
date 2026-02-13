if(DEFINED DATA_FILE)
  include("${DATA_FILE}")
endif()

if(NOT DEFINED STATIC_SOURCES)
  message(FATAL_ERROR "STATIC_SOURCES missing")
endif()
if(NOT DEFINED SHARED_SOURCES)
  message(FATAL_ERROR "SHARED_SOURCES missing")
endif()

set(_static_sources ${STATIC_SOURCES})
set(_shared_sources ${SHARED_SOURCES})

list(SORT _static_sources)
list(SORT _shared_sources)

if(NOT _static_sources STREQUAL _shared_sources)
  string(JOIN "\n" _static_lines ${_static_sources})
  string(JOIN "\n" _shared_lines ${_shared_sources})
  message(FATAL_ERROR
    "shoots_engine source drift detected.\n"
    "static:\n${_static_lines}\n"
    "shared:\n${_shared_lines}")
endif()
