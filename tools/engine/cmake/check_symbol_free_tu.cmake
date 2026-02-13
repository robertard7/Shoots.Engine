if(NOT DEFINED FILE)
  message(FATAL_ERROR "FILE missing")
endif()

file(READ "${FILE}" _content)
string(REGEX MATCH [[(^|\n)[ \t]*[A-Za-z_][A-Za-z0-9_ \t*]*[ \t]+[A-Za-z_][A-Za-z0-9_]*[ \t]*\([^;{}]*\)[ \t]*\{]] _func_match "${_content}")
if(_func_match)
  message(FATAL_ERROR "function definition found in symbol-free TU: ${FILE}")
endif()
