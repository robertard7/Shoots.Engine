#include "tools.h"

shoots_error_code_t tools_register(
  shoots_engine_t *engine,
  const char *tool_id,
  shoots_tool_category_t category,
  uint32_t version,
  uint64_t capabilities,
  const shoots_tool_constraints_t *constraints,
  uint32_t determinism_flags,
  shoots_tool_record_t **out_record,
  shoots_error_info_t *out_error) {
  return shoots_tool_register_internal(engine, tool_id, category, version,
                                       capabilities, constraints,
                                       determinism_flags, out_record, out_error);
}

shoots_error_code_t tools_invoke(
  shoots_engine_t *engine,
  const char *tool_id,
  shoots_error_info_t *out_error) {
  return shoots_tool_invoke_internal(engine, tool_id, out_error);
}
