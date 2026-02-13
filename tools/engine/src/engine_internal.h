#ifndef SHOOTS_ENGINE_INTERNAL_H
#define SHOOTS_ENGINE_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

#include "shoots/shoots.h"
#include "provider_runtime.h"

/* ------------------------------------------------------------
 * Forward declarations
 * ------------------------------------------------------------ */

typedef struct shoots_session shoots_session_t;
typedef struct shoots_ledger_entry shoots_ledger_entry_t;
typedef struct shoots_provider_request_record shoots_provider_request_record_t;

shoots_error_code_t shoots_validate_engine(shoots_engine_t *engine,
                                           shoots_error_info_t *out_error);

/* ------------------------------------------------------------
 * Engine / model / session state
 * ------------------------------------------------------------ */

typedef enum shoots_engine_state {
  SHOOTS_ENGINE_STATE_UNINITIALIZED = 0,
  SHOOTS_ENGINE_STATE_INITIALIZED   = 1,
  SHOOTS_ENGINE_STATE_DESTROYED     = 2
} shoots_engine_state_t;

typedef enum shoots_model_state {
  SHOOTS_MODEL_STATE_UNLOADED  = 0,
  SHOOTS_MODEL_STATE_LOADED    = 1,
  SHOOTS_MODEL_STATE_DESTROYED = 2
} shoots_model_state_t;

typedef enum shoots_session_state {
  SHOOTS_SESSION_STATE_UNINITIALIZED = 0,
  SHOOTS_SESSION_STATE_ACTIVE        = 1,
  SHOOTS_SESSION_STATE_CLOSED        = 2,
  SHOOTS_SESSION_STATE_DESTROYED     = 3
} shoots_session_state_t;

typedef enum shoots_session_mode {
  SHOOTS_SESSION_MODE_UNSPECIFIED   = 0,
  SHOOTS_SESSION_MODE_CONTINUATION  = 1,
  SHOOTS_SESSION_MODE_TRANSACTIONAL = 2
} shoots_session_mode_t;

/* ------------------------------------------------------------
 * Ledger
 * ------------------------------------------------------------ */

typedef enum shoots_ledger_entry_type {
  SHOOTS_LEDGER_ENTRY_DECISION   = 0,
  SHOOTS_LEDGER_ENTRY_CONSTRAINT = 1,
  SHOOTS_LEDGER_ENTRY_COMMAND    = 2,
  SHOOTS_LEDGER_ENTRY_RESULT     = 3,
  SHOOTS_LEDGER_ENTRY_ERROR      = 4
} shoots_ledger_entry_type_t;

#define SHOOTS_LEDGER_MAX_BYTES 16384u

/* ------------------------------------------------------------
 * Tools
 * ------------------------------------------------------------ */

typedef enum shoots_tool_category {
  SHOOTS_TOOL_CATEGORY_UNSPECIFIED = 0,
  SHOOTS_TOOL_CATEGORY_EXECUTION   = 1,
  SHOOTS_TOOL_CATEGORY_INTEGRATION = 2
} shoots_tool_category_t;

typedef enum shoots_tool_arbitration_result {
  SHOOTS_TOOL_ARBITRATION_ACCEPT = 0,
  SHOOTS_TOOL_ARBITRATION_REJECT = 1
} shoots_tool_arbitration_result_t;

typedef enum shoots_tool_confirm_policy {
  SHOOTS_TOOL_CONFIRM_NONE    = 0,
  SHOOTS_TOOL_CONFIRM_ALWAYS  = 1,
  SHOOTS_TOOL_CONFIRM_ON_FAIL = 2
} shoots_tool_confirm_policy_t;

typedef enum shoots_tool_determinism_flags {
  SHOOTS_TOOL_DETERMINISM_DETERMINISTIC = 1u << 0,
  SHOOTS_TOOL_DETERMINISM_IDEMPOTENT    = 1u << 1,
  SHOOTS_TOOL_DETERMINISM_PURE          = 1u << 2
} shoots_tool_determinism_flags_t;

typedef struct shoots_tool_constraints {
  uint32_t max_args;
  uint32_t max_bytes;
  shoots_tool_confirm_policy_t confirm_policy;
} shoots_tool_constraints_t;

typedef enum shoots_tool_reject_code {
  SHOOTS_TOOL_REJECT_OK = 0,
  SHOOTS_TOOL_REJECT_TOOL_NOT_FOUND = 1,
  SHOOTS_TOOL_REJECT_CONSTRAINT_MISMATCH = 2,
  SHOOTS_TOOL_REJECT_CAPABILITY_MISMATCH = 3,
  SHOOTS_TOOL_REJECT_INVALID_DESCRIPTOR = 4
} shoots_tool_reject_code_t;

#define SHOOTS_TOOL_REASON_TOKEN_MAX 24u

typedef struct shoots_tool_reject_reason {
  shoots_tool_reject_code_t code;
  char token[SHOOTS_TOOL_REASON_TOKEN_MAX];
} shoots_tool_reject_reason_t;

#define SHOOTS_TOOL_ID_MIN_LEN 1u
#define SHOOTS_TOOL_ID_MAX_LEN 64u
#define SHOOTS_TOOL_VERSION_MIN 1u
#define SHOOTS_TOOL_VERSION_MAX UINT32_MAX
#define SHOOTS_TOOL_MAX_ARGS 128u
#define SHOOTS_TOOL_MAX_BYTES 4096u
#define SHOOTS_TOOL_DETERMINISM_MASK (SHOOTS_TOOL_DETERMINISM_DETERMINISTIC | \
                                      SHOOTS_TOOL_DETERMINISM_IDEMPOTENT | \
                                      SHOOTS_TOOL_DETERMINISM_PURE)
#define SHOOTS_TOOL_CAPABILITIES_ALLOWED UINT64_MAX

/* ------------------------------------------------------------
 * Planning
 * ------------------------------------------------------------ */

typedef struct shoots_plan_request {
  const char  *intent_id;
  const char **requested_tools;
  size_t       requested_tool_count;
  const char  *constraints;
} shoots_plan_request_t;

typedef struct shoots_plan_response {
  char   **ordered_tool_ids;
  shoots_tool_reject_reason_t *rejection_reasons;
  size_t   tool_count;
} shoots_plan_response_t;

/* ------------------------------------------------------------
 * Execution results
 * ------------------------------------------------------------ */

typedef enum shoots_result_status {
  SHOOTS_RESULT_STATUS_OK    = 0,
  SHOOTS_RESULT_STATUS_ERROR = 1
} shoots_result_status_t;

/* ------------------------------------------------------------
 * Records
 * ------------------------------------------------------------ */

typedef struct shoots_command_record {
  uint64_t command_seq;
  uint64_t session_id;
  uint64_t execution_slot;
  char    *command_id;
  size_t   command_id_len;
  char    *args;
  size_t   args_len;
  uint8_t  has_last_result;
  int32_t  last_result_code;
  struct shoots_command_record *next;
} shoots_command_record_t;

typedef struct shoots_intent_record {
  uint64_t created_at;
  uint64_t session_id;
  char    *intent_id;
  size_t   intent_id_len;
  uint8_t  plan_emitted;
  struct shoots_intent_record *next;
} shoots_intent_record_t;

typedef struct shoots_result_record {
  uint64_t session_id;
  uint64_t execution_slot;
  uint64_t ledger_entry_id;
  shoots_result_status_t status;
  char    *command_id;
  size_t   command_id_len;
  char    *payload;
  size_t   payload_len;
  struct shoots_result_record *next;
} shoots_result_record_t;

struct shoots_provider_request_record {
  uint64_t request_id;
  uint64_t session_id;
  uint64_t plan_id;
  uint64_t execution_slot;
  uint8_t  provider_id_len;
  char     provider_id[SHOOTS_PROVIDER_ID_MAX];
  uint8_t  tool_id_len;
  char     tool_id[SHOOTS_PROVIDER_TOOL_ID_MAX];
  uint32_t tool_version;
  uint64_t capability_mask;
  uint64_t input_hash;
  uint32_t arg_size;
  uint8_t  arg_blob[SHOOTS_PROVIDER_ARG_MAX_BYTES];
  uint8_t  received;
  struct shoots_provider_request_record *next;
};

#define SHOOTS_SESSION_MAX_PLANS 4u
#define SHOOTS_SESSION_PLAN_MAX_TOOLS 64u
#define SHOOTS_ENGINE_MAX_PROVIDERS 8u

typedef struct shoots_plan_record {
  uint64_t plan_id;
  uint64_t plan_hash;
  size_t   tool_count;
  char   **tool_ids;
  shoots_tool_reject_reason_t *rejection_reasons;
} shoots_plan_record_t;

typedef struct shoots_tool_record {
  char    *tool_id;
  size_t   tool_id_len;
  shoots_tool_category_t category;
  uint32_t version;
  uint64_t capabilities;
  shoots_tool_constraints_t constraints;
  uint32_t determinism_flags;
  uint64_t tool_hash;
  struct shoots_tool_record *next;
} shoots_tool_record_t;

/* ------------------------------------------------------------
 * Core objects
 * ------------------------------------------------------------ */

struct shoots_model {
  uint32_t magic;
  shoots_engine_t *engine;
  shoots_model_state_t state;
  struct shoots_model *next;
};

struct shoots_session {
  uint32_t magic;
  uint64_t session_id;
  shoots_engine_t *engine;
  shoots_session_state_t state;
  shoots_session_mode_t mode;

  char    *intent_id;
  char    *last_error;

  uint64_t next_execution_slot;
  uint64_t active_execution_slot;
  uint8_t  has_active_execution;
  uint64_t terminal_execution_slot;
  uint8_t  has_terminal_execution;
  uint64_t next_plan_id;
  size_t   plan_count;
  shoots_plan_record_t plans[SHOOTS_SESSION_MAX_PLANS];

  char   *chat_buffer;
  size_t  chat_capacity;
  size_t  chat_size;
  size_t  chat_head;

  struct shoots_session *next;
};

struct shoots_ledger_entry {
  uint64_t entry_id;
  shoots_ledger_entry_type_t type;
  char   *payload;
  size_t  payload_len;
  struct shoots_ledger_entry *next;
};

struct shoots_engine {
  shoots_config_t config;

  char   *model_root_path;

  size_t  memory_used_bytes;
  size_t  memory_limit_bytes;
  void   *allocations_head;

  shoots_provider_runtime_t *provider_runtime;
  shoots_provider_descriptor_t providers[SHOOTS_ENGINE_MAX_PROVIDERS];
  size_t provider_count;
  uint8_t providers_locked;
  uint8_t provider_snapshot_exported;
  uint8_t provider_system_sealed;

  struct shoots_model   *models_head;
  struct shoots_model   *models_tail;

  struct shoots_session *sessions_head;
  struct shoots_session *sessions_tail;
  uint64_t               next_session_id;

  struct shoots_intent_record *intents_head;
  struct shoots_intent_record *intents_tail;
  uint64_t                     next_intent_created_at;

  struct shoots_ledger_entry *ledger_head;
  struct shoots_ledger_entry *ledger_tail;
  size_t                      ledger_entry_count;
  size_t                      ledger_total_bytes;
  uint64_t                    next_ledger_id;

  struct shoots_tool_record *tools_head;
  struct shoots_tool_record *tools_tail;
  uint8_t                    tools_locked;

  struct shoots_result_record *results_head;
  struct shoots_result_record *results_tail;

  struct shoots_provider_request_record *provider_requests_head;
  struct shoots_provider_request_record *provider_requests_tail;

  shoots_command_record_t *commands_head;
  shoots_command_record_t *commands_tail;
  size_t                   commands_entry_count;
  size_t                   commands_total_bytes;
  uint64_t                 next_command_seq;

  shoots_engine_state_t state;
  uint32_t              magic;
};

/* ------------------------------------------------------------
 * Internal APIs
 * ------------------------------------------------------------ */

void *shoots_engine_alloc_internal(
  shoots_engine_t *engine,
  size_t bytes,
  shoots_error_info_t *out_error);

void shoots_engine_alloc_free_internal(
  shoots_engine_t *engine,
  void *buffer);

shoots_error_code_t shoots_provider_register_internal(
  shoots_engine_t *engine,
  const shoots_provider_descriptor_t *descriptor,
  shoots_error_info_t *out_error);

shoots_error_code_t shoots_provider_registry_lock_internal(
  shoots_engine_t *engine,
  shoots_error_info_t *out_error);

shoots_error_code_t shoots_provider_unregister_internal(
  shoots_engine_t *engine,
  const char *provider_id,
  shoots_error_info_t *out_error);

shoots_error_code_t shoots_provider_request_mint_internal(
  shoots_engine_t *engine,
  shoots_session_t *session,
  uint64_t plan_id,
  uint64_t execution_slot,
  const char *tool_id,
  const shoots_provider_descriptor_t *provider,
  uint64_t capability_mask,
  uint64_t input_hash,
  const uint8_t *arg_blob,
  uint32_t arg_size,
  shoots_provider_request_t *out_request,
  shoots_error_info_t *out_error);

shoots_error_code_t shoots_provider_receipt_verify_internal(
  shoots_engine_t *engine,
  const shoots_provider_receipt_t *receipt,
  shoots_error_info_t *out_error);

shoots_error_code_t shoots_provider_receipt_map_terminal_internal(
  shoots_engine_t *engine,
  const shoots_provider_receipt_t *receipt,
  shoots_error_info_t *out_error);

shoots_error_code_t shoots_provider_requests_export_internal(
  shoots_engine_t *engine,
  shoots_provider_request_t **out_requests,
  size_t *out_count,
  shoots_error_info_t *out_error);

shoots_error_code_t shoots_provider_receipt_import_internal(
  shoots_engine_t *engine,
  const shoots_provider_receipt_t *receipt,
  shoots_error_info_t *out_error);

shoots_error_code_t shoots_session_create_internal(
  shoots_engine_t *engine,
  const char *intent_id,
  shoots_session_mode_t mode,
  struct shoots_session **out_session,
  shoots_error_info_t *out_error);

shoots_error_code_t shoots_session_attach_internal(
  shoots_engine_t *engine,
  uint64_t session_id,
  struct shoots_session **out_session,
  shoots_error_info_t *out_error);

shoots_error_code_t shoots_session_close_internal(
  shoots_engine_t *engine,
  struct shoots_session *session,
  shoots_error_info_t *out_error);

shoots_error_code_t shoots_session_transition_active_internal(
  struct shoots_session *session,
  uint64_t execution_slot,
  shoots_error_info_t *out_error);

shoots_error_code_t shoots_session_transition_terminal_internal(
  struct shoots_session *session,
  uint64_t execution_slot,
  shoots_error_info_t *out_error);

shoots_error_code_t shoots_session_plan_store_internal(
  struct shoots_session *session,
  uint64_t plan_id,
  uint64_t plan_hash,
  const char *const *tool_ids,
  const shoots_tool_reject_reason_t *rejection_reasons,
  size_t tool_count,
  shoots_error_info_t *out_error);

void shoots_session_plan_clear_internal(struct shoots_session *session);

shoots_error_code_t shoots_session_chat_append_internal(
  struct shoots_session *session,
  const char *text,
  shoots_error_info_t *out_error);

shoots_error_code_t shoots_session_chat_snapshot_internal(
  struct shoots_session *session,
  char **out_buffer,
  size_t *out_length,
  shoots_error_info_t *out_error);

shoots_error_code_t shoots_session_chat_clear_internal(
  struct shoots_session *session,
  shoots_error_info_t *out_error);

shoots_error_code_t shoots_ledger_append_internal(
  shoots_engine_t *engine,
  shoots_ledger_entry_type_t type,
  const char *payload,
  struct shoots_ledger_entry **out_entry,
  shoots_error_info_t *out_error);

shoots_error_code_t shoots_ledger_query_type_internal(
  shoots_engine_t *engine,
  shoots_ledger_entry_type_t type,
  struct shoots_ledger_entry ***out_entries,
  size_t *out_count,
  shoots_error_info_t *out_error);

shoots_error_code_t shoots_ledger_query_substring_internal(
  shoots_engine_t *engine,
  const char *substring,
  struct shoots_ledger_entry ***out_entries,
  size_t *out_count,
  shoots_error_info_t *out_error);

shoots_error_code_t shoots_invariant_violation_internal(
  shoots_engine_t *engine,
  const char *message,
  shoots_error_info_t *out_error);

shoots_error_code_t shoots_provider_snapshot_export_internal(
  shoots_engine_t *engine,
  shoots_provider_snapshot_t **out_snapshot,
  shoots_error_info_t *out_error);

/* BUILDER-ONLY */
/* READ-ONLY */
/* FROZEN API — DO NOT EXTEND WITHOUT PHASE BUMP */
shoots_error_code_t shoots_engine_export_provider_snapshot_const(
  const shoots_engine_t *engine,
  shoots_provider_snapshot_t **out_snapshot,
  shoots_error_info_t *out_error);

shoots_error_code_t shoots_engine_export_pending_provider_requests_const(
  const shoots_engine_t *engine,
  shoots_provider_request_record_t **out_list,
  size_t *out_count,
  shoots_error_info_t *out_error);

int shoots_engine_provider_ready(const shoots_engine_t *engine);

/* END BUILDER-ONLY FROZEN PROVIDER QUERIES */

shoots_error_code_t shoots_command_append_internal(
  shoots_engine_t *engine,
  shoots_session_t *session,
  uint64_t execution_slot,
  const char *command_id,
  const char *args,
  uint8_t has_last_result,
  int32_t last_result_code,
  shoots_command_record_t **out_record,
  shoots_error_info_t *out_error);

shoots_error_code_t shoots_command_fetch_last_internal(
  shoots_engine_t *engine,
  size_t max_count,
  shoots_command_record_t ***out_records,
  size_t *out_count,
  shoots_error_info_t *out_error);

shoots_error_code_t shoots_result_append_internal(
  shoots_engine_t *engine,
  shoots_session_t *session,
  const char *command_id,
  shoots_result_status_t status,
  const char *payload,
  shoots_result_record_t **out_record,
  shoots_error_info_t *out_error);

shoots_error_code_t shoots_tool_register_internal(
  shoots_engine_t *engine,
  const char *tool_id,
  shoots_tool_category_t category,
  uint32_t version,
  uint64_t capabilities,
  const shoots_tool_constraints_t *constraints,
  uint32_t determinism_flags,
  shoots_tool_record_t **out_record,
  shoots_error_info_t *out_error);

shoots_error_code_t shoots_tool_arbitrate_internal(
  shoots_engine_t *engine,
  const char *tool_id,
  shoots_tool_arbitration_result_t *out_result,
  shoots_error_info_t *out_error);

shoots_error_code_t shoots_tool_invoke_internal(
  shoots_engine_t *engine,
  const char *tool_id,
  shoots_error_info_t *out_error);

shoots_error_code_t shoots_plan_internal(
  shoots_engine_t *engine,
  const shoots_plan_request_t *request,
  shoots_plan_response_t *response,
  shoots_error_info_t *out_error);

shoots_error_code_t shoots_plan_response_free_internal(
  shoots_engine_t *engine,
  shoots_plan_response_t *response,
  shoots_error_info_t *out_error);

shoots_error_code_t shoots_engine_can_execute_internal(
  shoots_engine_t *engine,
  shoots_session_t *session,
  const char *tool_id,
  const char **out_reason,
  shoots_error_info_t *out_error);

#endif /* SHOOTS_ENGINE_INTERNAL_H */
