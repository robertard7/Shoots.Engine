#include "provider_runtime.h"

typedef shoots_error_code_t (*shoots_export_snapshot_sig_t)(
  const shoots_engine_t *engine,
  shoots_provider_snapshot_t **out_snapshot,
  shoots_error_info_t *out_error);

typedef shoots_error_code_t (*shoots_export_pending_sig_t)(
  const shoots_engine_t *engine,
  shoots_provider_request_record_t **out_list,
  size_t *out_count,
  shoots_error_info_t *out_error);

typedef int (*shoots_provider_ready_sig_t)(const shoots_engine_t *engine);

static shoots_export_snapshot_sig_t g_export_snapshot_sig =
  &shoots_engine_export_provider_snapshot_const;
static shoots_export_pending_sig_t g_export_pending_sig =
  &shoots_engine_export_pending_provider_requests_const;
static shoots_provider_ready_sig_t g_provider_ready_sig =
  &shoots_engine_provider_ready;

void shoots_provider_exports_signature_guard(void) {
  (void)g_export_snapshot_sig;
  (void)g_export_pending_sig;
  (void)g_provider_ready_sig;
}
