#ifndef MAIN_DIAG_H
#define MAIN_DIAG_H

#include <stdint.h>

struct app_config;
struct forwarder;

void main_diag_log_db_apply(const struct app_config *cfg, int trigger_profile_id,
                            const struct app_config *prev_cfg);
/* DB notify when only policies/profiles changed. */
void main_diag_log_db_policy_apply(const struct app_config *cfg, int trigger_profile_id,
                                   const struct app_config *prev_cfg);
void main_diag_log_no_update(int trigger_profile_id, const struct app_config *cfg);
void main_diag_log_config_summary(struct app_config *cfg, int trigger_profile_id,
                                  int is_reload, int policy_only);
void main_diag_log_dataplane_ready(struct forwarder *fwd);

/* Log NE dataplane key only when KEY_SLOT_CURRENT is non-zero (after load/handshake). */
void main_diag_log_ne_policy_key(int policy_index, int db_id);
void main_diag_log_ne_keys_table(const struct app_config *cfg);

#endif
