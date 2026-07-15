#ifndef FORWARDER_CRYPTO_RUNTIME_H
#define FORWARDER_CRYPTO_RUNTIME_H

#include "config.h"
#include "forwarder.h"
#include "flow_table.h"
#include "fragment.h"
#include "../crypto/crypto_dispatch.h"
#include "../crypto/packet_crypto.h"

#define FWD_CRYPTO_PROFILE_RELOAD_GRACE_MS 3000u

void fwd_crypto_reset_on_init(void);
void fwd_crypto_cleanup_all_profile_slots(void);
int fwd_crypto_rebuild(struct app_config *cfg);
int fwd_crypto_ensure_profile_slots(struct app_config *cfg);
void fwd_crypto_snapshot_active_to_prev(void);
void fwd_crypto_maybe_expire_prev_grace(void);
void fwd_crypto_clear_grace(void);
void fwd_crypto_sync_flow_table_windows(struct forwarder *fwd);
void fwd_crypto_cleanup_stale_profile_slots(const struct app_config *cfg);
void fwd_crypto_frag_gc_worker_tick(int worker_idx);

int fwd_crypto_profile_slot_for_id(int profile_id);
int fwd_crypto_flow_table_ready(int slot);
struct flow_table *fwd_crypto_flow_table(int slot);

struct crypto_dispatch_ctx fwd_crypto_make_dispatch_ctx(void);
struct packet_crypto_ctx *fwd_crypto_ctx_for_wire_id(uint8_t wire_id);
int fwd_crypto_profile_id_for_wire_id(uint8_t wire_id);
int fwd_crypto_policy_ready(int policy_index);
struct packet_crypto_ctx *fwd_crypto_policy_ctx(int policy_index);
int fwd_crypto_has_l2_marker(const uint8_t *pkt, uint32_t pkt_len);

struct frag_table *fwd_crypto_frag_l2(int slot, int worker_idx);
struct frag_table *fwd_crypto_frag_l3(int slot, int worker_idx);
struct frag_table *fwd_crypto_frag_l4(int slot, int worker_idx);

void forwarder_pre_diversify_pqc_keys(int profile_id);

#endif