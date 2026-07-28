#include "../../../../inc/core/iface_runtime.h"
#include "../../../../inc/core/iface_config_diff.h"
#include "../../../../inc/core/iface_ops.h"
#include "../../../../inc/core/iface_reload.h"
#include "../../../../inc/core/forwarder.h"
#include "../../../../inc/core/forwarder_reload.h"
#include "../../../../inc/core/interface.h"
#include "../../../../inc/core/main_diag.h"
#include "../../../../inc/core/xdp_attach.h"
#include "../../../../inc/db/db_runtime.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void ne_iface_runtime_init(struct ne_iface_runtime *rt, volatile sig_atomic_t *stop)
{
    memset(rt, 0, sizeof(*rt));
    rt->stop_requested = stop;
}

void *ne_iface_runtime_thread_main(void *arg)
{
    struct ne_iface_runtime *rt = arg;

    forwarder_pin_cpu();
    if (forwarder_init(&rt->fwd, &rt->cfg_slots[rt->active_slot]) != 0) {
        forwarder_cleanup(&rt->fwd);
        if (forwarder_should_stop())
            fprintf(stderr, "[STOP] forwarder init aborted\n");
        else
            fprintf(stderr, "[FATAL] forwarder_init failed\n");
        rt->running = 0;
        return NULL;
    }
    if (forwarder_should_stop()) {
        fprintf(stderr, "[STOP] forwarder init aborted\n");
        forwarder_cleanup(&rt->fwd);
        rt->running = 0;
        return NULL;
    }
    rt->running = 1;
    forwarder_run(&rt->fwd);
    rt->running = 0;
    return NULL;
}

int ne_iface_runtime_start(struct ne_iface_runtime *rt, const struct app_config *cfg)
{
    rt->active_slot = 0;
    rt->cfg_slots[rt->active_slot] = *cfg;
    rt->running = 0;
    if (pthread_create(&rt->thread, NULL, ne_iface_runtime_thread_main, rt) != 0) {
        fprintf(stderr, "[FATAL] failed to create forwarder thread\n");
        return -1;
    }
    rt->has_thread = 1;
    return 0;
}

static const struct app_config *runtime_active_cfg(struct ne_iface_runtime *rt)
{
    if (rt->fwd.cfg)
        return rt->fwd.cfg;
    return &rt->cfg_slots[rt->active_slot];
}

int ne_iface_runtime_stop_forwarder(struct ne_iface_runtime *rt)
{
    const struct app_config *cfg;

    if (!rt->has_thread)
        return 0;

    cfg = runtime_active_cfg(rt);
    fprintf(stderr, "[STOP] profile-xdp detach (all LAN/WAN)...\n");
    fflush(stderr);
    ne_xdp_attach_detach_config(cfg);

    fprintf(stderr, "[STOP] stopping dataplane...\n");
    fflush(stderr);
    forwarder_stop();
    forwarder_shutdown_resources();
    pthread_join(rt->thread, NULL);
    forwarder_cleanup(&rt->fwd);
    ne_xdp_attach_detach_config(cfg);
    interface_promisc_off_config(cfg);
    fprintf(stderr, "[STOP] done\n");
    fflush(stderr);
    rt->has_thread = 0;
    rt->running = 0;
    return 0;
}

int ne_iface_runtime_apply(struct ne_iface_runtime *rt, const int *active_ids,
                           int active_id_count, int trigger_id)
{
    struct app_config *merged_cfg = calloc(1, sizeof(*merged_cfg));
    int next_slot;
    const struct app_config *prev_cfg;
    int policy_only;
    int topo_ok;

    if (!merged_cfg) {
        fprintf(stderr, "[FATAL] out of memory building merged config\n");
        return -1;
    }
    if (build_merged_config(merged_cfg, active_ids, active_id_count, NULL) != 0) {
        fprintf(stderr,
                "[ERR] profile %d: failed to load config from Postgres (see [DB] lines above)\n",
                trigger_id);
        free(merged_cfg);
        return -1;
    }

    if (!rt->has_thread) {
        fprintf(stderr, "[LOAD] active:");
        for (int i = 0; i < active_id_count; i++)
            fprintf(stderr, " %d", active_ids[i]);
        fprintf(stderr, "\n");
        main_diag_log_db_apply(merged_cfg, trigger_id, NULL);
        int rc = ne_iface_runtime_start(rt, merged_cfg);
        free(merged_cfg);
        return rc != 0 ? -1 : 0;
    }

    next_slot = 1 - rt->active_slot;
    prev_cfg = &rt->cfg_slots[rt->active_slot];
    rt->cfg_slots[next_slot] = *merged_cfg;
    free(merged_cfg);

    if (ne_iface_cfg_db_unchanged(prev_cfg, &rt->cfg_slots[next_slot])) {
        fprintf(stderr,
                "[DB] profile %d — no change on first read (Postgres may not have committed yet), retry...\n",
                trigger_id);
        fflush(stderr);
        usleep(500000);
        if (build_merged_config(&rt->cfg_slots[next_slot], active_ids,
                                active_id_count, NULL) != 0) {
            fprintf(stderr,
                    "[ERR] profile %d: DB reload retry failed (see [DB] lines above)\n",
                    trigger_id);
            return -1;
        }
    }

    if (ne_iface_cfg_db_unchanged(prev_cfg, &rt->cfg_slots[next_slot])) {
        main_diag_log_no_update(trigger_id, prev_cfg);
        return 0;
    }

    policy_only = ne_iface_cfg_lan_wan_unchanged(prev_cfg, &rt->cfg_slots[next_slot]);
    topo_ok = forwarder_same_topology(prev_cfg, &rt->cfg_slots[next_slot]);

    if (policy_only)
        main_diag_log_db_policy_apply(&rt->cfg_slots[next_slot], trigger_id, prev_cfg);
    else
        main_diag_log_db_apply(&rt->cfg_slots[next_slot], trigger_id, prev_cfg);

    if (!topo_ok) {
        struct app_config *new_cfg = &rt->cfg_slots[next_slot];
        struct ne_iface_op_ctx op_ctx = {
            .fwd = &rt->fwd,
            .new_cfg = new_cfg,
            .old_cfg = prev_cfg,
            .profile_id = trigger_id,
        };
        int incremental_ok = 0;
        enum ne_iface_reload_path reload_path =
            ne_iface_reload_classify(prev_cfg, new_cfg);

        if (reload_path != NE_IFACE_RELOAD_PATH_NONE) {
            const char *path_label = "incremental LAN/WAN";
            if (reload_path == NE_IFACE_RELOAD_PATH_ADD_ONLY)
                path_label = "incremental LAN/WAN attach (add-only)";
            else if (reload_path == NE_IFACE_RELOAD_PATH_DELTA)
                path_label = "incremental LAN/WAN delta";
            else if (reload_path == NE_IFACE_RELOAD_PATH_ADD)
                path_label = "incremental LAN/WAN attach";
            else if (reload_path == NE_IFACE_RELOAD_PATH_REMOVE)
                path_label = "incremental LAN/WAN detach";
            else if (reload_path == NE_IFACE_RELOAD_PATH_EDIT)
                path_label = "incremental LAN/WAN edit";

            fprintf(stderr, "[RELOAD] profile %d — %s\n", trigger_id, path_label);
            fflush(stderr);
            if (ne_iface_reload_try_incremental(&op_ctx, reload_path) == 0)
                incremental_ok = 1;
            else
                fprintf(stderr,
                        "[RELOAD] incremental reload failed — keeping current dataplane\n");
        } else if (forwarder_is_wan_only_removal(prev_cfg, new_cfg)) {
            fprintf(stderr,
                    "[RELOAD] profile %d — WAN removed, drain %.1fs then detach (no hard cut)\n",
                    trigger_id, (double)FORWARDER_WAN_DRAIN_SEC);
            fflush(stderr);
            if (forwarder_reload_wan_removal(&rt->fwd, new_cfg) == 0)
                incremental_ok = 1;
            else
                fprintf(stderr,
                        "[RELOAD] WAN drain reload failed — keeping current dataplane\n");
        }

        if (incremental_ok) {
            rt->active_slot = next_slot;
            fprintf(stderr, "[RELOAD] OK profile %d — applied (incremental)\n", trigger_id);
            main_diag_log_config_summary(&rt->cfg_slots[rt->active_slot], trigger_id, 1, 0);
            fflush(stderr);
            return 0;
        }

        if (ne_iface_reload_any_predicate(prev_cfg, new_cfg) ||
            ne_iface_reload_is_edit_only(prev_cfg, new_cfg) ||
            forwarder_is_wan_only_removal(prev_cfg, new_cfg)) {
            fprintf(stderr,
                    "[ERR] profile %d: incremental reload failed — running dataplane unchanged\n",
                    trigger_id);
            fflush(stderr);
            return -1;
        }

        fprintf(stderr,
                "[RELOAD] profile %d — LAN/WAN topology changed — full dataplane restart\n",
                trigger_id);
        fflush(stderr);
        rt->active_slot = next_slot;
        if (ne_iface_runtime_stop_forwarder(rt) != 0)
            return -1;
        if (rt->stop_requested && *rt->stop_requested)
            return -1;
        if (ne_iface_runtime_start(rt, &rt->cfg_slots[rt->active_slot]) != 0)
            return -1;
        fprintf(stderr, "[RELOAD] OK profile %d — applied (full restart)\n", trigger_id);
        main_diag_log_config_summary(&rt->cfg_slots[rt->active_slot], trigger_id, 1, 0);
        fflush(stderr);
        return 0;
    }

    if (!policy_only) {
        if (ne_iface_cfg_tuning_only_change(prev_cfg, &rt->cfg_slots[next_slot])) {
            struct ne_iface_op_ctx op_ctx = {
                .fwd = &rt->fwd,
                .new_cfg = &rt->cfg_slots[next_slot],
                .old_cfg = prev_cfg,
                .profile_id = trigger_id,
            };

            fprintf(stderr,
                    "[RELOAD] profile %d — LAN/WAN edit/tuning (hot reload)\n",
                    trigger_id);
            fflush(stderr);
            if (ne_iface_op_iface_edit(&op_ctx) == 0) {
                rt->active_slot = next_slot;
                fprintf(stderr,
                        "[RELOAD] OK profile %d — applied (iface edit)\n",
                        trigger_id);
                main_diag_log_config_summary(&rt->cfg_slots[rt->active_slot],
                                             trigger_id, 1, 0);
                fflush(stderr);
                return 0;
            }
            fprintf(stderr,
                    "[RELOAD] iface edit failed; full dataplane restart\n");
            fflush(stderr);
        } else {
            fprintf(stderr,
                    "[RELOAD] profile %d — LAN/WAN settings changed — full dataplane restart\n",
                    trigger_id);
            fflush(stderr);
        }
        rt->active_slot = next_slot;
        if (ne_iface_runtime_stop_forwarder(rt) != 0)
            return -1;
        if (rt->stop_requested && *rt->stop_requested)
            return -1;
        if (ne_iface_runtime_start(rt, &rt->cfg_slots[rt->active_slot]) != 0)
            return -1;
        fprintf(stderr, "[RELOAD] OK profile %d — applied (full restart)\n", trigger_id);
        main_diag_log_config_summary(&rt->cfg_slots[rt->active_slot], trigger_id, 1, 0);
        fflush(stderr);
        return 0;
    }

    fprintf(stderr,
            "[RELOAD] profile %d — policies/crypto only (LAN/WAN ifaces unchanged)\n",
            trigger_id);
    fflush(stderr);

    {
        struct ne_iface_op_ctx op_ctx = {
            .fwd = &rt->fwd,
            .new_cfg = &rt->cfg_slots[next_slot],
            .old_cfg = prev_cfg,
            .profile_id = trigger_id,
        };
        if (ne_iface_op_profile_edit(&op_ctx) == 0) {
            rt->active_slot = next_slot;
            fprintf(stderr, "[RELOAD] OK profile %d — applied (hot reload)\n", trigger_id);
            fprintf(stderr, "[RELOAD] active:");
            for (int i = 0; i < active_id_count; i++)
                fprintf(stderr, " %d", active_ids[i]);
            fprintf(stderr, "\n");
            main_diag_log_config_summary(&rt->cfg_slots[rt->active_slot], trigger_id, 1, 1);
            fflush(stderr);
            return 0;
        }
    }
    fprintf(stderr,
            "[RELOAD] hot reload failed (see lines above); full dataplane restart\n");
    fflush(stderr);
    if (ne_iface_runtime_stop_forwarder(rt) != 0)
        return -1;
    if (rt->stop_requested && *rt->stop_requested)
        return -1;
    rt->active_slot = next_slot;
    if (ne_iface_runtime_start(rt, &rt->cfg_slots[rt->active_slot]) != 0)
        return -1;
    fprintf(stderr, "[RELOAD] OK profile %d — applied (full restart)\n", trigger_id);
    main_diag_log_config_summary(&rt->cfg_slots[rt->active_slot], trigger_id, 1, 0);
    fflush(stderr);
    return 0;
}
