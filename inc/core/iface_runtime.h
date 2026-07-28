#ifndef IFACE_RUNTIME_H
#define IFACE_RUNTIME_H

#include "config.h"
#include "forwarder.h"

#include <pthread.h>
#include <signal.h>

#define NE_IFACE_RUNTIME_MAX_PROFILES 32

struct ne_iface_runtime {
    pthread_t thread;
    int has_thread;
    int running;
    struct forwarder fwd;
    struct app_config cfg_slots[2];
    int active_slot;
    volatile sig_atomic_t *stop_requested;
};

void ne_iface_runtime_init(struct ne_iface_runtime *rt, volatile sig_atomic_t *stop);
int ne_iface_runtime_start(struct ne_iface_runtime *rt, const struct app_config *cfg);
int ne_iface_runtime_stop_forwarder(struct ne_iface_runtime *rt);
int ne_iface_runtime_apply(struct ne_iface_runtime *rt, const int *active_ids,
                           int active_id_count, int trigger_id);
void *ne_iface_runtime_thread_main(void *arg);

#endif
