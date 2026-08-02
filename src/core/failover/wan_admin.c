#include "../../../inc/core/wan_admin.h"
#include "../../../inc/core/config.h"
#include "../../../inc/core/forwarder.h"
#include "../../../inc/core/forwarder_wan.h"
#include "../../../inc/core/interface.h"
#include "../../../inc/core/profile_iface_lifecycle.h"

#include <errno.h>
#include <net/if.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

enum {
    WAN_ADMIN_OP_NONE = 0,
    WAN_ADMIN_OP_KICK = 1,
    WAN_ADMIN_OP_RESTORE = 2
};

static atomic_int admin_pending;
static atomic_int admin_done;
static struct forwarder *admin_fwd;
static int admin_op;
static char admin_ifname[IF_NAMESIZE];
static int admin_rc;
static pthread_mutex_t admin_wait_mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t admin_wait_cv = PTHREAD_COND_INITIALIZER;

static char kicked_ifnames[MAX_INTERFACES][IF_NAMESIZE];
static int kicked_n;
static pthread_mutex_t kicked_mtx = PTHREAD_MUTEX_INITIALIZER;

static void kicked_remember(const char *ifname)
{
    if (!ifname || !ifname[0])
        return;
    pthread_mutex_lock(&kicked_mtx);
    for (int i = 0; i < kicked_n; i++) {
        if (strcmp(kicked_ifnames[i], ifname) == 0) {
            pthread_mutex_unlock(&kicked_mtx);
            return;
        }
    }
    if (kicked_n < MAX_INTERFACES) {
        strncpy(kicked_ifnames[kicked_n], ifname, IF_NAMESIZE - 1);
        kicked_ifnames[kicked_n][IF_NAMESIZE - 1] = '\0';
        kicked_n++;
    }
    pthread_mutex_unlock(&kicked_mtx);
}

static void kicked_forget(const char *ifname)
{
    int w = 0;

    if (!ifname)
        return;
    pthread_mutex_lock(&kicked_mtx);
    for (int i = 0; i < kicked_n; i++) {
        if (strcmp(kicked_ifnames[i], ifname) == 0)
            continue;
        if (w != i)
            memcpy(kicked_ifnames[w], kicked_ifnames[i], IF_NAMESIZE);
        w++;
    }
    kicked_n = w;
    pthread_mutex_unlock(&kicked_mtx);
}

static int find_cfg_wan_idx(const struct app_config *cfg, const char *ifname)
{
    if (!cfg || !ifname)
        return -1;
    for (int i = 0; i < cfg->wan_count; i++) {
        if (strcmp(cfg->wans[i].ifname, ifname) == 0)
            return i;
    }
    return -1;
}

static int owner_profile_for_ifname(const struct app_config *cfg, const char *ifname)
{
    int ci = find_cfg_wan_idx(cfg, ifname);
    if (ci < 0)
        return 0;
    return config_wan_owner_profile(cfg, ci, -1);
}

static int wan_admin_apply_kick(struct forwarder *fwd, const char *ifname)
{
    int profile_id;
    int di = -1;
    int n;

    if (!fwd || !fwd->cfg || !ifname || !ifname[0])
        return -1;

    n = fwd->pair.wan_count;
    if (n < fwd->wan_count)
        n = fwd->wan_count;
    if (n > MAX_INTERFACES)
        n = MAX_INTERFACES;
    for (int i = 0; i < n; i++) {
        if (!ne_pair_wan_live(&fwd->pair, i))
            continue;
        if (fwd->wans[i].ifname[0] && strcmp(fwd->wans[i].ifname, ifname) == 0) {
            di = i;
            break;
        }
        if (fwd->pair.wans[i].ifname[0] &&
            strcmp(fwd->pair.wans[i].ifname, ifname) == 0) {
            di = i;
            break;
        }
    }
    if (di < 0) {
        fprintf(stderr, "[WAN-ADMIN] KICK %s — already not live\n", ifname);
        fflush(stderr);
        kicked_remember(ifname);
        return 0;
    }

    profile_id = owner_profile_for_ifname(fwd->cfg, ifname);
    fprintf(stderr, "[WAN-ADMIN] KICK WAN %s (profile=%d dp=%d)\n",
            ifname, profile_id, di);
    fflush(stderr);

    if (profile_iface_life_detach_wan(fwd, ifname, profile_id) != 0)
        return -1;
    kicked_remember(ifname);
    fprintf(stderr, "[WAN-ADMIN] KICK OK %s\n", ifname);
    fflush(stderr);
    return 0;
}

static int wan_admin_apply_restore(struct forwarder *fwd, const char *ifname)
{
    int profile_id;
    int ci;

    if (!fwd || !fwd->cfg || !ifname || !ifname[0])
        return -1;

    ci = find_cfg_wan_idx(fwd->cfg, ifname);
    if (ci < 0 || !config_wan_live(fwd->cfg, ci)) {
        fprintf(stderr, "[WAN-ADMIN] RESTORE %s — not dataplane in cfg\n", ifname);
        fflush(stderr);
        return -1;
    }

    profile_id = owner_profile_for_ifname(fwd->cfg, ifname);
    fprintf(stderr, "[WAN-ADMIN] RESTORE WAN %s (profile=%d)\n", ifname, profile_id);
    fflush(stderr);

    if (profile_iface_life_attach_wan_ifname(fwd, fwd->cfg, ifname, profile_id) != 0)
        return -1;
    kicked_forget(ifname);
    fprintf(stderr, "[WAN-ADMIN] RESTORE OK %s\n", ifname);
    fflush(stderr);
    return 0;
}

static int wan_admin_queue(struct forwarder *fwd, int op, const char *ifname)
{
    if (!fwd || !ifname || !ifname[0] || op == WAN_ADMIN_OP_NONE)
        return -1;
    if (!fwd->threads_started) {
        fprintf(stderr, "[WAN-ADMIN] dataplane not running yet\n");
        fflush(stderr);
        return -1;
    }

    pthread_mutex_lock(&admin_wait_mtx);
    if (atomic_load_explicit(&admin_pending, memory_order_acquire) &&
        !atomic_load_explicit(&admin_done, memory_order_acquire)) {
        pthread_mutex_unlock(&admin_wait_mtx);
        fprintf(stderr, "[WAN-ADMIN] busy\n");
        fflush(stderr);
        return -1;
    }

    admin_fwd = fwd;
    admin_op = op;
    strncpy(admin_ifname, ifname, IF_NAMESIZE - 1);
    admin_ifname[IF_NAMESIZE - 1] = '\0';
    admin_rc = -1;
    atomic_store_explicit(&admin_done, 0, memory_order_release);
    atomic_store_explicit(&admin_pending, 1, memory_order_release);

    struct timespec deadline;
    int have_deadline = 0;
    if (clock_gettime(CLOCK_REALTIME, &deadline) == 0) {
        deadline.tv_sec += 30;
        have_deadline = 1;
    }

    while (!atomic_load_explicit(&admin_done, memory_order_acquire)) {
        struct timespec ts;
        if (have_deadline) {
            ts = deadline;
        } else if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
            pthread_cond_wait(&admin_wait_cv, &admin_wait_mtx);
            continue;
        } else {
            ts.tv_nsec += 200000000L;
            if (ts.tv_nsec >= 1000000000L) {
                ts.tv_sec++;
                ts.tv_nsec -= 1000000000L;
            }
        }
        int wr = pthread_cond_timedwait(&admin_wait_cv, &admin_wait_mtx, &ts);
        if (have_deadline && wr == ETIMEDOUT) {
            fprintf(stderr, "[WAN-ADMIN] timed out (30s)\n");
            fflush(stderr);
            atomic_store_explicit(&admin_pending, 0, memory_order_release);
            break;
        }
    }

    int rc = admin_rc;
    int finished = atomic_load_explicit(&admin_done, memory_order_acquire);
    pthread_mutex_unlock(&admin_wait_mtx);
    if (!finished)
        return -1;
    return rc;
}

int wan_admin_kick(struct forwarder *fwd, const char *ifname)
{
    return wan_admin_queue(fwd, WAN_ADMIN_OP_KICK, ifname);
}

int wan_admin_restore(struct forwarder *fwd, const char *ifname)
{
    return wan_admin_queue(fwd, WAN_ADMIN_OP_RESTORE, ifname);
}

int fwd_wan_admin_apply_if_pending(void)
{
    struct forwarder *fwd;
    char ifname[IF_NAMESIZE];
    int op;

    if (!atomic_load_explicit(&admin_pending, memory_order_acquire))
        return 0;

    fwd = admin_fwd;
    op = admin_op;
    memcpy(ifname, admin_ifname, sizeof(ifname));
    if (!fwd) {
        admin_rc = -1;
        goto done;
    }

    switch (op) {
    case WAN_ADMIN_OP_KICK:
        admin_rc = wan_admin_apply_kick(fwd, ifname);
        break;
    case WAN_ADMIN_OP_RESTORE:
        admin_rc = wan_admin_apply_restore(fwd, ifname);
        break;
    default:
        admin_rc = -1;
        break;
    }

done:
    admin_op = WAN_ADMIN_OP_NONE;
    atomic_store_explicit(&admin_pending, 0, memory_order_release);
    atomic_store_explicit(&admin_done, 1, memory_order_release);
    pthread_mutex_lock(&admin_wait_mtx);
    pthread_cond_broadcast(&admin_wait_cv);
    pthread_mutex_unlock(&admin_wait_mtx);
    return 1;
}

void wan_admin_shutdown(void)
{
    atomic_store_explicit(&admin_pending, 0, memory_order_release);
    atomic_store_explicit(&admin_done, 1, memory_order_release);
    pthread_mutex_lock(&admin_wait_mtx);
    admin_rc = -1;
    pthread_cond_broadcast(&admin_wait_cv);
    pthread_mutex_unlock(&admin_wait_mtx);
}
