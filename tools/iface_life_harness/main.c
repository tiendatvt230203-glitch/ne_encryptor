#include "xsk.h"

#include <net/if.h>
#include <stdio.h>
#include <unistd.h>

#define LAN0 "enp6s0"
#define WAN0 "eno3"
#define LAN1 "eno2"
#define WAN1 "eno4"

static struct hx g;
static int fail;

static int need_if(const char *name)
{
    if (if_nametoindex(name))
        return 0;
    fprintf(stderr, "[HARNESS] missing iface %s\n", name);
    return -1;
}

static int br_add(const char *step, int pid, const char *lan, const char *wan)
{
    fprintf(stderr, "[HARNESS] ADD BR profile=%d LAN=%s WAN=%s\n", pid, lan, wan);
    if (hx_add(&g, lan, 1) != 0) {
        fprintf(stderr, "[HARNESS] FAIL %s: LAN %s\n", step, lan);
        hx_dump(&g, step);
        fail = 1;
        return -1;
    }
    if (hx_add(&g, wan, 0) != 0) {
        fprintf(stderr, "[HARNESS] FAIL %s: WAN %s\n", step, wan);
        hx_dump(&g, step);
        fail = 1;
        return -1;
    }
    hx_dump(&g, step);
    if (!hx_ok(&g, lan) || !hx_ok(&g, wan)) {
        fprintf(stderr, "[HARNESS] FAIL %s: BR not live\n", step);
        fail = 1;
        return -1;
    }
    fprintf(stderr, "[HARNESS] PASS %s\n", step);
    return 0;
}

static int br_del(const char *step, int pid, const char *lan, const char *wan)
{
    fprintf(stderr, "[HARNESS] DEL BR profile=%d LAN=%s WAN=%s\n", pid, lan, wan);
    if (hx_del(&g, wan) != 0 || hx_del(&g, lan) != 0) {
        fprintf(stderr, "[HARNESS] FAIL %s: kernel del\n", step);
        hx_dump(&g, step);
        fail = 1;
        return -1;
    }
    hx_dump(&g, step);
    if (hx_ok(&g, lan) || hx_ok(&g, wan)) {
        fprintf(stderr, "[HARNESS] FAIL %s: still live\n", step);
        fail = 1;
        return -1;
    }
    fprintf(stderr, "[HARNESS] PASS %s\n", step);
    return 0;
}

int main(void)
{
    if (geteuid() != 0) {
        fprintf(stderr, "[HARNESS] need root\n");
        return 1;
    }
    if (need_if(LAN0) || need_if(WAN0) || need_if(LAN1) || need_if(WAN1))
        return 1;

    fail = 0;
    if (hx_open(&g, "lan.o", "wan.o") != 0)
        return 1;

    fprintf(stderr, "[HARNESS] ADD PROFILE id=1\n");
    if (br_add("add_profile", 1, LAN0, WAN0) != 0)
        goto out;

    if (br_add("add_br", 1, LAN1, WAN1) != 0)
        goto out;

    if (br_del("del_br", 1, LAN1, WAN1) != 0)
        goto out;

    fprintf(stderr, "[HARNESS] ADD PROFILE id=2\n");
    if (br_add("add_profile2", 2, LAN1, WAN1) != 0)
        goto out;

    fprintf(stderr, "[HARNESS] DEL PROFILE id=2\n");
    if (br_del("del_profile2", 2, LAN1, WAN1) != 0)
        goto out;

    fprintf(stderr, "[HARNESS] EDIT BR profile=1: return %s/%s -> load %s/%s\n",
            LAN0, WAN0, LAN1, WAN1);
    if (hx_del(&g, WAN0) != 0 || hx_del(&g, LAN0) != 0) {
        fprintf(stderr, "[HARNESS] FAIL edit_br: return old\n");
        hx_dump(&g, "edit_br");
        fail = 1;
        goto out;
    }
    if (hx_add(&g, LAN1, 1) != 0 || hx_add(&g, WAN1, 0) != 0) {
        fprintf(stderr, "[HARNESS] FAIL edit_br: load new\n");
        hx_dump(&g, "edit_br");
        fail = 1;
        goto out;
    }
    hx_dump(&g, "edit_br");
    if (hx_ok(&g, LAN0) || hx_ok(&g, WAN0) || !hx_ok(&g, LAN1) || !hx_ok(&g, WAN1)) {
        fprintf(stderr, "[HARNESS] FAIL edit_br: state wrong\n");
        fail = 1;
        goto out;
    }
    fprintf(stderr, "[HARNESS] PASS edit_br\n");

out:
    hx_close(&g);
    fprintf(stderr, fail ? "[HARNESS] FAIL\n" : "[HARNESS] ALL PASS\n");
    return fail ? 1 : 0;
}
