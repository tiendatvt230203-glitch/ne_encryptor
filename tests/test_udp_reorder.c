#include "core/dataplane/udp_reorder.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define TEST_WORKER 0

struct capture {
    uint32_t emitted[1024];
    size_t emitted_n;
    size_t dropped;
};

static int capture_emit(void *ctx, struct dp_udp_reorder_item *item)
{
    struct capture *cap = ctx;

    assert(cap->emitted_n < sizeof(cap->emitted) / sizeof(cap->emitted[0]));
    cap->emitted[cap->emitted_n++] = (uint32_t)item->packet.addr;
    return 0;
}

static void capture_drop(void *ctx, struct dp_udp_reorder_item *item)
{
    struct capture *cap = ctx;

    (void)item;
    cap->dropped++;
}

static void submit(struct capture *cap, const struct dp_udp_reorder_key *key,
                   uint32_t epoch, uint32_t seq, uint64_t now_ns)
{
    struct dp_udp_reorder_item item;
    struct dp_udp_reorder_ops ops = {
        .ctx = cap,
        .emit = capture_emit,
        .drop = capture_drop,
    };

    memset(&item, 0, sizeof(item));
    item.packet.addr = seq;
    item.packet.len = 100;
    dp_udp_reorder_submit(TEST_WORKER, key, epoch, seq, &item, now_ns, &ops);
}

static void reset(struct capture *cap)
{
    struct dp_udp_reorder_ops ops = {
        .ctx = cap,
        .emit = capture_emit,
        .drop = capture_drop,
    };

    dp_udp_reorder_reset_worker(TEST_WORKER, &ops);
    memset(cap, 0, sizeof(*cap));
}

static void run_gc(struct capture *cap, uint64_t now_ns)
{
    struct dp_udp_reorder_ops ops = {
        .ctx = cap,
        .emit = capture_emit,
        .drop = capture_drop,
    };

    for (int i = 0; i < 40; i++)
        dp_udp_reorder_gc(TEST_WORKER, now_ns, &ops);
}

int main(void)
{
    struct capture cap = {0};
    struct dp_udp_reorder_key key = {
        .src_ip = 0x0a000001u,
        .dst_ip = 0x0a000002u,
        .src_port = 10000,
        .dst_port = 5201,
    };
    const uint64_t t0 = 1000000000ULL;

    submit(&cap, &key, 1, 0, t0);
    submit(&cap, &key, 1, 2, t0 + 1000);
    submit(&cap, &key, 1, 1, t0 + 2000);
    assert(cap.emitted_n == 3);
    assert(cap.emitted[0] == 0 && cap.emitted[1] == 1 && cap.emitted[2] == 2);

    reset(&cap);
    key.src_port++;
    submit(&cap, &key, 2, 1, t0);
    assert(cap.emitted_n == 0);
    submit(&cap, &key, 2, 0, t0 + 1000);
    assert(cap.emitted_n == 2 && cap.emitted[0] == 0 && cap.emitted[1] == 1);

    reset(&cap);
    key.src_port++;
    submit(&cap, &key, 3, 0, t0);
    submit(&cap, &key, 3, 2, t0 + 1000);
    submit(&cap, &key, 3, 3, t0 + 3000000ULL);
    assert(cap.emitted_n == 3);
    assert(cap.emitted[0] == 0 && cap.emitted[1] == 2 && cap.emitted[2] == 3);

    reset(&cap);
    key.src_port++;
    submit(&cap, &key, 4, 0, t0);
    submit(&cap, &key, 4, 0, t0 + 1000);
    assert(cap.emitted_n == 1 && cap.dropped == 1);

    reset(&cap);
    key.src_port++;
    submit(&cap, &key, 5, UINT32_MAX - 1u, t0);
    submit(&cap, &key, 5, UINT32_MAX, t0 + 1000);
    submit(&cap, &key, 5, 0, t0 + 2000);
    submit(&cap, &key, 5, 1, t0 + 3000);
    assert(cap.emitted_n == 0);
    run_gc(&cap, t0 + 3000000ULL);
    assert(cap.emitted_n == 4);
    assert(cap.emitted[0] == UINT32_MAX - 1u);
    assert(cap.emitted[1] == UINT32_MAX);
    assert(cap.emitted[2] == 0 && cap.emitted[3] == 1);

    reset(&cap);
    key.src_port++;
    submit(&cap, &key, 6, 1, t0);
    submit(&cap, &key, 7, 0, t0 + 1000);
    assert(cap.emitted_n == 1 && cap.emitted[0] == 0);
    assert(cap.dropped == 1); /* old epoch's held seq=1 */

    reset(&cap);
    puts("udp reorder: ok");
    return 0;
}
