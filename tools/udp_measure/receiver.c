/* receiver.c — dem loss/reorder. gcc -O2 -o receiver receiver.c */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define MAGIC 0x4E455544u
#define VER 1
#define FLAG_END 1
#define HDR 24
#define BATCH 128
#define MAX_C 64
#define JSON "result.json"
#define PAYLOAD_BYTE 0xA5u
/* 1 = check seq (loss/reorder/dup). 0 = chi check payload dung/sai. */
#define CHECK_SEQ 1
/* 8MB bitmap = 64M seq — du cho 5G x vai chuc giay @1400B */
#define BITMAP_PRE  (8u * 1024u * 1024u)

#pragma pack(push, 1)
struct hdr {
    uint32_t magic;
    uint8_t ver, flags;
    uint16_t flow;
    uint64_t seq, ts;
};
#pragma pack(pop)

static volatile int g_stop;

static uint64_t bswap64(uint64_t x) { return __builtin_bswap64(x); }

static double now_s(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

static void on_sig(int s)
{
    (void)s;
    g_stop = 1;
}

struct flow {
    uint8_t *bits;
    size_t bits_bytes;
    uint64_t recv, dup, reorder, max_seq, end_seq, corrupt;
    int ended;
    int64_t max_seen;
};

static struct flow g_fl[MAX_C];
static int g_expect;
static int g_pkt; /* 0 = khong ep size; >0 = phai dung -l */
static uint64_t g_invalid;

static int bit_set(struct flow *f, uint64_t seq)
{
    size_t bi = (size_t)(seq >> 3);
    uint8_t m = (uint8_t)(1u << (seq & 7));
    if (bi >= f->bits_bytes) {
        size_t nb = bi + 1;
        size_t grow = f->bits_bytes ? f->bits_bytes * 2 : BITMAP_PRE;
        if (grow < nb)
            grow = nb;
        {
            uint8_t *p = realloc(f->bits, grow);
            if (!p)
                return -1;
            memset(p + f->bits_bytes, 0, grow - f->bits_bytes);
            f->bits = p;
            f->bits_bytes = grow;
        }
    }
    if (f->bits[bi] & m)
        return 0;
    f->bits[bi] |= m;
    return 1;
}

static int bit_get(struct flow *f, uint64_t seq)
{
    size_t bi = (size_t)(seq >> 3);
    if (bi >= f->bits_bytes)
        return 0;
    return (f->bits[bi] >> (seq & 7)) & 1;
}

static void handle(const uint8_t *buf, int len)
{
    const struct hdr *h;
    uint16_t flow;
    uint64_t seq;
    struct flow *f;
    int r;

    if (len < HDR) {
        g_invalid++;
        return;
    }
    h = (const struct hdr *)buf;
    if (ntohl(h->magic) != MAGIC || h->ver != VER) {
        g_invalid++;
        return;
    }
    flow = ntohs(h->flow);
    seq = bswap64(h->seq);
    if (flow >= (uint16_t)g_expect)
        return;
    f = &g_fl[flow];

    if (h->flags & FLAG_END) {
        f->ended = 1;
        if (seq > f->end_seq)
            f->end_seq = seq;
        return;
    }

    if (g_pkt > 0 && len != g_pkt) {
        f->corrupt++;
        return;
    }
    {
        int b;
        for (b = HDR; b < len; b++) {
            if (buf[b] != PAYLOAD_BYTE) {
                f->corrupt++;
                return;
            }
        }
    }

    /* toi day: payload dung — moi tinh la goi tot */
    f->recv++;
    if (seq > f->max_seq)
        f->max_seq = seq;

    if (!CHECK_SEQ)
        return;

    r = bit_set(f, seq);
    if (r == 0) {
        f->dup++;
        return;
    }
    if (r < 0)
        return;

    if (f->max_seen >= 0 && (int64_t)seq < f->max_seen)
        f->reorder++;
    if ((int64_t)seq > f->max_seen)
        f->max_seen = (int64_t)seq;
}

static uint64_t count_loss(struct flow *f, uint64_t expected)
{
    uint64_t loss = 0, s;
    for (s = 0; s < expected; s++)
        if (!bit_get(f, s))
            loss++;
    return loss;
}

static void write_json(void)
{
    FILE *fp = fopen(JSON, "w");
    int i, first = 1;
        uint64_t te = 0, tr = 0, tl = 0, tro = 0, td = 0, tc = 0;

        if (!fp) {
            perror(JSON);
            return;
        }
        fprintf(fp, "{\n  \"status\": \"done\",\n  \"per_connect\": [\n");
        for (i = 0; i < g_expect; i++) {
            struct flow *f = &g_fl[i];
            uint64_t exp = f->ended ? f->end_seq : (f->max_seq ? f->max_seq + 1 : 0);
            uint64_t loss = CHECK_SEQ ? count_loss(f, exp) : 0;
            te += exp;
            tr += f->recv;
            tl += loss;
            tro += f->reorder;
            td += f->dup;
            tc += f->corrupt;
            if (!first)
                fprintf(fp, ",\n");
            first = 0;
            fprintf(fp,
                    "    {\"connect\": %d, \"expected\": %llu, \"recv\": %llu, "
                    "\"loss\": %llu, \"reorder\": %llu, \"dup\": %llu, "
                    "\"corrupt\": %llu, \"loss_pct\": %.4f}",
                    i, (unsigned long long)exp, (unsigned long long)f->recv,
                    (unsigned long long)loss, (unsigned long long)f->reorder,
                    (unsigned long long)f->dup, (unsigned long long)f->corrupt,
                    exp ? (100.0 * loss / exp) : 0.0);
        }
        fprintf(fp,
                "\n  ],\n  \"summary\": {\n"
                "    \"connects\": %d, \"expected\": %llu, \"recv\": %llu,\n"
                "    \"loss\": %llu, \"reorder\": %llu, \"dup\": %llu, \"corrupt\": %llu,\n"
                "    \"loss_pct\": %.4f, \"invalid\": %llu\n"
                "  }\n}\n",
                g_expect, (unsigned long long)te, (unsigned long long)tr, (unsigned long long)tl,
                (unsigned long long)tro, (unsigned long long)td, (unsigned long long)tc,
                te ? (100.0 * tl / te) : 0.0, (unsigned long long)g_invalid);
    fclose(fp);
    printf(">>> wrote %s\n", JSON);
}

static void report(void)
{
    int i;
    uint64_t te = 0, tr = 0, tl = 0, tro = 0, td = 0, tc = 0;

    printf("\n========== PER CONNECT ==========\n");
    for (i = 0; i < g_expect; i++) {
        struct flow *f = &g_fl[i];
        uint64_t exp = f->ended ? f->end_seq : (f->max_seq ? f->max_seq + 1 : 0);
        uint64_t loss = CHECK_SEQ ? count_loss(f, exp) : 0;
        te += exp;
        tr += f->recv;
        tl += loss;
        tro += f->reorder;
        td += f->dup;
        tc += f->corrupt;
        printf("connect %d: expected=%llu recv=%llu loss=%llu reorder=%llu dup=%llu corrupt=%llu loss%%=%.4f\n",
               i, (unsigned long long)exp, (unsigned long long)f->recv, (unsigned long long)loss,
               (unsigned long long)f->reorder, (unsigned long long)f->dup,
               (unsigned long long)f->corrupt, exp ? (100.0 * loss / exp) : 0.0);
    }
    printf("========== SUMMARY ==========\n");
    printf("connects=%d expected=%llu recv=%llu loss=%llu reorder=%llu dup=%llu corrupt=%llu loss%%=%.4f invalid=%llu\n",
           g_expect, (unsigned long long)te, (unsigned long long)tr, (unsigned long long)tl,
           (unsigned long long)tro, (unsigned long long)td, (unsigned long long)tc,
           te ? (100.0 * tl / te) : 0.0, (unsigned long long)g_invalid);
    if (tc)
        printf("*** PAYLOAD SAI: sender PAYLOAD_BYTE khac 0x%02X (corrupt=%llu, recv tot=%llu) ***\n",
               PAYLOAD_BYTE, (unsigned long long)tc, (unsigned long long)tr);
}

int main(int argc, char **argv)
{
    char bip[64] = "0.0.0.0";
    int port = 0, fd, i, ended, empty_spins;
    struct sockaddr_in addr;
    uint8_t *bufs[BATCH];
    struct mmsghdr msgs[BATCH];
    struct iovec iov[BATCH];
    double last_rep, last_pkt;
    uint64_t live_b = 0;

    for (i = 0; i < MAX_C; i++) {
        memset(&g_fl[i], 0, sizeof(g_fl[i]));
        g_fl[i].max_seen = -1;
    }

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--bind-ip") && i + 1 < argc)
            snprintf(bip, sizeof(bip), "%s", argv[++i]);
        else if (!strcmp(argv[i], "--port") && i + 1 < argc)
            port = atoi(argv[++i]);
        else if ((!strcmp(argv[i], "-c") || !strcmp(argv[i], "--expect-connects")) && i + 1 < argc)
            g_expect = atoi(argv[++i]);
        else if ((!strcmp(argv[i], "-l") || !strcmp(argv[i], "--packet-size")) && i + 1 < argc)
            g_pkt = atoi(argv[++i]);
        else {
            fprintf(stderr, "usage: %s --bind-ip IP --port P -c N [-l BYTES]\n", argv[0]);
            return 2;
        }
    }
    if (port <= 0 || g_expect < 1 || g_expect > MAX_C) {
        fprintf(stderr, "usage: %s --bind-ip IP --port P -c N [-l BYTES]\n", argv[0]);
        return 2;
    }
    if (g_pkt != 0 && (g_pkt < HDR || g_pkt > 2048)) {
        fprintf(stderr, "-l must be 0 (any) or %d..2048\n", HDR);
        return 2;
    }

    for (i = 0; i < g_expect; i++) {
        g_fl[i].bits = calloc(1, BITMAP_PRE);
        g_fl[i].bits_bytes = BITMAP_PRE;
        if (!g_fl[i].bits) {
            perror("calloc bitmap");
            return 1;
        }
    }

    {
        FILE *fp = fopen(JSON, "w");
        if (fp) {
            fputs("{\"status\":\"running\"}\n", fp);
            fclose(fp);
        }
    }

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        return 1;
    }
    {
        int on = 1, sz = 256 * 1024 * 1024;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
        setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &sz, sizeof(sz));
#ifdef SO_RCVBUFFORCE
        setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &sz, sizeof(sz));
#endif
#ifdef SO_BUSY_POLL
        {
            int bp = 50; /* usec */
            setsockopt(fd, SOL_SOCKET, SO_BUSY_POLL, &bp, sizeof(bp));
        }
#endif
    }
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    inet_pton(AF_INET, bip, &addr.sin_addr);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 1;
    }

    for (i = 0; i < BATCH; i++) {
        bufs[i] = malloc(2048);
        memset(&msgs[i], 0, sizeof(msgs[i]));
        iov[i].iov_base = bufs[i];
        iov[i].iov_len = 2048;
        msgs[i].msg_hdr.msg_iov = &iov[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
    }

    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);
    printf("receiver %s:%d expect_connects=%d pkt=%d%s payload=0x%02X seq_check=%s\n",
           bip, port, g_expect, g_pkt, g_pkt ? "" : " (any size)", PAYLOAD_BYTE,
           CHECK_SEQ ? "ON" : "OFF");
    printf("*** sender -c PHAI = %d ***\n", g_expect);

    last_rep = last_pkt = now_s();
    empty_spins = 0;
    while (!g_stop) {
        int n = recvmmsg(fd, msgs, BATCH, MSG_DONTWAIT, NULL);
        double t = now_s();

        if (n > 0) {
            empty_spins = 0;
            for (i = 0; i < n; i++) {
                handle(bufs[i], (int)msgs[i].msg_len);
                live_b += msgs[i].msg_len;
            }
            last_pkt = t;
        } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
            perror("recvmmsg");
            break;
        } else {
            empty_spins++;
            if (empty_spins > 10000) {
                struct timespec sl = {0, 50000};
                nanosleep(&sl, NULL);
                empty_spins = 0;
            }
        }

        if (t - last_rep >= 1.0) {
            uint64_t tc = 0, tr = 0;
            double dt = t - last_rep;
            ended = 0;
            for (i = 0; i < g_expect; i++) {
                if (g_fl[i].ended)
                    ended++;
                tc += g_fl[i].corrupt;
                tr += g_fl[i].recv;
            }
            printf("  [live] ended=%d/%d %.3f Mbps  recv=%llu corrupt=%llu\n", ended, g_expect,
                   (live_b * 8.0 / dt) / 1e6, (unsigned long long)tr, (unsigned long long)tc);
            fflush(stdout);
            live_b = 0;
            last_rep = t;
        }

        ended = 0;
        for (i = 0; i < g_expect; i++)
            if (g_fl[i].ended)
                ended++;
        if (ended >= g_expect && (t - last_pkt) >= 0.3)
            break;
        if (ended > 0 && ended < g_expect && (t - last_pkt) >= 2.0) {
            fprintf(stderr, "STOP: chi %d/%d END\n", ended, g_expect);
            break;
        }
    }

    report();
    write_json();

    for (i = 0; i < BATCH; i++)
        free(bufs[i]);
    for (i = 0; i < MAX_C; i++)
        free(g_fl[i].bits);
    close(fd);
    return 0;
}
