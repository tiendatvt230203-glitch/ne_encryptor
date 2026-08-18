/* sender.c — UDP seq sender, pace dung -b. gcc -O2 -pthread -o sender sender.c */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
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
#define BATCH 64
#define MAX_C 64
#define PAYLOAD_BYTE 0xA5u
#define PAYLOAD_BAD  0xA7u

enum {
    MODE_OK = 0,
    MODE_SHUFFLE,
    MODE_MISS,
    MODE_BAD
};

static const char *mode_name(int m)
{
    switch (m) {
    case MODE_SHUFFLE:
        return "shuffle-seq";
    case MODE_MISS:
        return "miss-seq";
    case MODE_BAD:
        return "bad-payload";
    default:
        return "ok";
    }
}

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

static int parse_bps(const char *s, double *out)
{
    char *e = NULL;
    double v = strtod(s, &e), m = 1;
    if (e == s || v <= 0)
        return -1;
    if (*e == 'K' || *e == 'k')
        m = 1e3;
    else if (*e == 'M' || *e == 'm')
        m = 1e6;
    else if (*e == 'G' || *e == 'g')
        m = 1e9;
    *out = v * m;
    return 0;
}

struct args {
    char src[64], dst[64];
    int dport, connects, pkt, sport0, ends, mode;
    double bps, dur;
};

struct warg {
    struct args *a;
    int id;
    uint64_t sent;
};

static void on_sig(int s)
{
    (void)s;
    g_stop = 1;
}

static void *worker(void *arg)
{
    struct warg *w = arg;
    struct args *a = w->a;
    int fd, i, sent_ok;
    struct sockaddr_in sin, din;
    uint8_t *bufs[BATCH];
    struct mmsghdr msgs[BATCH];
    struct iovec iov[BATCH];
    double t0, report_t, bps_B;
    uint64_t seq = 0, sent_bytes = 0, report_b = 0, max_wire = 0;
    uint64_t ts_be;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        return NULL;
    }
    {
        int sz = 128 * 1024 * 1024;
        setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sz, sizeof(sz));
    }

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons((uint16_t)(a->sport0 + w->id));
    inet_pton(AF_INET, a->src, &sin.sin_addr);
    if (bind(fd, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        perror("bind");
        close(fd);
        return NULL;
    }
    memset(&din, 0, sizeof(din));
    din.sin_family = AF_INET;
    din.sin_port = htons((uint16_t)a->dport);
    inet_pton(AF_INET, a->dst, &din.sin_addr);

    for (i = 0; i < BATCH; i++) {
        bufs[i] = calloc(1, (size_t)a->pkt);
        if (!bufs[i])
            abort();
        memset(&msgs[i], 0, sizeof(msgs[i]));
        iov[i].iov_base = bufs[i];
        iov[i].iov_len = (size_t)a->pkt;
        msgs[i].msg_hdr.msg_iov = &iov[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
        msgs[i].msg_hdr.msg_name = &din;
        msgs[i].msg_hdr.msg_namelen = sizeof(din);
        {
            struct hdr *h = (struct hdr *)bufs[i];
            h->magic = htonl(MAGIC);
            h->ver = VER;
            h->flags = 0;
            h->flow = htons((uint16_t)w->id);
            if (a->pkt > HDR)
                memset(bufs[i] + HDR,
                       a->mode == MODE_BAD ? PAYLOAD_BAD : PAYLOAD_BYTE,
                       (size_t)(a->pkt - HDR));
        }
    }

    bps_B = a->bps / 8.0;
    t0 = report_t = now_s();
    ts_be = bswap64(0);

    while (!g_stop) {
        double t = now_s();
        double allow;

        if (t - t0 >= a->dur)
            break;

        /* pace: chi gui khi sent_bytes < elapsed * rate */
        allow = (t - t0) * bps_B;
        if ((double)sent_bytes >= allow) {
            /* spin ngan — nanosleep qua tho o multi-Gbps */
            while (!g_stop) {
                t = now_s();
                if (t - t0 >= a->dur)
                    goto done;
                allow = (t - t0) * bps_B;
                if ((double)sent_bytes < allow)
                    break;
            }
            continue;
        }

        ts_be = bswap64((uint64_t)(t * 1e9));
        for (i = 0; i < BATCH; i++) {
            struct hdr *h = (struct hdr *)bufs[i];
            uint64_t s = seq + (uint64_t)i;

            if (a->mode == MODE_SHUFFLE) {
                if ((i & 1) == 0 && i + 1 < BATCH)
                    s = seq + (uint64_t)(i + 1);
                else if (i & 1)
                    s = seq + (uint64_t)(i - 1);
            } else if (a->mode == MODE_MISS)
                s = (s < 5) ? s : (1000000ull + (s - 5ull));
            h->seq = bswap64(s);
            h->ts = ts_be;
            if (s > max_wire)
                max_wire = s;
        }

        sent_ok = sendmmsg(fd, msgs, BATCH, 0);
        if (sent_ok < 0) {
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                continue;
            perror("sendmmsg");
            break;
        }

        seq += (uint64_t)sent_ok;
        w->sent += (uint64_t)sent_ok;
        sent_bytes += (uint64_t)sent_ok * (uint64_t)a->pkt;
        report_b += (uint64_t)sent_ok * (uint64_t)a->pkt;

        t = now_s();
        if (t - report_t >= 1.0) {
            double dt = t - report_t;
            printf("  [live] flow %d: %.3f Mbps (target %.3f)\n", w->id,
                   (report_b * 8.0 / dt) / 1e6, a->bps / 1e6);
            fflush(stdout);
            report_t = t;
            report_b = 0;
        }
    }

done:
    {
        uint8_t endb[HDR];
        struct hdr *h = (struct hdr *)endb;
        memset(endb, 0, sizeof(endb));
        h->magic = htonl(MAGIC);
        h->ver = VER;
        h->flags = FLAG_END;
        h->flow = htons((uint16_t)w->id);
        h->seq = bswap64(max_wire + 1);
        for (i = 0; i < a->ends; i++)
            sendto(fd, endb, HDR, 0, (struct sockaddr *)&din, sizeof(din));
    }

    for (i = 0; i < BATCH; i++)
        free(bufs[i]);
    close(fd);
    printf("  flow %d: done sent=%llu avg=%.3f Mbps\n", w->id,
           (unsigned long long)w->sent,
           a->dur > 0 ? (sent_bytes * 8.0 / a->dur) / 1e6 : 0.0);
    return NULL;
}

static void usage(const char *p)
{
    fprintf(stderr,
            "usage: %s --src-ip IP --dst-ip IP --dst-port P [-c N] [-b BPS] [-t SEC] [-l BYTES]\n"
            "         [--mode ok|shuffle|miss|bad]\n"
            "  ok       gui dung (mac dinh)\n"
            "  shuffle  xao cap seq (0,1 -> 1,0)  → receiver reorder\n"
            "  miss     gui 0 1 2 3 4 roi nhay seq 1000000 (bo 5..999999)\n"
            "           → receiver loss, khong can bao truoc cho receiver\n"
            "  bad      payload 0xA7 khong 0xA5   → receiver corrupt\n",
            p);
}

int main(int argc, char **argv)
{
    struct args a;
    struct warg wa[MAX_C];
    pthread_t th[MAX_C];
    int i;
    uint64_t total = 0;

    memset(&a, 0, sizeof(a));
    a.connects = 1;
    a.pkt = 1400;
    a.sport0 = 10000;
    a.ends = 8;
    a.bps = 1e9;
    a.dur = 10;
    a.mode = MODE_OK;

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--src-ip") && i + 1 < argc)
            snprintf(a.src, sizeof(a.src), "%s", argv[++i]);
        else if (!strcmp(argv[i], "--dst-ip") && i + 1 < argc)
            snprintf(a.dst, sizeof(a.dst), "%s", argv[++i]);
        else if (!strcmp(argv[i], "--dst-port") && i + 1 < argc)
            a.dport = atoi(argv[++i]);
        else if ((!strcmp(argv[i], "-c") || !strcmp(argv[i], "--connects")) && i + 1 < argc)
            a.connects = atoi(argv[++i]);
        else if ((!strcmp(argv[i], "-b") || !strcmp(argv[i], "--bandwidth")) && i + 1 < argc) {
            if (parse_bps(argv[++i], &a.bps)) {
                fprintf(stderr, "bad -b\n");
                return 2;
            }
        } else if ((!strcmp(argv[i], "-t") || !strcmp(argv[i], "--duration")) && i + 1 < argc)
            a.dur = atof(argv[++i]);
        else if ((!strcmp(argv[i], "-l") || !strcmp(argv[i], "--packet-size")) && i + 1 < argc)
            a.pkt = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--src-port-base") && i + 1 < argc)
            a.sport0 = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--mode") && i + 1 < argc) {
            const char *m = argv[++i];
            if (!strcmp(m, "ok"))
                a.mode = MODE_OK;
            else if (!strcmp(m, "shuffle"))
                a.mode = MODE_SHUFFLE;
            else if (!strcmp(m, "miss"))
                a.mode = MODE_MISS;
            else if (!strcmp(m, "bad"))
                a.mode = MODE_BAD;
            else {
                fprintf(stderr, "bad --mode (ok|shuffle|miss|bad)\n");
                return 2;
            }
        }
        else {
            usage(argv[0]);
            return 2;
        }
    }

    if (!a.src[0] || !a.dst[0] || a.dport <= 0 || a.connects < 1 || a.connects > MAX_C ||
        a.pkt < HDR) {
        usage(argv[0]);
        return 2;
    }

    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);

    printf("sender: mode=%s  %d connect x %.3f Gbps = %.3f Gbps  pkt=%d dur=%.1fs\n",
           mode_name(a.mode), a.connects, a.bps / 1e9, a.connects * a.bps / 1e9, a.pkt, a.dur);

    for (i = 0; i < a.connects; i++) {
        wa[i].a = &a;
        wa[i].id = i;
        wa[i].sent = 0;
        if (pthread_create(&th[i], NULL, worker, &wa[i])) {
            perror("pthread_create");
            return 1;
        }
    }
    for (i = 0; i < a.connects; i++) {
        pthread_join(th[i], NULL);
        total += wa[i].sent;
    }
    printf("sender finished: packets=%llu\n", (unsigned long long)total);
    return 0;
}