/*
 * Reproduce AF_XDP shared-UMEM remove → re-add (the -22 / EINVAL case).
 *
 * Mimics NE: one UMEM, home iface holds umem->fd, test iface is
 * create_shared → delete → create_shared again on the same UMEM.
 *
 * Build (repo root):
 *   make tools/test_xsk_rebind
 *
 * Run (root):
 *   sudo ./tools/test_xsk_rebind --veth --cycles 5
 *   sudo ./tools/test_xsk_rebind --veth --cycles 5 --bad-reclaim
 *   sudo ./tools/test_xsk_rebind enp5s0 --solo --cycles 3
 *   sudo ./tools/test_xsk_rebind <home_if> <test_if> --cycles 5
 *
 * Expect:
 *   default teardown  → rebind OK
 *   --bad-reclaim     → often EINVAL on rebind (old NE bug)
 */
#include <errno.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <unistd.h>

#include <xdp/xsk.h>

#define RING_SIZE   2048u
#define FRAME_SIZE  2048u
#define N_FRAMES    4096u
#define BATCH       64u

struct sock_slot {
	struct xsk_socket *xsk;
	struct xsk_ring_cons rx;
	struct xsk_ring_prod tx;
	struct xsk_ring_prod fq;
	struct xsk_ring_cons cq;
};

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage:\n"
		"  %s --veth [--cycles N] [--bad-reclaim] [--skb]\n"
		"  %s <home_if> <test_if> [--cycles N] [--bad-reclaim] [--skb]\n"
		"  %s <if> --solo [--cycles N] [--bad-reclaim] [--skb]\n"
		"\n"
		"  --veth         create veth-ne-home / veth-ne-test for the run\n"
		"  --solo         single iface owns umem fd; delete+recreate it\n"
		"  --bad-reclaim  rewind FQ producer before delete (old bug)\n"
		"  --skb          prefer XDP_FLAGS_SKB_MODE (default: try DRV then SKB)\n"
		"  --cycles N     remove/re-add loops (default 3)\n",
		prog, prog, prog);
}

static int run_cmd(const char *cmd)
{
	int rc = system(cmd);

	if (rc != 0)
		fprintf(stderr, "[WARN] cmd failed (%d): %s\n", rc, cmd);
	return rc;
}

static int ensure_up(const char *ifname)
{
	char cmd[128];

	snprintf(cmd, sizeof(cmd), "ip link set dev %s up >/dev/null 2>&1", ifname);
	return run_cmd(cmd);
}

static void bad_reclaim_fq(struct xsk_ring_prod *fq)
{
	uint32_t prod;
	uint32_t cons;

	if (!fq || !fq->ring || !fq->producer || !fq->consumer)
		return;
	prod = *fq->producer;
	cons = __atomic_load_n(fq->consumer, __ATOMIC_ACQUIRE);
	/* Steal outstanding fill entries back (desyncs shared UMEM). */
	__atomic_store_n(fq->producer, cons, __ATOMIC_RELEASE);
	fq->cached_prod = cons;
	fq->cached_cons = cons + fq->size;
	(void)prod;
}

static int create_one(struct xsk_umem *umem, const char *ifname, __u32 qid,
		      struct sock_slot *slot, uint32_t xdp_flags)
{
	struct xsk_socket_config cfg = {
		.rx_size = RING_SIZE,
		.tx_size = RING_SIZE,
		.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
		.xdp_flags = xdp_flags,
		.bind_flags = XDP_COPY | XDP_USE_NEED_WAKEUP,
	};
	int ret;

	memset(slot, 0, sizeof(*slot));
	ret = xsk_socket__create_shared(&slot->xsk, ifname, qid, umem,
					&slot->rx, &slot->tx,
					&slot->fq, &slot->cq, &cfg);
	return ret;
}

static int create_with_fallback(struct xsk_umem *umem, const char *ifname, __u32 qid,
				struct sock_slot *slot, int prefer_skb, const char *tag)
{
	uint32_t modes[2];
	int n = 0;
	int last = -EINVAL;

	if (prefer_skb) {
		modes[n++] = XDP_FLAGS_SKB_MODE;
	} else {
		modes[n++] = XDP_FLAGS_DRV_MODE;
		modes[n++] = XDP_FLAGS_SKB_MODE;
	}

	for (int i = 0; i < n; i++) {
		last = create_one(umem, ifname, qid, slot, modes[i]);
		if (last == 0) {
			printf("[OK] %s %s q=%u mode=0x%x fd=%d umem_fd=%d\n",
			       tag, ifname, qid, modes[i],
			       xsk_socket__fd(slot->xsk), xsk_umem__fd(umem));
			fflush(stdout);
			return 0;
		}
		printf("[..] %s %s q=%u mode=0x%x failed: %s (%d)\n",
		       tag, ifname, qid, modes[i],
		       strerror(last < 0 ? -last : last), last);
		fflush(stdout);
		memset(slot, 0, sizeof(*slot));
		if (last != -EINVAL && last != EINVAL)
			break;
	}
	fprintf(stderr, "[FAIL] %s %s: could not create XSK\n", tag, ifname);
	return last ? last : -1;
}

static void destroy_one(struct sock_slot *slot, int do_bad_reclaim, const char *tag)
{
	if (!slot || !slot->xsk)
		return;
	if (do_bad_reclaim) {
		printf("[..] %s: BAD reclaim FQ before delete\n", tag);
		bad_reclaim_fq(&slot->fq);
	}
	xsk_socket__delete(slot->xsk);
	memset(slot, 0, sizeof(*slot));
	printf("[OK] %s: deleted\n", tag);
	fflush(stdout);
}

static int test_shared(const char *home_if, const char *test_if, int cycles,
		       int bad_reclaim, int prefer_skb)
{
	void *bufs;
	struct xsk_umem *umem = NULL;
	struct xsk_ring_prod umem_fq;
	struct xsk_ring_cons umem_cq;
	struct xsk_umem_config ucfg = {
		.fill_size = RING_SIZE,
		.comp_size = RING_SIZE,
		.frame_size = FRAME_SIZE,
		.frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
		.flags = 0,
	};
	struct sock_slot home = {0};
	struct sock_slot test = {0};
	size_t bufsize = (size_t)N_FRAMES * FRAME_SIZE;
	int rc = -1;

	printf("\n=== SHARED UMEM: home=%s test=%s cycles=%d bad_reclaim=%d ===\n",
	       home_if, test_if, cycles, bad_reclaim);

	bufs = mmap(NULL, bufsize, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (bufs == MAP_FAILED) {
		perror("mmap");
		return -1;
	}

	memset(&umem_fq, 0, sizeof(umem_fq));
	memset(&umem_cq, 0, sizeof(umem_cq));
	if (xsk_umem__create(&umem, bufs, bufsize, &umem_fq, &umem_cq, &ucfg)) {
		fprintf(stderr, "[FAIL] umem create: %s\n", strerror(errno));
		goto out_unmap;
	}
	printf("[OK] umem fd=%d frames=%u\n", xsk_umem__fd(umem), N_FRAMES);

	if (create_with_fallback(umem, home_if, 0, &home, prefer_skb, "home") != 0)
		goto out_umem;

	for (int c = 1; c <= cycles; c++) {
		printf("\n--- cycle %d/%d: ADD test ---\n", c, cycles);
		if (create_with_fallback(umem, test_if, 0, &test, prefer_skb, "test-add") != 0) {
			fprintf(stderr, "[FAIL] cycle %d: add test iface failed\n", c);
			goto out_home;
		}

		printf("--- cycle %d/%d: REMOVE test ---\n", c, cycles);
		destroy_one(&test, bad_reclaim, "test-remove");

		printf("--- cycle %d/%d: RE-ADD test ---\n", c, cycles);
		if (create_with_fallback(umem, test_if, 0, &test, prefer_skb, "test-readd") != 0) {
			fprintf(stderr,
				"[FAIL] cycle %d: re-add conflict (kernel EINVAL / shared UMEM)\n",
				c);
			goto out_home;
		}
		printf("[OK] cycle %d: remove→re-add clean\n", c);

		destroy_one(&test, 0, "test-cleanup");
	}

	printf("\n[PASS] shared UMEM remove/re-add survived %d cycles\n", cycles);
	rc = 0;

out_home:
	destroy_one(&test, 0, "test-final");
	destroy_one(&home, 0, "home-final");
out_umem:
	if (umem)
		(void)xsk_umem__delete(umem);
out_unmap:
	munmap(bufs, bufsize);
	return rc;
}

static int test_solo(const char *ifname, int cycles, int bad_reclaim, int prefer_skb)
{
	void *bufs;
	struct xsk_umem *umem = NULL;
	struct xsk_ring_prod umem_fq;
	struct xsk_ring_cons umem_cq;
	struct xsk_umem_config ucfg = {
		.fill_size = RING_SIZE,
		.comp_size = RING_SIZE,
		.frame_size = FRAME_SIZE,
		.frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
		.flags = 0,
	};
	struct sock_slot slot = {0};
	size_t bufsize = (size_t)N_FRAMES * FRAME_SIZE;
	int rc = -1;

	printf("\n=== SOLO (iface owns umem fd): if=%s cycles=%d bad_reclaim=%d ===\n",
	       ifname, cycles, bad_reclaim);

	bufs = mmap(NULL, bufsize, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (bufs == MAP_FAILED) {
		perror("mmap");
		return -1;
	}

	memset(&umem_fq, 0, sizeof(umem_fq));
	memset(&umem_cq, 0, sizeof(umem_cq));
	if (xsk_umem__create(&umem, bufs, bufsize, &umem_fq, &umem_cq, &ucfg)) {
		fprintf(stderr, "[FAIL] umem create: %s\n", strerror(errno));
		goto out_unmap;
	}

	for (int c = 1; c <= cycles; c++) {
		printf("\n--- cycle %d/%d: ADD ---\n", c, cycles);
		if (create_with_fallback(umem, ifname, 0, &slot, prefer_skb, "solo-add") != 0) {
			fprintf(stderr, "[FAIL] cycle %d: add failed\n", c);
			goto out_umem;
		}

		printf("--- cycle %d/%d: REMOVE ---\n", c, cycles);
		destroy_one(&slot, bad_reclaim && c < cycles, "solo-remove");

		if (c == cycles)
			break;

		printf("--- cycle %d/%d: RE-ADD same umem ---\n", c, cycles);
		if (create_with_fallback(umem, ifname, 0, &slot, prefer_skb, "solo-readd") != 0) {
			fprintf(stderr,
				"[FAIL] cycle %d: re-add on same umem failed "
				"(umem fd was previous socket)\n",
				c);
			goto out_umem;
		}
		printf("[OK] cycle %d: solo remove→re-add clean\n", c);
	}

	printf("\n[PASS] solo remove/re-add survived %d cycles\n", cycles);
	rc = 0;

out_umem:
	destroy_one(&slot, 0, "solo-final");
	if (umem)
		(void)xsk_umem__delete(umem);
out_unmap:
	munmap(bufs, bufsize);
	return rc;
}

int main(int argc, char **argv)
{
	const char *home_if = NULL;
	const char *test_if = NULL;
	int cycles = 3;
	int bad_reclaim = 0;
	int prefer_skb = 0;
	int use_veth = 0;
	int solo = 0;
	int positional = 0;
	struct rlimit rl = {RLIM_INFINITY, RLIM_INFINITY};
	int rc;

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--veth") == 0) {
			use_veth = 1;
		} else if (strcmp(argv[i], "--solo") == 0) {
			solo = 1;
		} else if (strcmp(argv[i], "--bad-reclaim") == 0) {
			bad_reclaim = 1;
		} else if (strcmp(argv[i], "--skb") == 0) {
			prefer_skb = 1;
		} else if (strcmp(argv[i], "--cycles") == 0) {
			if (i + 1 >= argc) {
				usage(argv[0]);
				return 2;
			}
			cycles = atoi(argv[++i]);
			if (cycles < 1)
				cycles = 1;
		} else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
			usage(argv[0]);
			return 0;
		} else if (argv[i][0] == '-') {
			fprintf(stderr, "unknown option: %s\n", argv[i]);
			usage(argv[0]);
			return 2;
		} else {
			if (positional == 0)
				home_if = argv[i];
			else if (positional == 1)
				test_if = argv[i];
			else {
				usage(argv[0]);
				return 2;
			}
			positional++;
		}
	}

	(void)setrlimit(RLIMIT_MEMLOCK, &rl);

	if (use_veth) {
		home_if = "veth-ne-home";
		test_if = "veth-ne-test";
		run_cmd("ip link del veth-ne-home >/dev/null 2>&1");
		run_cmd("ip link del veth-ne-test >/dev/null 2>&1");
		if (run_cmd("ip link add veth-ne-home type veth peer name veth-ne-test") != 0) {
			fprintf(stderr, "[FAIL] cannot create veth pair (need root)\n");
			return 1;
		}
		ensure_up(home_if);
		ensure_up(test_if);
		prefer_skb = 1; /* veth: SKB */
		solo = 0;
	} else if (solo) {
		if (!home_if || test_if) {
			usage(argv[0]);
			return 2;
		}
		test_if = home_if;
		ensure_up(home_if);
	} else {
		if (!home_if || !test_if) {
			usage(argv[0]);
			return 2;
		}
		ensure_up(home_if);
		ensure_up(test_if);
	}

	if (solo)
		rc = test_solo(home_if, cycles, bad_reclaim, prefer_skb);
	else
		rc = test_shared(home_if, test_if, cycles, bad_reclaim, prefer_skb);

	if (use_veth) {
		run_cmd("ip link del veth-ne-home >/dev/null 2>&1");
		run_cmd("ip link del veth-ne-test >/dev/null 2>&1");
	}

	return rc ? 1 : 0;
}
