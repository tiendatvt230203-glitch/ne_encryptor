/* Check kernel + card: XDP frags + DRV (khong doi MTU).
 *
 *   gcc -O2 -Wall -I./include -o tools/xdp_frags_check tools/xdp_frags_check.c -lbpf -lelf -lz
 *   sudo ./tools/xdp_frags_check <ifname>
 *
 * kernel = load HAS_FRAGS
 * card   = attach DRV roi detach. Kernel fail => khong attach.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#ifndef BPF_F_XDP_HAS_FRAGS
#define BPF_F_XDP_HAS_FRAGS (1U << 5)
#endif
#ifndef XDP_FLAGS_DRV_MODE
#define XDP_FLAGS_DRV_MODE (1U << 2)
#endif

#define INSN(DST, IMM) ((struct bpf_insn){		\
	.code = BPF_ALU64 | BPF_MOV | BPF_K,		\
	.dst_reg = DST, .imm = IMM })
#define EXIT_INSN() ((struct bpf_insn){			\
	.code = BPF_JMP | BPF_EXIT })

enum {
	CARD_OK = 0,
	CARD_NO = 1,
	CARD_SKIP = 2,
};

static int check_kernel(int *prog_fd)
{
	struct bpf_insn insns[] = { INSN(BPF_REG_0, XDP_PASS), EXIT_INSN() };
	struct bpf_load_program_attr attr = {
		.prog_type = BPF_PROG_TYPE_XDP,
		.name = "frags",
		.insns = insns,
		.insns_cnt = 2,
		.license = "GPL",
		.prog_flags = BPF_F_XDP_HAS_FRAGS,
	};
	int fd = bpf_load_program_xattr(&attr, NULL, 0);

	if (fd < 0)
		return -errno;
	*prog_fd = fd;
	return 0;
}

static int check_card(int ifindex, int prog_fd)
{
	int rc;

	if (prog_fd < 0)
		return CARD_SKIP;

	rc = bpf_set_link_xdp_fd(ifindex, prog_fd, XDP_FLAGS_DRV_MODE);
	if (rc) {
		if (rc == -EOPNOTSUPP || rc == -EINVAL)
			return CARD_NO;
		errno = -rc;
		return CARD_SKIP;
	}
	(void)bpf_set_link_xdp_fd(ifindex, -1, XDP_FLAGS_DRV_MODE);
	return CARD_OK;
}

int main(int argc, char **argv)
{
	const char *ifname;
	unsigned ifindex;
	int prog_fd = -1, kr, cr;

	if (argc != 2) {
		fprintf(stderr, "usage: %s <ifname>\n", argv[0]);
		return 1;
	}
	ifname = argv[1];
	ifindex = if_nametoindex(ifname);
	if (!ifindex) {
		printf("KHONG DUOC: khong co interface %s\n", ifname);
		return 1;
	}

	kr = check_kernel(&prog_fd);
	cr = check_card((int)ifindex, prog_fd);

	if (kr == 0)
		printf("kernel: OK (load HAS_FRAGS)\n");
	else
		printf("kernel: KHONG (%s)\n", strerror(-kr));

	if (cr == CARD_OK)
		printf("card %s: OK (attach DRV + frags)\n", ifname);
	else if (cr == CARD_NO)
		printf("card %s: KHONG (attach DRV + frags fail)\n", ifname);
	else if (kr != 0)
		printf("card %s: CHUA TEST (kernel fail, khong attach)\n", ifname);
	else
		printf("card %s: CHUA TEST (%s)\n", ifname, strerror(errno));

	if (prog_fd >= 0)
		close(prog_fd);

	if (kr == 0 && cr == CARD_OK) {
		printf("=> DUOC: %s XDP frags + DRV\n", ifname);
		return 0;
	}
	if (kr != 0 && cr != CARD_NO)
		printf("=> KHONG DUOC: do kernel\n");
	else if (kr == 0 && cr == CARD_NO)
		printf("=> KHONG DUOC: do card\n");
	else if (kr != 0 && cr == CARD_NO)
		printf("=> KHONG DUOC: kernel va card\n");
	else
		printf("=> KHONG DUOC\n");
	return 1;
}
