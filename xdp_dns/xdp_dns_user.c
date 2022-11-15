/*
 *  Software Name : bmc-cache
 *  SPDX-FileCopyrightText: Copyright (c) 2021 Orange
 *  SPDX-License-Identifier: LGPL-2.1-only
 *
 *  This software is distributed under the
 *  GNU Lesser General Public License v2.1 only.
 *
 *  Author: Yoann GHIGOFF <yoann.ghigoff@orange.com> et al.
 */

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <assert.h>
#include <errno.h>
#include <sys/resource.h>
#include <linux/if_link.h>
#include <linux/limits.h>

#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

static int print_bpf_verifier(enum libbpf_print_level level,
							const char *format, va_list args)
{
	return vfprintf(stdout, format, args);
}


int main(int argc, char *argv[])
{
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	int xdp_main_prog_fd;
	struct bpf_program *prog;
	struct bpf_object *obj;
	char filename[PATH_MAX];
	int err;
	__u32 xdp_flags = 0;
	int *interfaces_idx;
	int ret = 0;

	int opt;
	int interface_count = 0;
	while ((opt = getopt(argc, argv, "")) != -1) {
		switch (opt) {
			case '?':
			default:
				fprintf(stderr, "Usage: %s <interface_idx...>\n", argv[0]);
				exit(EXIT_FAILURE);
		}
	}

	interface_count = argc - optind;
	if (interface_count <= 0) {
		fprintf(stderr, "Missing at least one required interface index\n");
		exit(EXIT_FAILURE);
	}

	interfaces_idx = calloc(sizeof(int), interface_count);
	if (interfaces_idx == NULL) {
		fprintf(stderr, "Error: failed to allocate memory\n");
		return 1;
	}

	for (int i = 0; i < interface_count && optind < argc; optind++, i++) {
		interfaces_idx[i] = atoi(argv[optind]);
	}
	xdp_flags |= XDP_FLAGS_DRV_MODE;

	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);

	sigset_t signal_mask;
	sigemptyset(&signal_mask);
	sigaddset(&signal_mask, SIGINT);
	sigaddset(&signal_mask, SIGTERM);
	sigaddset(&signal_mask, SIGUSR1);

	if (setrlimit(RLIMIT_MEMLOCK, &r)) {
		perror("setrlimit failed");
		return 1;
	}
	libbpf_set_print(print_bpf_verifier);

	obj = bpf_object__open(filename);
	if (!obj) {
		fprintf(stderr, "Error: bpf_object__open failed\n");
		return 1;
	}

	err = bpf_object__load(obj);
	if (err) {
		fprintf(stderr, "Error: bpf_object__load failed\n");
		return 1;
	}

	prog = bpf_object__find_program_by_name(obj, "xdp_dns");
	if (!prog) {
		fprintf(stderr, "Error: bpf_object__find_program_by_name failed\n");
		return 1;
	}

	xdp_main_prog_fd = bpf_program__fd(prog);
	if (xdp_main_prog_fd < 0) {
		fprintf(stderr, "Error: bpf_program__fd failed\n");
		return 1;
	}

	for (int i = 0; i < interface_count; i++) {
		if (bpf_set_link_xdp_fd(interfaces_idx[i], xdp_main_prog_fd, xdp_flags) < 0) {
			fprintf(stderr, "Error: bpf_set_link_xdp_fd failed for interface %d\n", interfaces_idx[i]);
			return 1;
		} else {
			printf("Main BPF program attached to XDP on interface %d\n", interfaces_idx[i]);
		}
	}


	int sig, quit = 0;
	FILE *fp = NULL;

	err = sigprocmask(SIG_BLOCK, &signal_mask, NULL);
	if (err != 0) {
		fprintf(stderr, "Error: Failed to set signal mask\n");
		exit(EXIT_FAILURE);
	}

	while (!quit) {
		err = sigwait(&signal_mask, &sig);
		if (err != 0) {
			fprintf(stderr, "Error: Failed to wait for signal\n");
			exit(EXIT_FAILURE);
		}

		switch (sig) {
			case SIGINT:
			case SIGTERM:
				quit = 1;
				break;

			case SIGALRM:
				if (fp != NULL) {
					fclose(fp);
				}
				quit = 1;
				break;

			case SIGUSR1:
				quit = ret;
				break;

			default:
				fprintf(stderr, "Unknown signal\n");
				break;
		}
	}

	for (int i = 0; i < interface_count; i++) {
		bpf_set_link_xdp_fd(interfaces_idx[i], -1, xdp_flags);
	}

	return ret;
}
