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

#define BPF_SYSFS_ROOT "/sys/fs/bpf"

static int print_bpf_verifier(enum libbpf_print_level level,
							const char *format, va_list args)
{
	return vfprintf(stdout, format, args);
}


int main(int argc, char *argv[])
{
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	struct bpf_program *prog;
	struct bpf_object *obj;
	char filename[PATH_MAX];
	int err;
	int ret = 0;

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

	prog = bpf_object__find_program_by_name(obj, "icmp_serv");
	if (!prog) {
		fprintf(stderr, "Error: bpf_object__find_program_by_name failed\n");
		return 1;
	}

	int len = snprintf(filename, PATH_MAX, "%s/%s", BPF_SYSFS_ROOT, "icmp_serv");
	if (len < 0) {
		fprintf(stderr, "Error: Program name '%s' is invalid\n", "icmp_serv");
		return -1;
	} else if (len >= PATH_MAX) {
		fprintf(stderr, "Error: Program name '%s' is too long\n", "icmp_serv");
		return -1;
	}
retry:
	if (bpf_program__pin_instance(prog, filename, 0)) {
		fprintf(stderr, "Error: Failed to pin program '%s' to path %s\n", "icmp_serv", filename);
		if (errno == EEXIST) {
			fprintf(stdout, "BPF program '%s' already pinned, unpinning it to reload it\n", "icmp_serv");
			if (bpf_program__unpin_instance(prog, filename, 0)) {
				fprintf(stderr, "Error: Fail to unpin program '%s' at %s\n", "icmp_serv", filename);
				return -1;
			}
			goto retry;
		}
		return -1;
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

	return ret;
}
