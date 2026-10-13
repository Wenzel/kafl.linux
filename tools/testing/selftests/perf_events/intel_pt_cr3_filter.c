// SPDX-License-Identifier: GPL-2.0-only
/*
 * Test for the Intel PT CR3 filter (cr3_filter format bit, CR3 match value
 * in perf_event_attr.config1).
 *
 * The match value is written to IA32_RTIT_CR3_MATCH, where reserved bits
 * raise #GP, so the kernel has to refuse them at perf_event_open() time.
 * Checks:
 *  - reserved bits (4:0, above MAXPHYADDR) are rejected with EINVAL
 *  - config1 is ignored unless cr3_filter is set
 *  - a legal, non-matching CR3 suppresses (nearly) all trace output
 */
#define _GNU_SOURCE

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#include <linux/perf_event.h>

#include "kselftest_harness.h"

#define PT_DIR		"/sys/bus/event_source/devices/intel_pt"

/* intel_pt format: pt is config:0, cr3_filter config:7, branch config:13. */
#define PT_CONFIG_PT		(1ULL << 0)
#define PT_CONFIG_CR3_FILTER	(1ULL << 7)
#define PT_CONFIG_BRANCH_EN	(1ULL << 13)

#define AUX_PAGES	64
#define BASE_PAGES	2

/* Page aligned, inside any MAXPHYADDR, and not a live page-table root. */
#define CR3_DECOY	0x3fffffff000ULL

static int read_pt_uint(const char *name, unsigned int *val)
{
	char path[128];
	FILE *f;
	int ret;

	snprintf(path, sizeof(path), PT_DIR "/%s", name);
	f = fopen(path, "r");
	if (!f)
		return -1;
	ret = fscanf(f, "%u", val) == 1 ? 0 : -1;
	fclose(f);
	return ret;
}

FIXTURE(cr3_filter)
{
	unsigned int	type;
};

FIXTURE_SETUP(cr3_filter)
{
	unsigned int cap;

	if (read_pt_uint("type", &self->type))
		SKIP(return, "no intel_pt PMU");
	if (read_pt_uint("caps/cr3_filtering", &cap) || !cap)
		SKIP(return, "intel_pt has no cr3_filtering capability");
}

FIXTURE_TEARDOWN(cr3_filter)
{
}

static int open_pt(unsigned int type, uint64_t config, uint64_t config1)
{
	struct perf_event_attr attr = {
		.type		= type,
		.size		= sizeof(attr),
		.config		= PT_CONFIG_PT | PT_CONFIG_BRANCH_EN | config,
		.config1	= config1,
		.disabled	= 1,
		.exclude_kernel	= 1,
		.exclude_hv	= 1,
	};

	return syscall(SYS_perf_event_open, &attr, 0, -1, -1, 0);
}

/* Branch heavy work, so an unfiltered trace is large. */
static void __attribute__((noinline)) workload(void)
{
	volatile unsigned long acc = 0;
	unsigned long i;

	for (i = 0; i < 4000000UL; i++)
		acc += (i & 7) ? i : acc >> 1;
}

/* Trace workload() and return the number of AUX bytes produced, or -1. */
static long long trace_bytes(unsigned int type, uint64_t config,
			     uint64_t config1)
{
	struct perf_event_mmap_page *pc;
	size_t base_sz = BASE_PAGES * getpagesize();
	size_t aux_sz = AUX_PAGES * getpagesize();
	long long bytes = -1;
	void *aux;
	int fd;

	fd = open_pt(type, config, config1);
	if (fd < 0)
		return -1;

	pc = mmap(NULL, base_sz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (pc == MAP_FAILED)
		goto out_close;
	pc->aux_offset = base_sz;
	pc->aux_size = aux_sz;
	aux = mmap(NULL, aux_sz, PROT_READ | PROT_WRITE, MAP_SHARED, fd,
		   base_sz);
	if (aux == MAP_FAILED)
		goto out_unmap_base;

	ioctl(fd, PERF_EVENT_IOC_RESET, 0);
	ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
	workload();
	ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
	__sync_synchronize();
	bytes = pc->aux_head - pc->aux_tail;

	munmap(aux, aux_sz);
out_unmap_base:
	munmap(pc, base_sz);
out_close:
	close(fd);
	return bytes;
}

TEST_F(cr3_filter, reserved_low_bits_rejected)
{
	int fd;

	/* Bits 4:0 of IA32_RTIT_CR3_MATCH are reserved. */
	fd = open_pt(self->type, PT_CONFIG_CR3_FILTER, 0x1);
	ASSERT_EQ(fd, -1);
	EXPECT_EQ(errno, EINVAL);

	fd = open_pt(self->type, PT_CONFIG_CR3_FILTER, 0x10);
	ASSERT_EQ(fd, -1);
	EXPECT_EQ(errno, EINVAL);
}

TEST_F(cr3_filter, above_maxphyaddr_rejected)
{
	int fd;

	/* MAXPHYADDR is at most 52 bits. */
	fd = open_pt(self->type, PT_CONFIG_CR3_FILTER, 1ULL << 63);
	ASSERT_EQ(fd, -1);
	EXPECT_EQ(errno, EINVAL);
}

TEST_F(cr3_filter, valid_value_accepted)
{
	int fd;

	fd = open_pt(self->type, PT_CONFIG_CR3_FILTER, CR3_DECOY);
	if (fd < 0 && errno == EACCES)
		SKIP(return, "not permitted to open intel_pt");
	ASSERT_GE(fd, 0);
	close(fd);
}

TEST_F(cr3_filter, config1_ignored_without_enable)
{
	int fd;

	/* The same value that is rejected above is ignored when disabled. */
	fd = open_pt(self->type, 0, 0x1);
	if (fd < 0 && errno == EACCES)
		SKIP(return, "not permitted to open intel_pt");
	ASSERT_GE(fd, 0);
	close(fd);
}

TEST_F(cr3_filter, nonmatching_cr3_suppresses_trace)
{
	long long base, decoy;

	base = trace_bytes(self->type, 0, 0);
	if (base < 0 && (errno == EACCES || errno == EPERM || errno == ENOMEM))
		SKIP(return, "cannot trace or map AUX buffer: %s",
		     strerror(errno));
	ASSERT_GT(base, 0);

	decoy = trace_bytes(self->type, PT_CONFIG_CR3_FILTER, CR3_DECOY);
	ASSERT_GE(decoy, 0);

	TH_LOG("unfiltered %lld bytes, non-matching CR3 %lld bytes",
	       base, decoy);
	EXPECT_LT(decoy * 100, base);
}

TEST_HARNESS_MAIN
