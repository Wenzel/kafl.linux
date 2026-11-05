// SPDX-License-Identifier: GPL-2.0-only
/*
 * Test for the Intel PT CR3 filter (cr3_filter format bit, CR3 match value
 * in perf_event_attr.config1).
 *
 * The match value is written to IA32_RTIT_CR3_MATCH, where reserved bits
 * raise #GP, so the kernel has to refuse them at perf_event_open() time.
 * Checks:
 *  - reserved bits 4:0 are rejected with EINVAL, high bits are accepted
 *  - without the privilege needed for kernel tracing, any cr3_filter
 *    request is refused with EACCES, before it is validated
 *  - config1 is ignored unless cr3_filter is set
 *  - a legal, non-matching CR3 suppresses most of the trace output
 *
 * A test that the filter selects the right CR3 needs the CR3 of a task,
 * which userspace cannot read, so it is not covered here.
 */
#define _GNU_SOURCE

#include <errno.h>
#include <stdbool.h>
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

/*
 * Page aligned, below 2^38 so it is inside the MAXPHYADDR of every CPU with
 * Intel PT, and unlikely to be a live page-table root.
 */
#define CR3_DECOY	0x3ffffff000ULL

/* The filtered trace must be at least this many times smaller. */
#define MIN_REDUCTION	10

/* Skip when the unfiltered trace is too small to compare against. */
#define MIN_BASE_BYTES	(16 * 1024)

FIXTURE(cr3_filter)
{
	unsigned int	type;
	bool		openable;	/* intel_pt can be opened at all */
	bool		privileged;	/* cr3_filter can be opened */
};

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

FIXTURE_SETUP(cr3_filter)
{
	unsigned int cap;
	int fd;

	if (read_pt_uint("type", &self->type))
		SKIP(return, "no intel_pt PMU");
	if (read_pt_uint("caps/cr3_filtering", &cap) || !cap)
		SKIP(return, "intel_pt has no cr3_filtering capability");

	/* Decide from what the kernel does, not from a copy of its policy. */
	fd = open_pt(self->type, 0, 0);
	self->openable = fd >= 0;
	if (fd >= 0)
		close(fd);
	else if (errno != EACCES && errno != EPERM)
		SKIP(return, "cannot open intel_pt: %s", strerror(errno));

	self->privileged = false;
	if (self->openable) {
		fd = open_pt(self->type, PT_CONFIG_CR3_FILTER, CR3_DECOY);
		if (fd >= 0) {
			self->privileged = true;
			close(fd);
		} else if (errno != EACCES) {
			SKIP(return, "cannot open cr3_filter: %s",
			     strerror(errno));
		}
	}
}

FIXTURE_TEARDOWN(cr3_filter)
{
}

/* Branch heavy work, so an unfiltered trace is large. */
static void __attribute__((noinline)) workload(void)
{
	unsigned long acc = 0;
	unsigned long i;

	for (i = 0; i < 4000000UL; i++) {
		acc += (i & 7) ? i : acc >> 1;
		asm volatile("" : "+r" (acc));	/* keep the loop */
	}
}

/* Trace workload() and return the number of AUX bytes, or -errno. */
static long long trace_bytes(unsigned int type, uint64_t config,
			     uint64_t config1)
{
	struct perf_event_mmap_page *pc;
	size_t base_sz = BASE_PAGES * getpagesize();
	size_t aux_sz = AUX_PAGES * getpagesize();
	long long bytes;
	void *aux;
	int fd;

	fd = open_pt(type, config, config1);
	if (fd < 0)
		return -errno;

	pc = mmap(NULL, base_sz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (pc == MAP_FAILED) {
		bytes = -errno;
		goto out_close;
	}
	pc->aux_offset = base_sz;
	pc->aux_size = aux_sz;
	aux = mmap(NULL, aux_sz, PROT_READ | PROT_WRITE, MAP_SHARED, fd,
		   base_sz);
	if (aux == MAP_FAILED) {
		bytes = -errno;
		goto out_unmap_base;
	}

	ioctl(fd, PERF_EVENT_IOC_RESET, 0);
	if (ioctl(fd, PERF_EVENT_IOC_ENABLE, 0)) {
		bytes = -errno;
		goto out_unmap_aux;
	}
	workload();
	ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
	__sync_synchronize();
	bytes = pc->aux_head - pc->aux_tail;

out_unmap_aux:
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

	if (!self->privileged)
		SKIP(return, "cr3_filter needs kernel tracing privilege");

	/* Bits 4:0 of IA32_RTIT_CR3_MATCH are reserved. */
	fd = open_pt(self->type, PT_CONFIG_CR3_FILTER, 0x1);
	ASSERT_EQ(fd, -1);
	EXPECT_EQ(errno, EINVAL);

	fd = open_pt(self->type, PT_CONFIG_CR3_FILTER, 0x10);
	ASSERT_EQ(fd, -1);
	EXPECT_EQ(errno, EINVAL);
}

TEST_F(cr3_filter, high_bits_accepted)
{
	int fd;

	if (!self->privileged)
		SKIP(return, "cr3_filter needs kernel tracing privilege");

	/* The SDM reserves only bits 4:0 of the MSR. */
	fd = open_pt(self->type, PT_CONFIG_CR3_FILTER, 1ULL << 63);
	ASSERT_GE(fd, 0);
	close(fd);
}

TEST_F(cr3_filter, unprivileged_rejected)
{
	int fd;

	if (!self->openable)
		SKIP(return, "not permitted to open intel_pt");
	if (self->privileged)
		SKIP(return, "kernel tracing allowed (paranoid <= 1 or CAP_PERFMON)");

	/* Probing match values would reveal the caller's page table address. */
	fd = open_pt(self->type, PT_CONFIG_CR3_FILTER, CR3_DECOY);
	ASSERT_EQ(fd, -1);
	EXPECT_EQ(errno, EACCES);

	/* The privilege check comes first: no EINVAL for a reserved bit. */
	fd = open_pt(self->type, PT_CONFIG_CR3_FILTER, 0x1);
	ASSERT_EQ(fd, -1);
	EXPECT_EQ(errno, EACCES);
}

TEST_F(cr3_filter, valid_value_accepted)
{
	int fd;

	if (!self->privileged)
		SKIP(return, "cr3_filter needs kernel tracing privilege");

	fd = open_pt(self->type, PT_CONFIG_CR3_FILTER, CR3_DECOY);
	ASSERT_GE(fd, 0);
	close(fd);
}

TEST_F(cr3_filter, config1_ignored_without_enable)
{
	int fd;

	if (!self->openable)
		SKIP(return, "not permitted to open intel_pt");

	/* The same value that is rejected above is ignored when disabled. */
	fd = open_pt(self->type, 0, 0x1);
	ASSERT_GE(fd, 0);
	close(fd);
}

TEST_F(cr3_filter, nonmatching_cr3_suppresses_trace)
{
	long long base, decoy;

	if (!self->privileged)
		SKIP(return, "cr3_filter needs kernel tracing privilege");

	base = trace_bytes(self->type, 0, 0);
	if (base < 0)
		SKIP(return, "cannot trace or map AUX buffer: %s",
		     strerror(-base));
	if (base < MIN_BASE_BYTES)
		SKIP(return, "unfiltered trace too small: %lld bytes", base);

	decoy = trace_bytes(self->type, PT_CONFIG_CR3_FILTER, CR3_DECOY);
	if (decoy < 0)
		TH_LOG("filtered trace failed: %s", strerror(-decoy));
	ASSERT_GE(decoy, 0);

	TH_LOG("unfiltered %lld bytes, non-matching CR3 %lld bytes",
	       base, decoy);
	EXPECT_LT(decoy * MIN_REDUCTION, base);
}

TEST_HARNESS_MAIN
