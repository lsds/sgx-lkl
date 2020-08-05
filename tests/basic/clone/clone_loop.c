#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#define _GNU_SOURCE
#include <sched.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/mman.h>

#define RUNS 10000
static char child_tls1[4069];

static char child_stack1[8192];
static char *child_stack_end1 = child_stack1 + 8192;

__attribute__((weak)) int lkl_syscall(int, long*);

static int futex_wait(volatile int *addr, int val)
{
	return syscall(SYS_futex, addr, 0 /* FUTEX_WAIT */, val, NULL, 0, 0);
}

int newthr(void* arg)
{
	int odd = (int)(intptr_t)arg;
	return 0;
}

int main(int argc, char** argv)
{
	unsigned flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND
		| CLONE_THREAD | CLONE_SYSVSEM | CLONE_SETTLS | CLONE_CHILD_SETTID
		| CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID | CLONE_DETACHED;

	pid_t ptid;
	pid_t ctid_futex1, ctid_futex2;
	for (int i = 0; i < RUNS; i++) {
		pid_t ctid1 = clone(newthr, child_stack_end1, 
							flags, (void*)0, &ptid, &child_tls1,
							&ctid_futex1);
		futex_wait(&ctid_futex1, ctid1);
	}

	return 0;
}