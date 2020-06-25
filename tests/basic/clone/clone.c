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

static char *child_stack;
static char *child_stack_end;
static char child_tls[4069];
static char child_tls1[4069];
static char child_tls2[4069];

static char child_stack1[8192];
static char *child_stack_end1 = child_stack1 + 8192;
static char child_stack2[8192];
static char *child_stack_end2 = child_stack2 + 8192;

volatile int thread_started;
__attribute__((weak)) int lkl_syscall(int, long*);

static void assert(int cond, const char *msg, ...)
{
	if (cond) return;
	va_list ap;
	va_start(ap, msg);
	vfprintf(stderr, msg, ap);
	va_end(ap);
	fprintf(stderr, "\nTEST_FAILED\n");
	exit(-1);
}

static int futex_wait(volatile int *addr, int val)
{
	return syscall(SYS_futex, addr, 0 /* FUTEX_WAIT */, val, NULL, 0, 0);
}

static int futex_wake(volatile int *addr)
{
	return syscall(SYS_futex, addr, 1 /* FUTEX_WAKE */, 100, NULL, 0, 0);
}

int newthr(void *arg)
{
	// Sleep long enough to make sure that the caller goes to sleep on the
	// futex.
	sleep(2);
	thread_started = 1;
	assert(arg == (void*)0x42, "New thread got correct argument");
	char x;
	assert(&x > child_stack, "Local variable is not on the stack");
	assert(&x < child_stack_end, "Local variable is not on the stack");
	fprintf(stderr, "New thread created.\n");
	fprintf(stderr, "Arg: %p.\n", arg);
	fprintf(stderr, "Stack: %p.\n", &x);
	// This would normally crash, but SGX_LKL defers unmapping the child stack
	// until the thread exits.
	munmap(child_stack, child_stack_end - child_stack);
	return 0;
}

volatile int barrier = 0;
volatile int counter = 0;

int parallelthr(void* arg)
{
	int odd = (int)(intptr_t)arg;
	fprintf(stderr, "Thread %d started\n", odd);
	futex_wait(&barrier, 0);
	fprintf(stderr, "Thread %d woke up\n", odd);
	// After this point, the thread will not yield until the function returns.
	// This depends on the kernel waking up two clone'd threads and having them
	// run in parallel.  The purpose of this test is to ensure that nothing in
	// the SGX-LKL host interface that backs the clone system call causes
	// host tasks to become serialised.
	// Note: This test will work only with 2+ ethreads.
	while (1)
	{
		int v = __atomic_load_n(&counter, __ATOMIC_SEQ_CST);

		if (v == 100)
			break;

		if (v % 2 == odd)
		{
			__atomic_compare_exchange_n(&counter, &v, v+1, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
		}
	}

	fprintf(stderr, "Thread %d finished\n", odd);

	return 0;
}

int main(int argc, char** argv)
{
	unsigned flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND
		| CLONE_THREAD | CLONE_SYSVSEM | CLONE_SETTLS | CLONE_CHILD_SETTID
		| CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID | CLONE_DETACHED;


	pid_t ptid;
	pid_t ctid = 0;
	child_stack = mmap(0, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	child_stack_end = child_stack + 8192;
	assert(child_stack != MAP_FAILED, "Failed to map child stack");
	fprintf(stderr, "Clone syscall number: %d\n", SYS_clone);
	fprintf(stderr, "lkl_syscall: %p\n", lkl_syscall);
	fprintf(stderr, "fn: %p \n", newthr);
	fprintf(stderr, "ctid: %p \n", &ctid);
	fprintf(stderr, "Stack: %p-%p \n", child_stack, child_stack_end);

	int clone_ret = clone(newthr, child_stack_end, flags, (void*)0x42, &ptid, &child_tls, &ctid);
	if (clone_ret == -1)
	{
		perror("Clone failed");
	}
	fprintf(stderr, "Clone returned %d, ctid: %d ptid: %d\n", clone_ret, ctid, ptid);
	assert(ctid == clone_ret, "ctid is %d, should be %d\n", ctid, clone_ret);
	int futex_ret = futex_wait(&ctid, clone_ret);
	assert(futex_ret == 0, "futex syscall returned %d (%s)\n", strerror(errno));
	fprintf(stderr, "After futex call, ctid is %d\n", ctid);
	assert(ctid == 0, "ctid was not zeroed during futex wait\n");
	fprintf(stderr, "Other thread should have terminated by now.\n");
	assert(thread_started == 1, "Thread did not run");
	fprintf(stderr, "Thread stacks: %p, %p, %p\n", child_stack, child_stack1, child_stack2);

	pid_t ctid_futex1, ctid_futex2;
	pid_t ctid1 = clone(parallelthr, child_stack_end1, flags, (void*)0, &ptid, &child_tls1, &ctid_futex1);
	pid_t ctid2 = clone(parallelthr, child_stack_end2, flags, (void*)0x1, &ptid, &child_tls2, &ctid_futex2);
	fprintf(stderr, "Created two threads: %d, %d, waking them now\n", ctid1, ctid2);
	barrier = 1;
	fprintf(stderr, "\nIf this test hangs after waking up one thread, check you have at least 2 ethreads\n");
	fprintf(stderr, "This test is checking that LKL is able to wake up two cloned threads and leaving them running in parallel\n\n");
	futex_wake(&barrier);
	fprintf(stderr, "Waiting for for Thread 0 to finish\n");
	futex_wait(&ctid_futex1, ctid1);
	fprintf(stderr, "Waiting for for Thread 1 to finish\n");
	futex_wait(&ctid_futex2, ctid2);

	fprintf(stderr, "\nTEST_PASSED\n");

	return 0;
}
