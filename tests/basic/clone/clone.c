#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#define _GNU_SOURCE
#include <sched.h>
#include <unistd.h>
#include <sys/syscall.h>

static char child_stack[8192];
static char *child_stack_end = child_stack + 8192;
static char child_tls[4069];

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

int do_clone(int syscall_number, long *args);
static int clone_wrapper(int (*fn)(void *), void *child_stack, int flags, void *arg, pid_t *ptid, void *newtls, pid_t *ctid)
{
	long args[6] = 
		{
			(long)flags,
			((long)child_stack) - 16,
			(long)ptid,
			(long)ctid,
			(long)newtls,
			0
		};
	void **stack = (void**)child_stack;
	stack[-1] = fn;
	stack[-2] = arg;
	return do_clone(220, args);
}

static void sigsegv(int signo, siginfo_t *si, void *addr)
{
	fprintf(stderr, "Fault: %p (%p)\n", si->si_addr, addr);
	_Exit(0);
}


int newthr(void *arg)
{
	thread_started = 1;
	assert(arg == (void*)0x42, "New thread got correct argument");
	char x;
	assert(&x > child_stack, "Local variable is not on the stack");
	assert(&x < child_stack_end, "Local variable is not on the stack");
	fprintf(stderr, "New thread created.\n");
	fprintf(stderr, "Arg: %p.\n", arg);
	fprintf(stderr, "Stack: %p.\n", &x);
	return 0;
}

int main(int argc, char** argv)
{
	unsigned flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND
		| CLONE_THREAD | CLONE_SYSVSEM | CLONE_SETTLS
		| CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID | CLONE_DETACHED;

	pid_t ptid;
	pid_t ctid;
	fprintf(stderr, "Clone syscall number: %d\n", SYS_clone);
	fprintf(stderr, "lkl_syscall: %p\n", lkl_syscall);
	fprintf(stderr, "fn: %p \n", newthr);
	fprintf(stderr, "ctid: %p \n", &ctid);
	fprintf(stderr, "Stack: %p-%p \n", child_stack, child_stack_end);
	struct sigaction sa = {0};
	sa.sa_sigaction=sigsegv;
	sigaction(SIGSEGV, &sa, NULL);

	int clone_ret = clone_wrapper(newthr, child_stack_end, flags, (void*)0x42, &ptid, &child_tls, &ctid);
	if (clone_ret == -1)
	{
		perror("Clone failed");
	}
	fprintf(stderr, "Clone returned %d, ctid: %d ptid: %d\n", clone_ret, ctid, ptid);
	sleep(2);
	fprintf(stderr, "Other thread should have terminated by now.\n");
	assert(thread_started == 1, "Thread did not run");

	fprintf(stderr, "\nTEST_PASSED\n");

    return 0;
}
