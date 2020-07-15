#include "openenclave/corelibc/stdlib.h"
#include "openenclave/corelibc/stdarg.h"
#include "openenclave/internal/print.h"

#define OE_STDERR_FILENO 1

// LKL would normally provide implementations for lkl_printf and lkl_bug.
// However, these would come from liblkl-in.o which relies on a libc.
// In SGX-LKL kernel space we do not have a regular libc available.
// Here we provide the missing implementations using OE's core libc.
// See lkl/tools/lkl/lib/utils.c for the original implementations.

int lkl_printf(const char *fmt, ...)
{
	int n;
	oe_va_list args;

	oe_va_start(args, fmt);
	n = oe_host_vfprintf(OE_STDERR_FILENO, fmt, args);
	oe_va_end(args);

	return n;
}

void lkl_bug(const char *fmt, ...)
{
	oe_va_list args;

	oe_va_start(args, fmt);
	oe_host_vfprintf(OE_STDERR_FILENO, fmt, args);
	oe_va_end(args);

	oe_abort();
}
