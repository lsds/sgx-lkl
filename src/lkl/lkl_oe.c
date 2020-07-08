#include "openenclave/corelibc/stdarg.h"
#include "openenclave/internal/print.h"

#define OE_STDERR_FILENO 1

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
