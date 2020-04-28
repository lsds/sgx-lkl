#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/stat.h>

#define HW_FILE "/app/helloworld.txt"

struct swrap
{
	struct stat s;
	unsigned long long overflow;
};

static inline void check(_Bool condition, const char *msg, ...)
{
	if (!condition)
	{
		va_list ap;
		va_start(ap, msg);
		vfprintf(stderr, msg, ap);
		va_end(ap);
		fprintf(stderr, "\nTEST_FAILED\n");
		exit(1);
	}
}

int main(int argc, char** argv)
{
	struct swrap s;
	s.overflow = -1ULL;
	int ret = stat(HW_FILE, &s.s);
	check(ret == 0, "stat file %s: %s\n", HW_FILE, strerror(errno));
	check(s.overflow == -1ULL, "stat overflowed buffer: %llx", s.overflow);
	check(s.s.st_size == 24, "stat returned incorrect size: %d", (int)s.s.st_size);
	check(s.s.st_mode == S_IFREG | S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH, "stat returned incorrect mode: 0%o", (int)s.s.st_mode);
	check(s.s.st_uid == 0, "stat returned incorrect user id: %d", (int)s.s.st_uid);
	check(s.s.st_gid == 0, "stat returned incorrect group: %d", (int)s.s.st_gid);
	check(s.s.st_nlink == 1, "stat returned incorrect number of hard links: %d", (int)s.s.st_nlink);
	fprintf(stderr, "TEST_PASSED\n");
	return 0;
}
