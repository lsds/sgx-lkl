/*
 * illegal_instructions-test.c
 *
 * This test checks how illegal instructions inside of enclaves are handled
 * in hw mode.
 *
 * Note that this test does not work in sw mode because the enclave then
 * executes some illegal instructions without error.
 *
 * Eventually the behaviour of this test should be enhanced (as described in
 * https://github.com/lsds/sgx-lkl-oe/issues/286) to send a SIGILL signal to
 * the application via LKL when an illegal instruction is unhandled. This
 * requires correct synchronous signal handling.
 *
 * In addition, the tests should be extended to check for sane values.
 *
 */

#include <asm/unistd.h>
#include <stdint.h>
#include <stdio.h>

int main(void)
{
    /* This test checks if a cpuid instructions is emulated. */

    int a[3];
    a[3] = 0;
    int eax = 0;
    __asm__("cpuid"
            : "=a"(eax), "=b"(a[0]), "=c"(a[2]), "=d"(a[1])
            : "a"(eax), "c"(0) /* input: info into eax */);

    printf("CPU: %s\n", (char*)a);
    printf("TEST PASSED (cpuid)\n");

    /* The next test checks if an rdtsc instuctions is emulated. */

    unsigned int lo, hi;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    printf("TSC: %li\n", ((uint64_t)hi << 32) | lo);
    printf("TEST PASSED (rdtsc)\n");

    /* The following test checks that a syscall results in an oe_abort(). */

    printf("TEST PASSED (syscall)\n");
    char output_str[] = "TEST FAILED (syscall from enclave)\n";
    int fd = 1;
    int ret;

    __asm__(
        "syscall"
        : "=a"(ret)
        : "a"(__NR_write), "D"(fd), "S"(output_str), "d"(sizeof(output_str) - 1)
        : "rcx", "r11", "memory");

    return 0;
}