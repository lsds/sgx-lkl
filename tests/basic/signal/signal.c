#define _GNU_SOURCE

#include <errno.h>
#include <malloc.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <unistd.h>

/* Defines for the program */
#define handle_error(msg)   \
    do                      \
    {                       \
        perror(msg);        \
        exit(EXIT_FAILURE); \
    } while (0)

#define INSTALL_SIGNAL_HANDLER(sig_no, str, handler)               \
    if (signal(sig_no, handler) == SIG_ERR)                        \
    {                                                              \
        memset(errmsg, 0, sizeof(errmsg));                         \
        sprintf(                                                   \
            errmsg,                                                \
            "%s::signal handler registration failed sig_no(%d)\n", \
            str,                                                   \
            sig_no);                                               \
        handle_error(errmsg);                                      \
    }

#define INSTALL_SIGACTION_HANDLER(sig_no, str, handler)       \
    sa.sa_flags = SA_SIGINFO;                                 \
    sigemptyset(&sa.sa_mask);                                 \
    sa.sa_sigaction = handler;                                \
    if (sigaction(sig_no, &sa, NULL) == -1)                   \
    {                                                         \
        memset(errmsg, 0, sizeof(errmsg));                    \
        sprintf(                                              \
            errmsg,                                           \
            "%s::sigaction registration failed sig_no(%d)\n", \
            str,                                              \
            sig_no);                                          \
        handle_error(errmsg);                                 \
    }

#define DO_EXCEPTION(exception_name) do_##exception_name();
#define RAISE_SIGNAL(sig_no) raise_signal(sig_no);
#define SIGNAL_COUNT 32

/* signal name list */
static char signame[][SIGNAL_COUNT] = {
    "INVALID", "SIGHUP",  "SIGINT",    "SIGQUIT", "SIGILL",    "SIGTRAP",
    "SIGABRT", "SIGBUS",  "SIGFPE",    "SIGKILL", "SIGUSR1",   "SIGSEGV",
    "SIGUSR2", "SIGPIPE", "SIGALRM",   "SIGTERM", "SIGSTKFLT", "SIGCHLD",
    "SIGCONT", "SIGSTOP", "SIGTSTP",   "SIGTTIN", "SIGTTOU",   "SIGURG",
    "SIGXCPU", "SIGXFSZ", "SIGVTALRM", "SIGPROF", "SIGWINCH",  "SIGPOLL",
    "SIGPWR",  "SIGSYS"};

/* Bitmap to track the signal trigger and delivery. This is a backbone of this
 * test app to determine all the signal is handled appropiately. */
static unsigned int signal_bitmap;

static inline void mark_signal_complete(int sig_no)
{
    printf("%15s %10s \t\t %d \n", "TESTED SIGNAL", signame[sig_no], sig_no);
    signal_bitmap &= ~(1 << sig_no);
}

static inline void mark_signal_pending(int sig_no)
{
    signal_bitmap |= (1 << sig_no);
}

static void signal_handler(int sig_no)
{
    mark_signal_complete(sig_no);
}

/* Handler for invalid memory access */
static void sigsegv_handler(int sig_no, siginfo_t* si, void* arg)
{
    ucontext_t* ctx = (ucontext_t*)arg;
    /* In this example, the length of the offending instruction  is 3 bytes.
     * So we skip the offender. */
    ctx->uc_mcontext.gregs[REG_RIP] += 3;
    mark_signal_complete(sig_no);
}

/* Handler for handling alignment exception */
static void sigbus_handler(int sig_no, siginfo_t* si, void* arg)
{
    ucontext_t* ctx = (ucontext_t*)arg;
    /* T.B.D - the length of the offending instruction is ?? bytes */
    ctx->uc_mcontext.gregs[REG_RIP] += 2; /* T.B.D */
    mark_signal_complete(sig_no);
}

/* Handler for floating point exception */
static void sigfpe_handler(int sig_no, siginfo_t* si, void* arg)
{
    ucontext_t* ctx = (ucontext_t*)arg;
    /* In this example, the length of the offending instruction  is 2 bytes.
     * So we skip the offender */
    ctx->uc_mcontext.gregs[REG_RIP] += 2;
    mark_signal_complete(sig_no);
}

/* Handler for illegal instruction exception */
static void sigill_handler(int sig_no, siginfo_t* si, void* arg)
{
    ucontext_t* ctx = (ucontext_t*)arg;
    ctx->uc_mcontext.gregs[REG_RIP] += 2;
    mark_signal_complete(sig_no);
}

static void do_divide_error(void)
{
    volatile int division_by_zero = 0;
    mark_signal_pending(SIGFPE);
    division_by_zero = 1 / division_by_zero;
}

static void do_null_pointer_exception(void)
{
    mark_signal_pending(SIGSEGV);
    volatile char* p = 0x0;
    volatile char x = *p;
}

static void do_sigbus_exception(void)
{
    char* cptr = NULL;

    mark_signal_pending(SIGBUS);

    /* Enable alignment checking on x86_64 */
    __asm__("pushf\norl $0x40000,(%rsp)\npopf");

    /* malloc provides aligned memory */
    cptr = malloc(sizeof(int) + 1);

    /* Increment the pointer by one, making it misaligned */
    int* iptr = (int*)++cptr;

    /* Dereference it as an int pointer, causing an unaligned access */
    *iptr = 42;
}

static void do_sigill_exception(void)
{
    mark_signal_pending(SIGILL);
    /* T.B.D */
}

static void raise_signal(int sig_no)
{
    mark_signal_pending(sig_no);
    raise(sig_no);
}

static void do_sigalarm(void)
{
    mark_signal_pending(SIGALRM);
    alarm(1);
}

static void do_setitimer(void)
{
    mark_signal_pending(SIGALRM);
    struct itimerval timer;
    /* expire once after 100 nanosecond */
    timer.it_value.tv_sec = 0;
    timer.it_value.tv_usec = 100;
    timer.it_interval.tv_sec = 0;
    timer.it_interval.tv_usec = 0;

    setitimer(ITIMER_REAL, &timer, NULL);
}

/* Function to check the signal bitmap to confirming the
 * reciept of signal for each exception */
static void check_signal_delivery(void)
{
    int bail_out_cnt = 3;
    while (bail_out_cnt)
    {
        if (!signal_bitmap)
            break;
        sleep(1);
        bail_out_cnt--;
    }
    if (signal_bitmap)
    {
        printf("TEST FAILED\n");
        for (int i = 0; i < SIGNAL_COUNT; i++)
            if ((signal_bitmap & (1 << i)))
                printf("SIGNAL ==> %s <== NOT CLEARED \n", signame[i]);
    }
    else
        printf("TEST PASSED\n");
}

int main(int argc, char* argv[])
{
    struct sigaction sa;
    char errmsg[256] = {0};
    int sig_no = 0;
    signal_bitmap = 0;

    /* Phase1: Test the signal dispatch and delivery at LKL level */
    for (sig_no = 1; sig_no < SIGNAL_COUNT; sig_no++)
    {
        if (sig_no == SIGKILL || sig_no == SIGSTOP)
            continue;
        INSTALL_SIGNAL_HANDLER(sig_no, signame[sig_no], signal_handler)
    }

    for (sig_no = 1; sig_no < SIGNAL_COUNT; sig_no++)
    {
        if (sig_no == SIGKILL || sig_no == SIGSTOP)
            continue;
        RAISE_SIGNAL(sig_no)
    }

    /* Check signal delivery pending status */
    /* If any signal is pending then test is marked as failed. */
    check_signal_delivery();

    /* Phase2: Test the exception generated by SGX HW from OE SDK */
    INSTALL_SIGACTION_HANDLER(SIGFPE, signame[SIGFPE], sigfpe_handler)
    INSTALL_SIGACTION_HANDLER(SIGSEGV, signame[SIGSEGV], sigsegv_handler)

#ifdef __ALL_HW_EXCEPTION_OE_SUPPORT__
    // Exception currently not trigerred from OE
    INSTALL_SIGACTION_HANDLER(SIGBUS, signame[SIGBUS], sigbus_handler)
    INSTALL_SIGACTION_HANDLER(SIGILL, signame[SIGILL], sigill_handler)
#endif //__ALL_HW_EXCEPTION_OE_SUPPORT__

    DO_EXCEPTION(divide_error)
    DO_EXCEPTION(null_pointer_exception)
    DO_EXCEPTION(sigalarm)

#ifdef __ALL_HW_EXCEPTION_OE_SUPPORT__
    // Exception currently not trigerred from OE
    DO_EXCEPTION(sigbus_exception)
    DO_EXCEPTION(sigill_exception)
#endif //__ALL_HW_EXCEPTION_OE_SUPPORT__

    /* Check signal delivery pending status */
    /* If any signal is pending then test is marked as failed. */
    check_signal_delivery();

    /* Another SIGALRM related test, needs to be run in a different phase from
     * the sigalarm test */
    DO_EXCEPTION(setitimer)

    /* Check signal delivery pending status */
    /* If any signal is pending then test is marked as failed. */
    check_signal_delivery();

    return 0;
}
