/* Test program to validate the global variable exposed from libsgxlkl.so */
/* Motive is to capture all global variable validation rather depending of
 * external apps */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

extern int errno;
static int prog_exec_status = 0;

// Enumeration for test cases
typedef enum test_index
{
    en_test_errno_fail_index = 1,
    en_test_errno_pass_index,
    en_test_optind_index,
    en_test_opterr_index,
    en_test_getopt_index,

    // add new test above
    en_total_test
} test_index_en;

static int _do_file_ops(const char* filename)
{
    FILE* fp = NULL;

    // Clear errno and perform operation
    errno = 0;

    fp = fopen(filename, "r");
    int l_err_no = errno;

    if (!fp)
        fprintf(stderr, "fopen failed errno(%d)\n", errno);

    if (fp)
        fclose(fp);

    return l_err_no;
}

void perform_getopt_test(int argc, char** argv)
{
    int aflag = 0, bflag = 0, index = 0, c = 0;
    char* cvalue = NULL;

    // Reset the global variables.
    opterr = 0, optind = 0;

    while ((c = getopt(argc, argv, "abc:")) != -1)
    {
        switch (c)
        {
            case 'a':
                aflag = 1;
                break;
            case 'b':
                bflag = 1;
                break;
            case 'c':
                cvalue = optarg;
                break;
            default:
                fprintf(stderr, "Invalid option \n");
        }
    }

    // fprintf(stdout, "optind: %d opterr: %d cvalue: %p:%s\n", optind, opterr,
    // cvalue, cvalue);
    if ((aflag != 1) || (bflag != 1) || strcmp(cvalue, "hello"))
        prog_exec_status |= (1 << en_test_getopt_index);

    if (optind != 5)
        prog_exec_status |= (1 << en_test_optind_index);

    if (opterr != 0)
        prog_exec_status |= (1 << en_test_opterr_index);

    return;
}

void perform_errno_test(void)
{
    int l_err_no = 0;

    // pass a non existent file to cause failure and check errno
    l_err_no = _do_file_ops("file_fake.txt");

    if (l_err_no != 2)
    {
        prog_exec_status |= (1 << en_test_errno_fail_index);
        fprintf(
            stdout,
            "fake test failed: errno=%i l_err_no=%i\n",
            errno,
            l_err_no);
    }

    // reset the errno to verify the valid scenario
    l_err_no = _do_file_ops("/helloworld.txt");

    if (l_err_no != 0)
    {
        prog_exec_status |= (1 << en_test_errno_pass_index);
        fprintf(
            stdout,
            "valid test failed: errno=%i l_err_no=%i\n",
            errno,
            l_err_no);
    }
}

void print_test_status(void)
{
    for (int i = 1; i < en_total_test; i++)
        if (prog_exec_status & (1 << i))
            fprintf(stdout, "test: %d failed\n", i);
}

int main(int argc, char** argv)
{
    perform_getopt_test(argc, argv);
    perform_errno_test();

    if (!prog_exec_status)
        fprintf(stdout, "TEST PASSED\n");
    else
        fprintf(stdout, "TEST FAILED\n");

    print_test_status();

    return 0;
}
