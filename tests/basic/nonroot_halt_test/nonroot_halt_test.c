/* Program to validate that sgxlkl-oe shuddown gracefully even if
 * application modifies uid or permission */

#include <errno.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

int handle_failure(const char* msg)
{
    printf("%s \n", msg);
    return 1;
}

int main()
{
    uid_t uid = 0;
    int ret = 0;
    /* alpine root file system has a nobody user */
    char* username = "nobody";
    struct passwd* pwd = NULL;

    pwd = getpwuid(getuid());
    if (!pwd)
        return handle_failure("TEST FAILED (getpwuid FAILED)");

    printf("username = %s uid = %ld \n", pwd->pw_gecos, (long)pwd->pw_uid);

    pwd = getpwnam(username);
    if (!pwd)
        return handle_failure("TEST FAILED (USER NOT FOUND)");

    /* Fetch uid and set the uid of application as non root */
    uid = (uid_t)pwd->pw_uid;
    ret = setuid(uid);
    if (ret)
        return handle_failure("TEST FAILED (setuid failed)");

    printf("new username = %s uid = %ld\n", pwd->pw_gecos, (long)pwd->pw_uid);

    printf("TEST PASSED (check application exits successfully)\n");

    return 0;
}
