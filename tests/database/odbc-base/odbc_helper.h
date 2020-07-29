// Copyright Microsoft.
// Licensed under the attached Microsoft Software License Terms
#ifndef ODBC_HELPER_H
#define ODBC_HELPER_H

#define SUCCESS 0
#define FAILURE 1

#define CONNSTR_MAX_LEN 1024
#define SQL_BUFFER_LEN 1024

#define OK_CHECK(EXPRESSION)         \
    do                               \
    {                                \
        int _result_ = (EXPRESSION); \
        if (_result_ != SUCCESS)     \
            goto done;               \
    } while (0)

int connectDB(char* connstr);
int execute();
void clean();
void disconnect();

#endif // ODBC_HELPER_H
