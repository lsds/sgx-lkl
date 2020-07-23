#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "odbc_helper.h"

int main(int argc, char** argv)
{
    int result = FAILURE;
    char fullConnstr[CONNSTR_MAX_LEN];

    char* db_name = getenv("DB_NAME");
    char* db_server = getenv("DB_SERVER_NAME");

    if (argc != 2)
    {
        fprintf(stderr, "Error: correct usage: %s (msi|classic)\n", argv[0]);
        goto done;
    }

    const char* conn_mode = argv[1];
    if (db_server == NULL || db_name == NULL)
    {
        fprintf(
            stderr,
            "\nError: env DB_SERVER_NAME or DB_NAME has not been set.\n");
        goto done;
    }

    if (SUCCESS == strcmp(conn_mode, "msi"))
    {
        if (snprintf(
                fullConnstr,
                CONNSTR_MAX_LEN,
                "Server=%s;Database=%s;"
                "Driver={ODBC Driver 17 for SQL "
                "Server};Authentication=ActiveDirectoryMsi",
                db_server,
                db_name) >= CONNSTR_MAX_LEN)
        {
            fprintf(stderr, "\nError: Connection string is too long.\n");
            goto done;
        }
    }
    else if (SUCCESS == strcmp(conn_mode, "classic"))
    {
        char* db_password = getenv("DB_PASSWORD");
        char* db_uid = getenv("DB_USERID");

        if (db_password == NULL || db_uid == NULL)
        {
            fprintf(
                stderr,
                "\nError: env DB_PASSWORD or DB_USERID has not been set.\n");
            goto done;
        }
        if (snprintf(
                fullConnstr,
                CONNSTR_MAX_LEN,
                "Server=%s;Database=%s;UID=%s;PWD=%s;"
                "Driver={ODBC Driver 17 for SQL Server};",
                db_server,
                db_name,
                db_uid,
                db_password) >= CONNSTR_MAX_LEN)
        {
            fprintf(stderr, "\nError: Connection string is too long.\n");
            goto done;
        }
    }
    else
    {
        fprintf(stderr, "Error: unknown connection mode.\n", argv[0]);
        goto done;
    }

    if (SUCCESS != (result = connectDB(fullConnstr)))
    {
        fprintf(stderr, "\nError: Failed to execute one or more queries.\n");
        goto done;
    }

    if (SUCCESS != (result = execute()))
    {
        result = FAILURE;
        goto done;
    }

    result = SUCCESS;

done:
    disconnect();
    return result;
}
