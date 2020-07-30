#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "odbc_helper.h"

#define CONNSTR_MAX_LEN 2048

int main(int argc, char** argv)
{
    int result = FAILURE;
    char fullConnstr[CONNSTR_MAX_LEN];

    char* db_server = getenv("DB_SERVER_NAME");
    char* db_name = getenv("DB_NAME");
    char* maa_url = getenv("MAA_URL");

    char* db_uid = getenv("DB_USERID");
    char* db_password = getenv("DB_PASSWORD");

    if (argc != 3)
    {
        fprintf(stderr, "Error: correct usage: %s (msi|classic) ('reg_init'|<whatever>)\n", argv[0]);
        goto done;
    }

    const char* conn_mode = argv[1];
    if (db_server == NULL || db_name == NULL || maa_url == NULL)
    {
        printf("%s", db_server);
        printf("%s", db_name);
        printf("%s", maa_url);
        fprintf(
            stderr,
            "\nError: env DB_SERVER_NAME, DB_NAME or MAA_URL has not been "
            "set.\n");
        goto done;
    }

    if (SUCCESS == strcmp(conn_mode, "msi"))
    {
        if (snprintf(
                fullConnstr,
                CONNSTR_MAX_LEN,
                "Server=%s;Database=%s;"
                "Authentication=ActiveDirectoryMsi;"
                "Driver={ODBC Driver 17 for SQL Server};"
                "ColumnEncryption=SGX-AAS,%s/attest/"
                "SgxEnclave?api-version=2018-09-01-preview",
                db_server,
                db_name,
                maa_url) >= CONNSTR_MAX_LEN)
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
                "Server=%s;Database=%s;"
                "UID=%s;PWD=%s;"
                "Driver={ODBC Driver 17 for SQL Server};"
                "ColumnEncryption=SGX-AAS,%s/attest/"
                "SgxEnclave?api-version=2018-09-01-preview",
                db_server,
                db_name,
                db_uid,
                db_password,
                maa_url) >= CONNSTR_MAX_LEN)
        {
            fprintf(stderr, "\nError: Connection string is too long.\n");
            goto done;
        }
    }
    else
    {
        fprintf(stderr, "Error: unknown connection mode.\n");
        goto done;
    }

    if (SUCCESS != (result = connectDB(fullConnstr)))
    {
        fprintf(stderr, "\nError: Failed to connect to database.\n");
        goto done;
    }

    char* setting = argv[2];

    if (SUCCESS != (result = execute(setting)))
    {
        fprintf(stderr, "\nError: Failed to execute one or more queries.\n");
        goto done;
    }

    result = SUCCESS;
done:
    disconnect();
    return result;
}
