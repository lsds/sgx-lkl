#include <stdio.h>
#include <stdlib.h>
#include "odbc_proxy.h"

#define CONNSTR_MAX_LEN 2048

int main(int argc, char** argv)
{
    int result = FAILURE;
    char fullConnstr[CONNSTR_MAX_LEN];

    char* db_password = getenv("DB_PASSWORD");
    char* db_server = getenv("DB_SERVER_NAME");
    char* db_uid = getenv("DB_USERID");
    char* db_name = getenv("DB_NAME");
    char* maa_add = getenv("MAA_SERVICE_ADD");

    if (db_password == NULL || db_server == NULL || db_uid == NULL ||
        db_name == NULL || maa_add == NULL)
    {
        fprintf(
            stderr,
            "\n-------------------- Failure --------------------"
            "\nOne or more required environment variables not being set."
            "\n-------------------- Failure --------------------\n\n");
        goto done;
    }
    if (snprintf(
            fullConnstr,
            CONNSTR_MAX_LEN,
            "Server=%s;Database=%s;UID=%s;PWD=%s;"
            "Driver={ODBC Driver 17 for SQL Server};"
            "ColumnEncryption=SGX-AAS,%s"
            "attest/SgxEnclave?api-version=2018-09-01-preview",
            db_server,
            db_name,
            db_uid,
            db_password,
            maa_add) >= CONNSTR_MAX_LEN)
    {
        fprintf(
            stderr,
            "\n-------------------- Failure --------------------"
            "\nConnection string is too long."
            "\n-------------------- Failure --------------------\n\n");
        goto done;
    }

    // Connect to database with AAD credentials.
    if (SUCCESS != (result = odbc_proxy_connectDB(fullConnstr)))
    {
        fprintf(
            stderr,
            "\n-------------------- Failure --------------------"
            "\nFailed to connect to Database."
            "\n-------------------- Failure --------------------\n\n");
        goto done;
    }

    if (SUCCESS != (result = odbc_proxy_execute()))
    {
        fprintf(
            stderr,
            "\n-------------------- Failure --------------------"
            "\nFailed to execute one or more queries."
            "\n-------------------- Failure --------------------\n\n");
        goto done;
    }

    result = SUCCESS;
done:
    odbc_proxy_disconnect();
    return result;
}
