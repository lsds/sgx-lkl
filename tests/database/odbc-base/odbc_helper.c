#include "odbc_helper.h"
#define __stdcall
#include <msodbcsql.h>
#include <sql.h>
#include <sqlext.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static SQLHENV env = NULL;
static SQLHDBC dbc = NULL;

static void printSQLInfo(SQLRETURN rc, SQLHANDLE h, SQLSMALLINT ht)
{
    if (!h)
        return;

    SQLSMALLINT i = 0;
    SQLSMALLINT outlen = 0;
    char errmsg[1024];
    while ((rc = SQLGetDiagField(
                ht,
                h,
                ++i,
                SQL_DIAG_MESSAGE_TEXT,
                errmsg,
                sizeof(errmsg),
                &outlen)) == SQL_SUCCESS ||
           rc == SQL_SUCCESS_WITH_INFO)
    {
        fprintf(stderr, "Return Code#%d: %s\n", i, errmsg);
    }
}

static int checkRC(SQLRETURN rc, char* msg, SQLHANDLE h, SQLSMALLINT ht)
{
    if (rc == SQL_SUCCESS_WITH_INFO)
    {
        printSQLInfo(rc, h, ht);
    }
    else if (rc == SQL_ERROR || rc != SQL_SUCCESS)
    {
        fprintf(stderr, "Error occurred upon %s\n", msg);
        printSQLInfo(rc, h, ht);
        return FAILURE;
    }
    return SUCCESS;
}

int connectDB(char* connstr)
{
    int result = FAILURE;
    SQLRETURN rc;
    SQLHSTMT stmt = NULL;
    char sqlbuf[SQL_BUFFER_LEN];

    rc = SQLAllocHandle(SQL_HANDLE_ENV, NULL, &env);
    OK_CHECK(checkRC(rc, "allocating environment handle", 0, 0));
    rc = SQLSetEnvAttr(env, SQL_ATTR_ODBC_VERSION, (SQLPOINTER)SQL_OV_ODBC3, 0);
    OK_CHECK(checkRC(rc, "setting ODBC version to 3.0", env, SQL_HANDLE_ENV));
    rc = SQLAllocHandle(SQL_HANDLE_DBC, env, &dbc);
    OK_CHECK(checkRC(rc, "allocating connection handle", env, SQL_HANDLE_ENV));
    rc = SQLDriverConnect(
        dbc, 0, connstr, strlen(connstr), NULL, 0, NULL, SQL_DRIVER_NOPROMPT);
    OK_CHECK(checkRC(rc, "connecting to data source", dbc, SQL_HANDLE_DBC));

    result = SUCCESS;

done:
    if (stmt)
        SQLFreeStmt(stmt, SQL_CLOSE);
    return result;
}

int execute()
{
    int result = FAILURE;
    SQLRETURN rc;
    SQLHSTMT stmt = NULL;
    char sqlbuf[SQL_BUFFER_LEN];

    // Do a sample query
    rc = SQLAllocHandle(SQL_HANDLE_STMT, dbc, &stmt);
    OK_CHECK(checkRC(rc, "allocating statement handle", dbc, SQL_HANDLE_DBC));
    rc = SQLExecDirect(stmt, "SELECT USER_NAME()", SQL_NTS);
    OK_CHECK(checkRC(rc, "Sample query execution.", stmt, SQL_HANDLE_STMT));
    char query_result[256];

    // Binding data column
    rc = SQLBindCol(stmt, 1, SQL_C_CHAR, query_result, sizeof(query_result), 0);
    OK_CHECK(checkRC(rc, "Binding columns for select", stmt, SQL_HANDLE_STMT));

    // Fetch query results
    if (SQL_SUCCESS == (rc = SQLFetch(stmt)))
    {
        printf("Successfully logged in as: %s\n", query_result);
    }
    else
    {
        printf("Cannot fetch user id from Database. There may be errors "
               "in database connection.");
        goto done;
    }
    result = SUCCESS;

done:
    if (stmt)
        SQLFreeStmt(stmt, SQL_CLOSE);
    return result;
}

void disconnect()
{
    SQLDisconnect(dbc);
    SQLFreeHandle(SQL_HANDLE_DBC, dbc);
    SQLFreeHandle(SQL_HANDLE_ENV, env);
}