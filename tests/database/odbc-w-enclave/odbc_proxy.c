#include <stdlib.h>
#define __stdcall
#include <dlfcn.h>
#include <sql.h>
#include <sqlext.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

#include "msodbcsql.h"
#include "odbc_proxy.h"

// The app is to test the functionality of ODBC connection, so here hard coded
// CMK and CEK VALUE are used
#define CMK_NAME "SGXTESTCMK"
#define CMK_VALUE "abcdefghijklmnopkrstuvwxyz012345"
#define CEK_NAME "SGXTESTCEK"
#define CEK_VALUE "012345abcdefghijklmnopkrstuvwxyz"
#define TABLE_NAME "SGXTESTTABLE"
#define MAX_KEY_LEN 32       // Max Key Length for both CMK and CEK
#define DEFAULT_VCHAR_LEN 32 // Default length of all varchar fields
#define DLLPATH "./cksp.so"
#define KSPNAME L"AZURE_KEY_VAULT"
#define SQL_BUFFER_LEN 1024

#define OK_CHECK(EXPRESSION)         \
    do                               \
    {                                \
        int _result_ = (EXPRESSION); \
        if (_result_ != SUCCESS)     \
            goto done;               \
    } while (0)

static void* hProvLib = NULL;
static SQLHENV env = NULL;
static SQLHDBC dbc = NULL;

static size_t wchar_str_len(const wchar_t* ws)
{
    size_t i = 0;
    for (const int16_t* p = ws; *p != 0; p++, i++)
        ;
    return i;
}

static int wchar_str_cmp(const wchar_t* p1, const wchar_t* p2)
{
    return memcmp(p1, p2, (wchar_str_len(p1) + 1) * sizeof(int16_t));
}

static void print_sql_info(SQLRETURN rc, SQLHANDLE h, SQLSMALLINT ht)
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
        print_sql_info(rc, h, ht);
    }
    else if (rc == SQL_ERROR || rc != SQL_SUCCESS)
    {
        fprintf(stderr, "Error occurred upon %s\n", msg);
        print_sql_info(rc, h, ht);
        return FAILURE;
    }
    return SUCCESS;
}

static int clean_up(SQLHSTMT stmt)
{
    int result = FAILURE;
    SQLRETURN rc;
    printf("Drop table, CMK and CEK.\n");
    rc = SQLExecDirect(stmt, "DROP TABLE IF EXISTS " TABLE_NAME, SQL_NTS);
    OK_CHECK(checkRC(rc, "DROP TABLE.", stmt, SQL_HANDLE_STMT));
    // do not explicitly check key drops, because if the does not exist, will
    // return error code
    SQLExecDirect(stmt, "DROP COLUMN ENCRYPTION KEY " CEK_NAME, SQL_NTS);
    SQLExecDirect(stmt, "DROP COLUMN MASTER KEY " CMK_NAME, SQL_NTS);

    result = SUCCESS;
done:
    return result;
}

static int create_CMK(SQLHSTMT stmt)
{
    int result = FAILURE;
    SQLRETURN rc;
    char* stmt_str =
        "CREATE COLUMN MASTER KEY " CMK_NAME " WITH"
        "(KEY_STORE_PROVIDER_NAME = N'AZURE_KEY_VAULT',"
        "KEY_PATH = "
        "N'https://acckeyvault.vault.azure.net/keys/TestCMK1/"
        "2a89d8e0cb834009827d588a32709e39',"
        "ENCLAVE_COMPUTATIONS (SIGNATURE ="
        "0x8DB2E0CE56163AB9CD42A0316F63817A9451B4320F911C2193625E56CF484425"
        "CE3694920A8DE9C29545DC46C6C312239E6ADC3F34593C4F43A5A754D06BA582A6"
        "ADEC75A97ABF11114D1B9406ED7C81BC5EB77B1AA266C18DA96EE9220BC1124805"
        "159FA110E519926E18589F16D785F0F10CAD4282C989703281E74EE3A3C3B8F76D"
        "6E9899DCE9B8ED314B9B4DB03EF96C97BF6DC54EA06CCF44E0E5B28FAB65D51B14"
        "8994F35A32AAABD4C1F370D6F20352EF82F3CCD50689D02F12CCCB2978AB59D8A8"
        "503A9424000C6452C295A3110D3BB3F9AEE6C13BDF7E46467532B24E9B8FB32DB1"
        "0A9C77658DB5A1F0A4D03A1F0633BF542F53A114F3665EAB8DF0))";
    printf("Create CMK: %s\n", stmt_str);
    rc = SQLExecDirect(stmt, stmt_str, SQL_NTS);
    OK_CHECK(checkRC(rc, "Create CMK.", stmt, SQL_HANDLE_STMT));

    result = SUCCESS;
done:
    return rc;
}

static void postKspError(CEKEYSTORECONTEXT* ctx, const wchar_t* msg, ...)
{
    if (msg > (wchar_t*)65535)
        wprintf(L"Provider emitted message: %s\n", msg);
    else
        wprintf(L"Provider emitted message ID %d\n", msg);
}

// Find the custom Key Store Provider by name
static CEKEYSTOREPROVIDER2* loadKspByName(char* libPath, wchar_t* kspName)
{
    CEKEYSTOREPROVIDER2** ppKsp;
    // Load the provider dynamic link library
    if (!(hProvLib = dlopen(libPath, RTLD_NOW)) ||
        !(ppKsp =
              (CEKEYSTOREPROVIDER2**)dlsym(hProvLib, "CEKeystoreProvider2")))
    {
        fprintf(stderr, "Error loading KSP library\n");
        return NULL;
    }

    CEKEYSTOREPROVIDER2* pKsp;
    while (pKsp = *ppKsp++)
    {
        if (!wchar_str_cmp(kspName, pKsp->Name))
        {
            if (!pKsp->Init || !pKsp->Write || !pKsp->DecryptCEK ||
                !pKsp->EncryptCEK || !pKsp->VerifyCMKMetadata)
            {
                fprintf(
                    stderr,
                    "Could not find required functions in the library\n");
                return NULL;
            }
            return pKsp;
        }
    }
    fprintf(stderr, "Could not find provider in the library\n");
    return NULL;
}

static SQLRETURN create_ecek(SQLHSTMT stmt)
{
    int result = FAILURE;
    unsigned char CEK[32];
    unsigned char* ECEK;
    unsigned short ECEKlen;
    char ecekStr[2 * ECEKlen + 1];
    CEKEYSTORECONTEXT* ctx = {0};
    CEKEYSTOREPROVIDER2* pKsp = NULL;
    SQLRETURN rc;

    // Load n init custom key store provider dynamic link library
    if (!(pKsp = loadKspByName(DLLPATH, KSPNAME)))
    {
        fprintf(stderr, "Failed to load CKSP\n");
        return 1;
    }
    if (!pKsp->Init(ctx, postKspError))
    {
        fprintf(stderr, "Failed to initialize CKSP\n");
        return 1;
    }

    // use predefined/hardcoded value for demo purpose
    OK_CHECK(!pKsp->EncryptCEK(
        ctx,
        postKspError,
        L"",
        L"none",
        CEK_VALUE,
        MAX_KEY_LEN,
        &ECEK,
        &ECEKlen));

    ecekStr[2 * ECEKlen] = '\0';
    for (size_t i = 0; i < ECEKlen; i++)
        sprintf(ecekStr + 2 * i, "%02x", ECEK[i]);

    // Create a CEK and store on the database server
    char cekSql[SQL_BUFFER_LEN];
    OK_CHECK(
        snprintf(
            cekSql,
            SQL_BUFFER_LEN,
            "CREATE COLUMN ENCRYPTION KEY " CEK_NAME " WITH VALUES ("
            "COLUMN_MASTER_KEY = " CMK_NAME ","
            "ALGORITHM = 'none',"
            "ENCRYPTED_VALUE = 0x%s)",
            ecekStr) >= SQL_BUFFER_LEN);
    fprintf(stderr, "Create CEK: %s\n", cekSql);
    rc = SQLExecDirect(stmt, cekSql, SQL_NTS);
    OK_CHECK(checkRC(rc, "Creating and storing ECEK", stmt, SQL_HANDLE_STMT));
    result = SUCCESS;
done:
    dlclose(hProvLib);
    free(ECEK);
    return result;
}

static int create_table(SQLHSTMT stmt)
{
    int result = FAILURE;
    SQLRETURN rc;

    char stmt_str[SQL_BUFFER_LEN] =
        "CREATE TABLE " TABLE_NAME
        "(DATA varchar(32) COLLATE Latin1_General_BIN2 ENCRYPTED WITH "
        "(COLUMN_ENCRYPTION_KEY=" CEK_NAME ", ENCRYPTION_TYPE=RANDOMIZED, "
        "ALGORITHM='AEAD_AES_256_CBC_HMAC_SHA_256'))";

    printf("\n%s\n", stmt_str);
    rc = SQLExecDirect(stmt, stmt_str, SQL_NTS);
    OK_CHECK(checkRC(rc, "Creating table", stmt, SQL_HANDLE_STMT));

    result = SUCCESS;
done:
    return result;
}

static int insert_data_to_table(SQLHSTMT stmt)
{
    int result = FAILURE;
    SQLRETURN rc;
    char data[DEFAULT_VCHAR_LEN];

    // Binding parameter for encrypted column query
    rc = SQLBindParameter(
        stmt,
        1,
        SQL_PARAM_INPUT,
        SQL_C_CHAR,
        SQL_VARCHAR,
        DEFAULT_VCHAR_LEN,
        0,
        data,
        DEFAULT_VCHAR_LEN,
        0);
    OK_CHECK(
        checkRC(rc, "Binding parameters for insert", stmt, SQL_HANDLE_STMT));
    strcpy(data, "encrypted-data");
    rc = SQLExecDirect(stmt, "INSERT INTO SGXTESTTABLE values (?)", SQL_NTS);
    OK_CHECK(checkRC(rc, "Inserting data into table", stmt, SQL_HANDLE_STMT));

    result = SUCCESS;
done:
    return result;
}

static int query_table(SQLHSTMT stmt)
{
    int result = FAILURE;
    SQLRETURN rc;
    char data[DEFAULT_VCHAR_LEN];

    rc = SQLExecDirect(stmt, "SELECT * FROM " TABLE_NAME, SQL_NTS);
    OK_CHECK(checkRC(rc, "Query table", stmt, SQL_HANDLE_STMT));
    rc = SQLBindCol(stmt, 1, SQL_C_CHAR, data, DEFAULT_VCHAR_LEN, 0);

    if (SQL_SUCCESS == (rc = SQLFetch(stmt)))
    {
        printf("\nQuery from encrypted column successfully. Decrepted data: %s\n", data);
    }

    SQLFreeStmt(stmt, SQL_CLOSE);
    OK_CHECK(checkRC(rc, "Free statement", stmt, SQL_HANDLE_STMT));

    result = SUCCESS;
done:
    return result;
}

int odbc_proxy_connectDB(char* connstr)
{
    int result = FAILURE;
    SQLRETURN rc;
    char sqlbuf[SQL_BUFFER_LEN];
    char* ckspData = "";
    size_t ckspDataSize = sizeof(char*);

    // Connect to Database Server
    rc = SQLAllocHandle(SQL_HANDLE_ENV, NULL, &env);
    OK_CHECK(checkRC(rc, "allocating environment handle", 0, 0));
    rc = SQLSetEnvAttr(env, SQL_ATTR_ODBC_VERSION, (SQLPOINTER)SQL_OV_ODBC3, 0);
    OK_CHECK(checkRC(rc, "setting ODBC version to 3.0", env, SQL_HANDLE_ENV));
    rc = SQLAllocHandle(SQL_HANDLE_DBC, env, &dbc);
    OK_CHECK(checkRC(rc, "allocating connection handle", env, SQL_HANDLE_ENV));
    rc = SQLDriverConnect(
        dbc, 0, connstr, strlen(connstr), NULL, 0, NULL, SQL_DRIVER_NOPROMPT);
    OK_CHECK(checkRC(rc, "connecting to data source", dbc, SQL_HANDLE_DBC));

    // load Custom Key Store Provider
    rc = SQLSetConnectAttr(
        dbc, SQL_COPT_SS_CEKEYSTOREPROVIDER, DLLPATH, SQL_NTS);
    OK_CHECK(checkRC(rc, "Loading KSP into ODBC Driver", dbc, SQL_HANDLE_DBC));

    // Write Custom Key Store Provider, this step is for SQLAEv2
    // compatibility
    if (ckspData != NULL && ckspDataSize > 0)
    {
        unsigned char ksd[sizeof(CEKEYSTOREDATA) + ckspDataSize];
        CEKEYSTOREDATA* pKsd = (CEKEYSTOREDATA*)ksd;
        pKsd->name = KSPNAME;
        pKsd->dataSize = ckspDataSize;
        memcpy(pKsd->data, ckspData, ckspDataSize);
        rc = SQLSetConnectAttr(
            dbc, SQL_COPT_SS_CEKEYSTOREDATA, (SQLPOINTER)pKsd, SQL_IS_POINTER);
        OK_CHECK(checkRC(rc, "Configuring the KSP", dbc, SQL_HANDLE_DBC));
    }

    result = SUCCESS;
done:
    return result;
}

int odbc_proxy_execute()
{
    int result = FAILURE;
    SQLHSTMT stmt;
    SQLRETURN rc = SQLAllocHandle(SQL_HANDLE_STMT, dbc, &stmt);
    OK_CHECK(checkRC(rc, "allocating statement handle", dbc, SQL_HANDLE_DBC));

    // 1. before start drop all tables and CEKs, CMKs
    OK_CHECK(clean_up(stmt));

    // 2. Create CMK (Column Master Key)
    OK_CHECK(create_CMK(stmt));

    // 3. create CEK (Column Encryption Key)
    OK_CHECK(create_ecek(stmt));

    // 4. Create Data table
    OK_CHECK(create_table(stmt));

    // 5. Insert Data into the table
    OK_CHECK(insert_data_to_table(stmt));

    // 6. Query data
    OK_CHECK(query_table(stmt));

    result = SUCCESS;
done:
    if (stmt)
    {
        SQLFreeStmt(stmt, SQL_CLOSE);
    }
    return result;
}

void odbc_proxy_disconnect()
{
    SQLDisconnect(dbc);
    SQLFreeHandle(SQL_HANDLE_DBC, dbc);
    SQLFreeHandle(SQL_HANDLE_ENV, env);
}