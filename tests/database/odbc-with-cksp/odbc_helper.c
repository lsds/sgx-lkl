#include <stdlib.h>
#define __stdcall
#include <dlfcn.h>
#include <sql.h>
#include <sqlext.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <wchar.h>

#include "msodbcsql.h"
#include "odbc_helper.h"

// The app is to test the functionality of ODBC connection, so here hard coded
// CMK and CEK VALUE are used
#define CMK_NAME "SGXTESTCMK"
#define CMK_VALUE "abcdefghijklmnopkrstuvwxyz012345"
#define CEK_NAME "SGXTESTCEK"
#define CEK_VALUE "012345abcdefghijklmnopkrstuvwxyz"
#define REG_TABLE_NAME "SGXREGISTRY"
#define DATA_TABLE_NAME "SGXTESTTABLE"
#define SAMPLE_DATA "encrypted-data"
#define MAX_DB_OBJECT_ID_LEN 32
#define MAX_DB_OBJECT_NAME_LEN 64
#define MAX_KEY_LEN 32       // Max Key Length for both CMK and CEK
#define DEFAULT_VCHAR_LEN 32 // Default length of all varchar fields
#define DLLPATH "./cksp.so"
#define KSPNAME L"AZURE_KEY_VAULT"
#define SQL_BUFFER_LEN 1024

static char db_object_id[MAX_DB_OBJECT_ID_LEN];
static char cek_name_gen[MAX_DB_OBJECT_NAME_LEN];
static char cmk_name_gen[MAX_DB_OBJECT_NAME_LEN];
static char table_name_gen[MAX_DB_OBJECT_NAME_LEN];

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

// generate random object names for SQL Server Table, CMK and CEK
// The format is:
//      <OBJECT_NAME> := <CONSTANT_OBJECT_NAME><OBJECT_ID>
//      <OBJECT_ID> := <timestamp><rand value>
static void generate_objects_names(SQLHSTMT stmt)
{
    time_t _time = time(NULL);
    srand(_time);
    int random_val = rand();
    sprintf(db_object_id, "_%ld_%d", _time, random_val);
    sprintf(cek_name_gen, "%s%s", CEK_NAME, db_object_id);
    sprintf(cmk_name_gen, "%s%s", CMK_NAME, db_object_id);
    sprintf(table_name_gen, "%s%s", DATA_TABLE_NAME, db_object_id);
}

static int register_db_object(SQLHSTMT stmt, const char* type)
{
    int result = FAILURE;
    SQLRETURN rc;
    char buffer[SQL_BUFFER_LEN];
    if (type == NULL)
    {
        fprintf(stderr, "Type to register cannot be empty.\n");
        goto done;
    }
    sprintf(
        buffer,
        "INSERT INTO %s (ID, TYPE) VALUES ('%s','%s')",
        REG_TABLE_NAME,
        db_object_id,
        type);
    rc = SQLExecDirect(stmt, buffer, SQL_NTS);
    OK_CHECK(checkRC(
        rc, "Register object to registry table", stmt, SQL_HANDLE_STMT));
    result = SUCCESS;
done:
    return result;
}

static int deregister_db_object(SQLHSTMT stmt, const char* type)
{
    int result = FAILURE;
    SQLRETURN rc;
    char buffer[SQL_BUFFER_LEN];
    if (type == NULL)
    {
        fprintf(stderr, "Type to be deregister cannot be empty.\n");
        goto done;
    }
    sprintf(
        buffer,
        "DELETE FROM %s WHERE ID='%s' AND TYPE='%s'",
        REG_TABLE_NAME,
        db_object_id,
        type);
    rc = SQLExecDirect(stmt, buffer, SQL_NTS);
    OK_CHECK(checkRC(
        rc, "Deregister object from registry table", stmt, SQL_HANDLE_STMT));
    result = SUCCESS;
done:
    return result;
}

static int clean_up(SQLHSTMT stmt)
{
    int result = FAILURE;
    SQLRETURN rc;
    printf("Drop generated table, CMK and CEK.\n");
    char buffer[SQL_BUFFER_LEN];

    // drop data table
    sprintf(buffer, "DROP TABLE IF EXISTS %s", table_name_gen);
    rc = SQLExecDirect(stmt, buffer, SQL_NTS);
    OK_CHECK(checkRC(rc, "DROP TABLE.", stmt, SQL_HANDLE_STMT));
    OK_CHECK(deregister_db_object(stmt, "TABLE"));
    // drop column encryption key
    memset(buffer, '\0', SQL_BUFFER_LEN);
    sprintf(buffer, "DROP COLUMN ENCRYPTION KEY %s", cek_name_gen);
    rc = SQLExecDirect(stmt, buffer, SQL_NTS);
    OK_CHECK(checkRC(rc, "DROP CEK.", stmt, SQL_HANDLE_STMT));
    OK_CHECK(deregister_db_object(stmt, "CEK"));
    // drop column master key
    memset(buffer, '\0', SQL_BUFFER_LEN);
    sprintf(buffer, "DROP COLUMN MASTER KEY %s", cmk_name_gen);
    SQLExecDirect(stmt, buffer, SQL_NTS);
    OK_CHECK(checkRC(rc, "DROP CMK.", stmt, SQL_HANDLE_STMT));
    OK_CHECK(deregister_db_object(stmt, "CMK"));

    result = SUCCESS;
done:
    return result;
}

static int create_CMK(SQLHSTMT stmt)
{
    int result = FAILURE;
    SQLRETURN rc;
    // To generate a column master key, a [,ENCLAVE_COMPUTATIONS (SIGNATURE =
    // signature)] is required. SQL Always Encrypted will not recognize custom
    // key store provider, the key value path has to be a real akv path (even
    // though it's a placeholder only and never been accessed for key
    // operations). The signature has to be a hash value computed from the key
    // path and other settings. The signature hash is generated by SQL Server
    // client like SSMS(SQL Server Management Studio) or Data Studio). There is
    // not public API for generating the signature. Here we use a pre-generated
    // CMK path w/ a correct signature value to create CMK. Because we are using
    // custom key store provider, the azure key vault path here is just a
    // placeholder and will never be accessed.
    char buffer[SQL_BUFFER_LEN];
    sprintf(
        buffer,
        "CREATE COLUMN MASTER KEY %s WITH"
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
        "0A9C77658DB5A1F0A4D03A1F0633BF542F53A114F3665EAB8DF0))",
        cmk_name_gen);
    printf("Create CMK: %s\n", buffer);
    rc = SQLExecDirect(stmt, buffer, SQL_NTS);
    OK_CHECK(checkRC(rc, "Create CMK.", stmt, SQL_HANDLE_STMT));

    result = SUCCESS;
done:
    return rc;
}

static void post_ksp_error(CEKEYSTORECONTEXT* ctx, const wchar_t* msg, ...)
{
    if (msg > (wchar_t*)65535)
        wprintf(L"Provider emitted message: %s\n", msg);
    else
        wprintf(L"Provider emitted message ID %d\n", msg);
}

// Find the custom Key Store Provider by name
static CEKEYSTOREPROVIDER2* load_ksp(char* libPath, wchar_t* kspName)
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
    char* ecek_str;
    CEKEYSTORECONTEXT* ctx = {0};
    CEKEYSTOREPROVIDER2* pKsp = NULL;
    SQLRETURN rc;

    // Load n init custom key store provider dynamic link library
    if (!(pKsp = load_ksp(DLLPATH, KSPNAME)))
    {
        fprintf(stderr, "Failed to load CKSP\n");
        goto done;
    }
    if (!pKsp->Init(ctx, post_ksp_error))
    {
        fprintf(stderr, "Failed to initialize CKSP\n");
        goto done;
    }

    // use predefined/hardcoded value for demo purpose
    OK_CHECK(!pKsp->EncryptCEK(
        ctx,
        post_ksp_error,
        L"",
        L"none",
        CEK_VALUE,
        MAX_KEY_LEN,
        &ECEK,
        &ECEKlen));

    ecek_str = malloc(2 * ECEKlen + 1);
    ecek_str[2 * ECEKlen] = '\0';
    for (size_t i = 0; i < ECEKlen; i++)
        sprintf(ecek_str + 2 * i, "%02x", ECEK[i]);

    // Create a CEK and store on the database server
    char buffer[SQL_BUFFER_LEN];
    OK_CHECK(
        snprintf(
            buffer,
            SQL_BUFFER_LEN,
            "CREATE COLUMN ENCRYPTION KEY %s WITH VALUES ("
            "COLUMN_MASTER_KEY = %s,"
            "ALGORITHM = 'none',"
            "ENCRYPTED_VALUE = 0x%s)",
            cek_name_gen,
            cmk_name_gen,
            ecek_str) >= SQL_BUFFER_LEN);
    printf("Create CEK: %s\n", buffer);
    rc = SQLExecDirect(stmt, buffer, SQL_NTS);
    OK_CHECK(checkRC(rc, "Creating and storing ECEK", stmt, SQL_HANDLE_STMT));

    result = SUCCESS;
done:
    dlclose(hProvLib);
    if (ECEK != NULL)
    {
        free(ECEK);
    }
    if (ecek_str != NULL)
    {
        free(ecek_str);
    }
    return result;
}

static int init_registry_table(SQLHSTMT stmt)
{
    int result = FAILURE;
    SQLRETURN rc;
    char buffer[SQL_BUFFER_LEN];

    // if the registry table already exists, do not create the table
    rc = SQLExecDirect(stmt, "SELECT * FROM " REG_TABLE_NAME, SQL_NTS);
    if (SUCCESS == checkRC(rc, "Create registry table", stmt, SQL_HANDLE_STMT))
    {
        result == SUCCESS;
        printf("\nRegistry table already exists, do not need to init.\n");
        SQLFreeStmt(stmt, SQL_CLOSE);
        goto done;
    }

    sprintf(
        buffer,
        "CREATE TABLE %s (ID VARCHAR(32), TYPE VARCHAR(32))",
        REG_TABLE_NAME);
    rc = SQLExecDirect(stmt, buffer, SQL_NTS);
    OK_CHECK(checkRC(rc, "Creating registry table", stmt, SQL_HANDLE_STMT));

    result = SUCCESS;
done:
    return result;
}

static int create_data_table(SQLHSTMT stmt)
{
    int result = FAILURE;
    SQLRETURN rc;

    char buffer[SQL_BUFFER_LEN];

    sprintf(
        buffer,
        "CREATE TABLE %s"
        "(DATA varchar(32) COLLATE Latin1_General_BIN2 ENCRYPTED WITH "
        "(COLUMN_ENCRYPTION_KEY=%s, ENCRYPTION_TYPE=RANDOMIZED, "
        "ALGORITHM='AEAD_AES_256_CBC_HMAC_SHA_256'))",
        table_name_gen,
        cek_name_gen);

    printf("\n%s\n", buffer);
    rc = SQLExecDirect(stmt, buffer, SQL_NTS);
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
    char buffer[SQL_BUFFER_LEN];
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
    strcpy(data, SAMPLE_DATA);
    sprintf(buffer, "INSERT INTO %s values (?)", table_name_gen);
    rc = SQLExecDirect(stmt, buffer, SQL_NTS);
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
    char buffer[SQL_BUFFER_LEN];

    sprintf(buffer, "SELECT * FROM %s", table_name_gen);
    rc = SQLExecDirect(stmt, buffer, SQL_NTS);
    OK_CHECK(checkRC(rc, "Query table", stmt, SQL_HANDLE_STMT));
    rc = SQLBindCol(stmt, 1, SQL_C_CHAR, data, DEFAULT_VCHAR_LEN, 0);
    rc = SQLFetch(stmt);
    OK_CHECK(checkRC(rc, "Fetch data from table", stmt, SQL_HANDLE_STMT));

    if (SUCCESS != strcmp(data, SAMPLE_DATA))
    {
        fprintf(
            stderr,
            "\nError: Fetched and decrypted data [%s] does not match original "
            "data [%s].\n",
            data,
            SAMPLE_DATA);
        goto done;
    }

    SQLFreeStmt(stmt, SQL_CLOSE);
    OK_CHECK(checkRC(rc, "Free statement", stmt, SQL_HANDLE_STMT));

    result = SUCCESS;
done:
    return result;
}

int connectDB(char* connstr)
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

    // Write Custom Key Store Provider, this step is for latest SQL
    // Always Encrypted compatibility
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

int execute(char* setting)
{
    int result = FAILURE;
    SQLHSTMT stmt;
    SQLRETURN rc = SQLAllocHandle(SQL_HANDLE_STMT, dbc, &stmt);
    OK_CHECK(checkRC(rc, "allocating statement handle", dbc, SQL_HANDLE_DBC));

    // 0. init the registry table, for first time setting
    if (setting && SUCCESS == (strcmp(setting, "reg_init")))
    {
        init_registry_table(stmt);
    }

    // 1. generate database objects(data table, cmk, cek) with random object ID
    generate_objects_names(stmt);

    // 2. Create CMK (Column Master Key) and add to registry
    OK_CHECK(create_CMK(stmt));
    OK_CHECK(register_db_object(stmt, "CMK"));

    // 3. create CEK (Column Encryption Key) and add to registry
    OK_CHECK(create_ecek(stmt));
    OK_CHECK(register_db_object(stmt, "CEK"));

    // 4. Create Data table and add to registry
    OK_CHECK(create_data_table(stmt));
    OK_CHECK(register_db_object(stmt, "TABLE"));

    // 5. Insert Data into the table
    OK_CHECK(insert_data_to_table(stmt));

    // 6. Query data
    OK_CHECK(query_table(stmt));

    // 7. Clean up all footprints(Table, CMK, CEK) and deregister from registry
    OK_CHECK(clean_up(stmt));

    printf("All queries being executed successfully.");
    result = SUCCESS;
done:
    if (stmt)
    {
        SQLFreeStmt(stmt, SQL_CLOSE);
    }
    return result;
}

void disconnect()
{
    SQLDisconnect(dbc);
    SQLFreeHandle(SQL_HANDLE_DBC, dbc);
    SQLFreeHandle(SQL_HANDLE_ENV, env);
}