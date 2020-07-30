/***************************************************************************
  Custom Key Store Provider

  This module interacts with ODBC driver and implement a key store provider
  w/ custom encryption/decryption algorithm for Column Encryption Key.

 **************************************************************************/

#include <assert.h>
#include <sqltypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#define __stdcall
#include <sql.h>
#include <sqlext.h>
#include "msodbcsql.h"

#define CKSP_ERROR 0
#define CKSP_OK 1

/***************************************************************************
  This function is invoked by ODBC driver whenever it loads the custom KSP
 ***************************************************************************/
int __stdcall KeystoreInit(CEKEYSTORECONTEXT* ctx, errFunc* onError)
{
    printf("KSP Init()\n");
    return CKSP_OK;
}

/***************************************************************************
  This function is invoked by ODBC driver for writing data to CKSP
 ***************************************************************************/
int __stdcall KeystoreWrite(
    CEKEYSTORECONTEXT* ctx,
    errFunc* onError,
    void* data,
    unsigned int len)
{
    assert(len == sizeof(data));
    return CKSP_OK;
}

/***************************************************************************
  This function is invoked by ODBC driver whenever an ECEK needs to be
  decrypted, as the result of a query involving encrypted columns.

  Parameters:
    ctx:      current context of the CSKP
    onError:  error handler
    keyPath:  the AKV path to the CMK in wchars
    alg:      algorithm used to encrypt the CEK
    ecek:     the encrypted ECK
    ecekLen:  the length of the ECEK
    cekOut:   the double pointer to the buffer we allocate and save CEK
    cekLen:   the length of the CEK
  ***************************************************************************/
int __stdcall KeystoreDecrypt(
    CEKEYSTORECONTEXT* ctx,
    errFunc* onError,
    const wchar_t* keyPath,
    const wchar_t* alg,
    unsigned char* ecek,
    unsigned short ecekLen,
    unsigned char** cekOut,
    unsigned short* cekLen)
{
    if ((*cekOut = malloc(ecekLen)) == NULL)
    {
        fprintf(stderr, "KSP Encrypt: out of memory\n");
        return CKSP_ERROR;
    }

    *cekLen = ecekLen;
    // simple decryption.
    for (size_t i = 0; i < ecekLen; i++)
        (*cekOut)[i] = ecek[i] - 1;

    fprintf(stderr, "KSP Decrypt(): Successful\n");
    return CKSP_OK;
}

/***************************************************************************
  A client application will call this function to encrypt a given CEK.
  The output ECEK is then stored in the database.

  Parameters:
    ctx:      current context of the CSKP
    onError:  error handler
    keyPath:  the real key path to the CMK in wchars
    alg:      algorithm used to encrypt the CEK
    cek:      the unencrypted ECK
    cekLen:   the length of the CEK
    ecekOut:   the double pointer to the buffer we allocate and save ECEK
    ecekLen:   the length of the ECEK
  ***************************************************************************/
int KeystoreEncrypt(
    CEKEYSTORECONTEXT* ctx,
    errFunc* onError,
    const wchar_t* keyPath,
    const wchar_t* alg,
    unsigned char* cek,
    unsigned short cekLen,
    unsigned char** ecekOut,
    unsigned short* ecekLen)
{
    if ((*ecekOut = malloc(cekLen)) == NULL)
    {
        fprintf(stderr, "KSP Encrypt: out of memory\n");
        return CKSP_ERROR;
    }

    *ecekLen = cekLen;
    // simple encryption.
    for (size_t i = 0; i < cekLen; i++)
        (*ecekOut)[i] = cek[i] + 1;

    return CKSP_OK;
}

int VerifyCMKMetadata(
    CEKEYSTORECONTEXT* ctx,
    errFunc* onError,
    const wchar_t* keyPath,
    unsigned char* signature,
    unsigned short sigLen)
{
    return 1;
}

void KeyStoreFree()
{
}

// The current Azure SQL Always Encrypted (July 2020) only recognizes built-in
// key vaults, not the custom ones. If we register a custom key vault with the
// latest Azure SQL, it doesn't even forward the key decryption request to the
// driver. This could break in the future as the Azure SQL starts to support
// custom key vaults. Currently, it will pretend to be AKV, so SQL server will
// forward the ECEK decryption requests to client.
CEKEYSTOREPROVIDER2 MyCustomKSPName_desc = {
    L"AZURE_KEY_VAULT", // KSP name
    KeystoreInit,       // Init
    0,                  // Read
    KeystoreWrite,      // Write
    KeystoreDecrypt,    // Decrypt
    KeystoreEncrypt,    // Encrypt
    VerifyCMKMetadata,  // Verify CMK
    0,                  // Reserved
    KeyStoreFree        // Free
};

CEKEYSTOREPROVIDER2* CEKeystoreProvider2[] = {&MyCustomKSPName_desc, 0};