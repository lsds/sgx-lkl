# Azure SQL Client use ODBC to Connect Database and Issue Queries

## Description

This is the test case to verify an SGX-LKL application inside enclave can use ODBC to connect to Azure SQL Database with always encrypted feature and issue queries. After connection between the SGX-LKL application and the database is established, the SGX-LKL application will do the following queries and operations:

1. Create a Column Master Key(CMK) with random key name suffix. CMKs are keys used to encrypt column encryption keys. [More details can be found here](https://docs.microsoft.com/en-us/sql/relational-databases/security/encryption/overview-of-key-management-for-always-encrypted?view=sql-server-ver15).
2. Create Column Encryption Key(CEK) with random key name suffix. Note: CEKs are content-encryption keys used to encrypt data in database columns. [More details can be found here](https://docs.microsoft.com/en-us/sql/relational-databases/security/encryption/overview-of-key-management-for-always-encrypted?view=sql-server-ver15).
3. Create data table with random table name suffix.
4. Insert data into the table created.
5. Query data from the data table, and compare the decrypted result with the expected result.
6. Clean up: drop all generated data table, CEK and CMK.

To help clean up test artifacts we use a registry table in the database to record CMK, CEK and data tables created during test execution. The initialization of the registry table can be configured in `enclave-config.json` file.

## Components and Tools Used

- Application programming language: **_C_**. 
- Database Server: **_Azure SQL Database with Always Encrypted_**.
- Database driver: **_ODBC_**.
- Docker builder: **_alpine:3.10_**

## To Run the Test

### Prerequisites

- You should have an SQL Server database created with following permissions and role: **ALTER ANY COLUMN ENCRYPTION KEY** and **ALTER ANY COLUMN MASTER KEY** permission. **db_owner** role is required.
- Clean up existing binaries or image files
    ```bash
        make clean
    ```
- set the following environment variables before run the test
    - **DB_SERVER_NAME**: the database server address or ip 
    - **DB_NAME**: the name of the database you have created on the database server
    - **MAA_URL**: the url of the attestation provider
-  in `enclave-config.json` file, edit `args` values to specify the connection mode and decide whether to init the registry. 
    - `arg[0]` is the running app program name. 
    - `arg[1]` specify database connection mode. The app support two types of connections: [MSI (Managed Identities for Azure Resources)](https://docs.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview) or `classic (using userid and password)` mode.
        - To use **classic** (default) mode, set the following two environment variables
            - **DB_USERID**: the user id for the database login
            - **DB_PASSWORD**: the password matching the user id
        - To use **msi** mode, you need to enable MSI and config the VM or resources running sgxlkl with the SQL Server database. [Here is a reference](https://docs.microsoft.com/en-us/azure/app-service/app-service-web-tutorial-connect-msi).
    - `arg[2]` indicates wether to init the registry table. To registry table, set the `arg[2]` value to `reg_init`. To not init(default setting), set any other values.

### Run test application

After all aforementioned steps finish, run the test case with following command:

```bash
    make run-hw    
```
