# ODBC Baseline Test Case

## Description

This test case builds connection and executes query from sgxlkl enclave application to a remote database. The test will try to connect the database, and then do a simple query to get the current login user name.

## Components and Tools Used

- Application programming language: **_C_**. 
- Database Server: **_Azure SQL Database_**.
- Database driver: **_ODBC_**.
- Docker builder: **_alpine:3.10_**

## To Run the Test

### Prerequisites

- You should have a SQL Server database created and having **read permission**, a.k.a **db_datareader** role assigned to your account in SQL Server.
- Clean up existing binaries or image files
    ```bash
        make clean
    ```
- set the following environment variables before run the test
    - **DB_SERVER_NAME**: the database server address or ip 
    - **DB_NAME**: the name of the database you have created on the database server
-  in enclave-config.json file, edit the second application argument value in `args` to specify the connection mode. The app support two types of connections: [msi (Managed Identities for Azure Resources)](https://docs.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview) or `classic (using userid and password)` mode.
    - To use **classic** (default) mode, set the following two environment variables
        - **DB_USERID**: the user id for the database login
        - **DB_PASSWORD**: the password matching the user id
    - To use **msi** mode, you need to enable MSI and config the VM or resources running sgxlkl w/ the SQL Server database. [Here is a reference](https://docs.microsoft.com/en-us/azure/app-service/app-service-web-tutorial-connect-msi).

### Run test application

after all the aforementioned steps, run the test case with following command:

```bash
    make run-hw    
```
