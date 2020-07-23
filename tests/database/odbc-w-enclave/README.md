# Database Test Case (ODBC Attestation)

## Description

This is the test case for database connection and query from sgxlkl application to a remote SQLServer database with always encrypted V2. After connection with attestation established, the test will do following queries and operations:

1. before start, drop the test data table, CEK(Column Encrypted Key), CMK(Column Master Key)
2. Create CMK (Column Master Key)
3. create CEK (Column Encryption Key)
4. Create Data table
5. Insert Data into the table
6. Query data
 
## Components and Tools Used

- Application programming language: **_C_**. 
- Database Server: **_Azure SQL Database_**.
- Database driver: **_ODBC_**.
- Docker builder: **_alpine:3.10_**

## To Run the Test

### Prerequists

- You should have a SQL Server database created and having **read permission**
- Clean up existing binaries or image files
    ```bash
        make clean
    ```
- set the following environment variables before run the test
    - **MAA_SERVICE_ADD**: the http address of the attestation provider
    - **DB_SERVER_NAME**: the database server address or ip 
    - **DB_NAME**: the name of the database you have created on the database server
    - **DB_USERID**: the user id for the database login
    - **DB_PASSWORD**: the password matching the user id
- after all the aforementioned steps, run the test case with following command:
    ```bash
        make run-hw    
    ```
