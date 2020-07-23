#ifndef ODBC_PROXY_H
#define ODBC_PROXY_H

#define SUCCESS 0
#define FAILURE 1

int odbc_proxy_connectDB(char* connstr);
int odbc_proxy_execute();
void odbc_proxy_disconnect();

#endif // ODBC_PROXY_H
