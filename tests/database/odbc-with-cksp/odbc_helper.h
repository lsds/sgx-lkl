#ifndef ODBC_HELPER_H
#define ODBC_HELPER_H

#define SUCCESS 0
#define FAILURE 1

int connectDB(char* connstr);
int execute(char* setting);
void disconnect();

#endif // ODBC_HELPER_H
