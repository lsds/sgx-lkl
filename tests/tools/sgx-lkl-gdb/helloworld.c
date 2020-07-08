#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void print_hello(int count)
{
    for (int i = 0; i < count ; i++)
    {
        fprintf(stdout, "%d: Hello world!\n", i);
    }
}

int main(int argc, char** argv)
{
    print_hello(4);
    return 0;
}
