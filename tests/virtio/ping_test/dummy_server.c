#include <stdio.h>

int main()
{
    char x = 0;
    printf("\n Dummy server program to run ping test in SGXLKL-OE \n");
    while (1)
    {
        printf("Press 'Q' to quit\n");
        x = getchar();

        if (x == 'Q')
            break;
        x = getchar();
    }
    return 0;
}
