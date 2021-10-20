#include <stdio.h>
#include <stdlib.h>

char m = 0;

void    v(void)
{
    char s[512];

    fgets(s, 512, stdin);
    printf(s);

    if (m == 0x40)
    {
        fwrite("Wait what?!\n", 12, 1, stdout);
        system("/bin/sh");
    }
}

int     main(void)
{
    v();
    return 0;
}