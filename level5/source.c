#include <stdio.h>
#include <stdlib.h>

void    o(void)
{
    system("/bin/sh");
    _exit(1);
}

void    n(void)
{
    char s[536];

    fgets(s, 512, stdin);
    printf(s);
    exit(1);
}

int     main(void)
{
    n();
    return 0;
}