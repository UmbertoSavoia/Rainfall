#include <stdio.h>
#include <stdlib.h>

void    run(void)
{
    fwrite("Good... Wait what?\n", 1, 19, stdout);
    system("/bin/sh");
}

int     main(void)
{
    char s[64];
    gets(s);

    return 0;
}